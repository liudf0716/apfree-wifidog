 /* vim: set sw=4 ts=4 sts=4 et : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id$ */
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "centralserver.h"
#include "firewall.h"
#include "version.h"
#include "debug.h"
#include "simple_http.h"

json_object *
auth_server_roam_request(const char *mac)
{
	s_config *config = config_get_config();
    int sockfd;
    char buf[MAX_BUF];
    char *tmp = NULL, *end = NULL;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();


    sockfd = connect_auth_server();
	if (sockfd <= 0) {
		debug(LOG_ERR, "There was a problem connecting to the auth server!");		
        return NULL;
	}

     /**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
    memset(buf, 0, sizeof(buf));
	snprintf(buf, sizeof(buf),
		"GET %sroam?gw_id=%s&mac=%s&channel_path=%s HTTP/1.1\r\n"
        "User-Agent: ApFree WiFiDog %s\r\n"
		"Connection: keep-alive\r\n"
        "Host: %s\r\n"
        "\r\n",
        auth_server->authserv_path,
        config->gw_id,
		mac,
		g_channel_path?g_channel_path:"null",
		VERSION, auth_server->authserv_hostname);

    char *res = http_get_ex(sockfd, buf, 2);

	close_auth_server();
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem talking to the auth server!");		
        return NULL;
    }

    if ((tmp = strstr(res, "{\"")) && (end = strrchr(res, '}'))) {
		char *is_roam = NULL;
		*(end+1) = '\0';
		debug(LOG_DEBUG, "tmp is [%s]", tmp);
		json_object *roam_info = json_tokener_parse(tmp);
		if(roam_info == NULL) {
        	debug(LOG_ERR, "error parse json info %s!", tmp);
			free(res);
			return NULL;
		}
	
		is_roam = json_object_get_string(json_object_object_get(roam_info, "roam"));
		if(is_roam && strcmp(is_roam, "yes") == 0) {
			json_object *client = json_object_object_get(roam_info, "client");
			if(client != NULL) {
				json_object *client_dup = json_tokener_parse(json_object_to_json_string(client));
        		debug(LOG_INFO, "roam client is %s!", json_object_to_json_string(client));
				free(res);
				json_object_put(roam_info);
				return client_dup;
			}
		}

		free(res);
		json_object_put(roam_info);
		return NULL;
    }

    free(res);
    return NULL;
}

char * 
get_auth_uri(const char *request_type, client_type_t type, void *data)
{
    char *ip    = NULL;
    char *mac   = NULL;
    char *name  = NULL;
    char *safe_token    = NULL;
    unsigned long long int incoming = outgoing = incoming_delta = outgoing_delta = 0;
    time_t first_login;
    unsigned int online_time = 0;
    int wired = 0;

    switch(type) {
    case online_client:
        t_client *o_client = (t_client *)data;
        ip  = o_client->ip;
        mac = o_client->mac;
        safe_token = httpdUrlEncode(o_client->token);
        if (o_client->name)
            name = o_client->name;
        first_login = o_client->first_login;
        incoming = o_client->counters.incoming;
        outgoing = o_client->counters.outgoing;
        incoming_delta  = o_client->counters.incoming_delta;
        outgoing_delta  = o_client->counters.outgoing_delta;
    case trusted_client:
        t_trusted_mac *t_mac = (t_trusted_mac *)data;
        ip  = t_mac->ip;
        mac = t_mac->mac;
        wired = is_device_wired(mac);
    default:
        return NULL;
    }

    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;
    int nret = 0;
    if (config->deltatraffic) {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null");
    } else {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null");
    }

    if (safe_token) free(safe_token);

    return nret>0?uri:NULL;
}

/** Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/
t_authcode
auth_server_request(t_authresponse * authresponse, const char *request_type, const char *ip, const char *mac,
                    const char *token, unsigned long long int incoming, unsigned long long int outgoing, 
					unsigned long long int incoming_delta, unsigned long long int outgoing_delta,
					time_t first_login, unsigned int online_time, char *name, int wired)
{
    s_config *config = config_get_config();
    int sockfd;
    char buf[MAX_BUF] = {0};
    char *tmp;
    char *safe_token;
    t_auth_serv *auth_server = get_auth_server();

    /* Blanket default is error. */
    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();
	if (sockfd <= 0) {
		debug(LOG_ERR, "There was a problem connecting to the auth server!");		
        return AUTH_ERROR;
	}
        /**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
    safe_token = httpdUrlEncode(token);
    if(config -> deltatraffic) {
           snprintf(buf, (sizeof(buf) - 1),
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d HTTP/1.1\r\n"
             "User-Agent: ApFree WiFiDog %s\r\n"
			 "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, safe_token, 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
			 (long long)first_login,
			 online_time,
             config->gw_id,
			 g_channel_path?g_channel_path:"null", 
			 name?name:"null",
			 wired,
			 VERSION, auth_server->authserv_hostname);
    } else {
            snprintf(buf, (sizeof(buf) - 1),
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d HTTP/1.1\r\n"
             "User-Agent: ApFree WiFiDog %s\r\n"
			 "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip,
             mac, safe_token, incoming, outgoing, 
			 (long long)first_login, online_time,
			 config->gw_id, 
			 g_channel_path?g_channel_path:"null",
			 name,
			 wired,
			 VERSION, auth_server->authserv_hostname);
        }
    free(safe_token);

    char *res = http_get(sockfd, buf);
    if (NULL == res) {
		close_auth_server();
        debug(LOG_ERR, "There was a problem talking to the auth server!");
        return (AUTH_ERROR);
    }

	decrease_authserv_fd_ref();
    if ((tmp = strstr(res, "Auth: "))) {
        if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
            debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
            free(res);
            return (authresponse->authcode);
        } else {
            debug(LOG_WARNING, "Auth server did not return expected authentication code");
            free(res);
            return (AUTH_ERROR);
        }
    }
    free(res);
    return (AUTH_ERROR);
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int
connect_auth_server()
{
    int sockfd;

    LOCK_CONFIG();
    sockfd = _connect_auth_server(0);	
    UNLOCK_CONFIG();

    if (sockfd == -1) {
        debug(LOG_ERR, "Failed to connect to any of the auth servers");
        mark_auth_offline();
    } else {
        debug(LOG_DEBUG, "Connected to auth server");
        mark_auth_online();
    }
    return (sockfd);
}

// just decrease authserv_fd_ref
void
decrease_authserv_fd_ref()
{
	s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
	
	LOCK_CONFIG();

	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        if (auth_server->authserv_fd > 0) {
			auth_server->authserv_fd_ref -= 1;
			if (auth_server->authserv_fd_ref == 0) {
				debug(LOG_INFO, "authserv_fd_ref is 0, but not close this connection");
			} else if (auth_server->authserv_fd_ref < 0) {
				debug(LOG_ERR, "Impossible, authserv_fd_ref is %d", auth_server->authserv_fd_ref);
				close(auth_server->authserv_fd);
				auth_server->authserv_fd = -1;
				auth_server->authserv_fd_ref = 0;
			}
		}
    }
	
	UNLOCK_CONFIG();
}

void
close_auth_server()
{
	LOCK_CONFIG();
	_close_auth_server();
	UNLOCK_CONFIG();
}

void
_close_auth_server()
{
	s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
	
	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        if (auth_server->authserv_fd > 0) {
			auth_server->authserv_fd_ref -= 1;
			if (auth_server->authserv_fd_ref <= 0) {
				debug(LOG_INFO, "authserv_fd_ref is %d, close this connection", auth_server->authserv_fd_ref);
				close(auth_server->authserv_fd);
				auth_server->authserv_fd = -1;
				auth_server->authserv_fd_ref = 0;
			} 
		}
    }
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int
_connect_auth_server(int level)
{
    s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    struct in_addr *h_addr;
    int num_servers = 0;
    char *hostname = NULL;
    char *ip;
    struct sockaddr_in their_addr;
    int sockfd;

    /* If there are no auth servers, error out, from scan-build warning. */
    if (NULL == config->auth_servers) {
        return (-1);
    }

	if (!is_online()) {
		debug(LOG_INFO, "Sorry, internet is not available!");
		return -1;
	}
	
	auth_server = config->auth_servers;
	if (auth_server->authserv_fd > 0) {
		if (is_socket_valid(auth_server->authserv_fd)) {
			debug(LOG_INFO, "Use keep-alive http connection, authserv_fd_ref is %d", auth_server->authserv_fd_ref);
			auth_server->authserv_fd_ref++;
			return auth_server->authserv_fd;
		} else {
			debug(LOG_INFO, "Server has closed this connection, initialize it");
			close(auth_server->authserv_fd);
			auth_server->authserv_fd = -1;
			auth_server->authserv_fd_ref = 0;
			return _connect_auth_server(level);
		}
	}
	
    /* XXX level starts out at 0 and gets incremented by every iterations. */
    level++;

    /*
     * Let's calculate the number of servers we have
     */
    for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
        num_servers++;
    }
    debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

    if (level > num_servers) {
        /*
         * We've called ourselves too many times
         * This means we've cycled through all the servers in the server list
         * at least once and none are accessible
         */
        return (-1);
    }	
	
    /*
     * Let's resolve the hostname of the top server to an IP address
     */
	auth_server = config->auth_servers;
    hostname = auth_server->authserv_hostname;
    debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
    h_addr = wd_gethostbyname(hostname);
    if (!h_addr) {
        /*
         * DNS resolving it failed
         */
        debug(LOG_INFO, "Level %d: Resolving auth server [%s] failed", level, hostname);

		if (auth_server->last_ip) {
			free(auth_server->last_ip);
			auth_server->last_ip = NULL;
		}
		mark_auth_server_bad(auth_server);
		return _connect_auth_server(level);
    } else {
        /*
         * DNS resolving was successful
         */
		ip = safe_malloc(HTTP_IP_ADDR_LEN);
		inet_ntop(AF_INET, h_addr, ip, HTTP_IP_ADDR_LEN);
		ip[HTTP_IP_ADDR_LEN-1] = '\0';
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

        if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
            /*
             * But the IP address is different from the last one we knew
             * Update it
             */
            debug(LOG_INFO, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
            if (auth_server->last_ip)
                free(auth_server->last_ip);
            auth_server->last_ip = ip;

            /* Update firewall rules */
            fw_clear_authservers();
            fw_set_authservers();
        } else {
            /*
             * IP is the same as last time
             */
            free(ip);
        }

        /*
         * Connect to it
         */
        debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
        int port = htons(auth_server->authserv_http_port);

        their_addr.sin_port = port;
        their_addr.sin_family = AF_INET;
        their_addr.sin_addr = *h_addr;
        memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
        free(h_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
            return (-1);
        }

		int res = wd_connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr), 
							 auth_server->authserv_connect_timeout);
		if (res == 0) {
			// connect successly
			auth_server->authserv_fd = sockfd;
			auth_server->authserv_fd_ref++;
			return sockfd;
		} else {
			debug(LOG_INFO,
				"Level %d: Failed to connect to auth server %s:%d (%d - %s). Marking it as bad and trying next if possible",
				level, hostname, ntohs(port), errno,  strerror(errno));
			close(sockfd);
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level); /* Yay recursion! */
		}
    }
}

void
process_auth_server_response(struct evhttp_request *req, void *ctx)
{
    static int authdown = 0;
    
    if (req == NULL || (req && req->response_code != 200)) {
        if (!authdown) {
            mark_auth_offline();
            fw_set_authdown();
            authdown = 1;
        }
        return;
    }

    char buffer[MAX_BUF] = {0};
    char *tmp = NULL;
    t_authresponse authresponse;
    int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
            buffer, MAX_BUF-1);
    if (nread > 0)
        debug(LOG_DEBUG, "process_auth_server_response buffer is %s", buffer);
    
    if (nread <= 0) {
        debug(LOG_ERR, "There was a problem getting response from the auth server!");
        if (!authdown) {
            mark_auth_offline();
            fw_set_authdown();
            authdown = 1;
        }
        return;
    } else if ((tmp = strstr(buffer, "Auth: "))) {
        if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
            debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
        } else {
            debug(LOG_WARNING, "Auth server did not return expected authentication code");
            return;
        }
    }

    t_client    *p1 = (t_client *)(((struct evhttps_request_context *)ctx)->data);
    if (!p1) {
       if (authresponse.authcode == AUTH_ERROR)
            debug(LOG_WARNING, "Auth server error when reporting logout");
        return;
    }

    t_client *tmp_c = NULL;
    time_t current_time = time(NULL);
    
    debug(LOG_DEBUG,
          "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
          p1->ip, p1->counters.last_updated, current_time - p1->counters.last_updated,
          config->checkinterval * config->clienttimeout, current_time);
    if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
        /* Timing out user */
        debug(LOG_DEBUG, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
              p1->ip, config->checkinterval * config->clienttimeout);
        LOCK_CLIENT_LIST();
        tmp_c = client_list_find_by_client(p1);
        if (NULL != tmp_c) {
            evhttps_logout_client(ctx, tmp_c);
        } else {
            debug(LOG_NOTICE, "Client was already removed. Not logging out.");
        }
        UNLOCK_CLIENT_LIST();
    }else {
        /*
         * This handles any change in
         * the status this allows us
         * to change the status of a
         * user while he's connected
         *
         * Only run if we have an auth server
         * configured!
         */
        fw_client_process_from_authserver_response(&authresponse, p1);
    }
}
