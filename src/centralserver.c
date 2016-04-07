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
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "firewall.h"
#include "../config.h"

#include "simple_http.h"

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
    char buf[MAX_BUF];
    char *tmp;
    char *safe_token;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    /* Blanket default is error. */
    authresponse->authcode = AUTH_ERROR;

    sockfd = connect_auth_server();

        /**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
    memset(buf, 0, sizeof(buf));
    safe_token = httpdUrlEncode(token);
    if(config -> deltatraffic) {
           snprintf(buf, (sizeof(buf) - 1),
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d HTTP/1.0\r\n"
             "User-Agent: WiFiDog %s\r\n"
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
             "GET %s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%d HTTP/1.0\r\n"
             "User-Agent: WiFiDog %s\r\n"
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

    char *res;
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) {
        res = https_get(sockfd, buf, auth_server->authserv_hostname);
    } else {
        res = http_get(sockfd, buf);
    }
#endif
#ifndef USE_CYASSL
    res = http_get(sockfd, buf);
#endif
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem talking to the auth server!");
        return (AUTH_ERROR);
    }

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

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int
_connect_auth_server(int level)
{
    s_config *config = config_get_config();
    t_auth_serv *auth_server = NULL;
    t_popular_server *popular_server = NULL;
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
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);

        for (popular_server = config->popular_servers; popular_server; popular_server = popular_server->next) {
            debug(LOG_DEBUG, "Level %d: Resolving popular server [%s]", level, popular_server->hostname);
            h_addr = wd_gethostbyname(popular_server->hostname);
            if (h_addr) {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] succeeded = [%s]", level, popular_server->hostname,
                      inet_ntoa(*h_addr));
                break;
            } else {
                debug(LOG_DEBUG, "Level %d: Resolving popular server [%s] failed", level, popular_server->hostname);
            }
        }

        /* 
         * If we got any h_addr buffer for one of the popular servers, in other
         * words, if one of the popular servers resolved, we'll assume the DNS
         * works, otherwise we'll deal with net connection or DNS failure.
         */
        if (h_addr) {
            free(h_addr);
            /*
             * Yes
             *
             * The auth server's DNS server is probably dead. Try the next auth server
             */
            debug(LOG_DEBUG, "Level %d: Marking auth server [%s] as bad and trying next if possible", level, hostname);
            if (auth_server->last_ip) {
                free(auth_server->last_ip);
                auth_server->last_ip = NULL;
            }
            mark_auth_server_bad(auth_server);
            return _connect_auth_server(level);
        } else {
            /*
             * No
             *
             * It's probably safe to assume that the internet connection is malfunctioning
             * and nothing we can do will make it work
             */
            mark_offline();
            debug(LOG_DEBUG, "Level %d: Failed to resolve auth server and all popular servers. "
                  "The internet connection is probably down", level);
            return (-1);
        }
    } else {
        /*
         * DNS resolving was successful
         */
        mark_online();
		ip = safe_malloc(HTTP_IP_ADDR_LEN);
		inet_ntop(AF_INET, h_addr, ip, HTTP_IP_ADDR_LEN);
		ip[HTTP_IP_ADDR_LEN-1] = '\0';
        debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

        if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
            /*
             * But the IP address is different from the last one we knew
             * Update it
             */
            debug(LOG_DEBUG, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
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
        int port = 0;
#ifdef USE_CYASSL
        if (auth_server->authserv_use_ssl) {
            debug(LOG_DEBUG, "Level %d: Connecting to SSL auth server %s:%d", level, hostname,
                  auth_server->authserv_ssl_port);
            port = htons(auth_server->authserv_ssl_port);
        } else {
            debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname,
                  auth_server->authserv_http_port);
            port = htons(auth_server->authserv_http_port);
        }
#endif
#ifndef USE_CYASSL
        debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
        port = htons(auth_server->authserv_http_port);
#endif
        their_addr.sin_port = port;
        their_addr.sin_family = AF_INET;
        their_addr.sin_addr = *h_addr;
        memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
        free(h_addr);

        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
            return (-1);
        }

        if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
            /*
             * Failed to connect
             * Mark the server as bad and try the next one
             */
            debug(LOG_DEBUG,
                  "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible",
                  level, hostname, ntohs(port), strerror(errno));
            close(sockfd);
            mark_auth_server_bad(auth_server);
            return _connect_auth_server(level); /* Yay recursion! */
        } else {
            /*
             * We have successfully connected
             */
            debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%d", level, hostname, ntohs(port));
            return sockfd;
        }
    }
}
