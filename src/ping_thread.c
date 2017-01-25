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
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"
#include "wd_util.h"
#include "version.h"
#include "httpd_priv.h"

static void ping(void);
static void evpings(void);

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_ping(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
	t_auth_serv *auth_server = get_auth_server();
	
	//>>> liudf added 20160411
	// move from fw_init to here	
	fw_set_pan_domains_trusted();

	fix_weixin_http_dns_ip();

	parse_inner_trusted_domain_list();
	fw_set_inner_domains_trusted();

	parse_user_trusted_domain_list();
    fw_set_user_domains_trusted();

	fw_set_trusted_maclist();
	fw_set_untrusted_maclist();
	
    while (1) {
        /* Make sure we check the servers at the very begining */
        
		if (auth_server->authserv_use_ssl) {
       		debug(LOG_DEBUG, "Running evpings()");
			evpings();
		} else {
			debug(LOG_DEBUG, "Running ping()");
			ping();
		}
		
        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}

char *
get_ping_request(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *request = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&request,
			"GET %s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf%%&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&version=%s&type=%s&name=%s&channel_path=%s&wired_passed=%d HTTP/1.1\r\n"
             "User-Agent: ApFree WiFiDog %s\r\n"
			 "Connection: keep-alive\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
			 offline_client_ageout(),
			 g_online_clients,
			 NULL != g_ssid?g_ssid:"NULL",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 NULL != g_channel_path?g_channel_path:"null",
             config_get_config()->wired_passed,
             VERSION, auth_server->authserv_hostname);
	
	return nret>0?request:NULL;
}

char *
get_ping_uri(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *uri = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&uri, 
			"%s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf%%&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&version=%s&type=%s&name=%s&channel_path=%s&wired_passed=%d",
			 auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
			 offline_client_ageout(),
			 g_online_clients,
			 NULL != g_ssid?g_ssid:"NULL",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 NULL != g_channel_path?g_channel_path:"null",
             config_get_config()->wired_passed);
	
	return nret>0?uri:NULL;
}

void
get_sys_info(struct sys_info *info)
{
	FILE 	*fh = NULL;
	char	ssid[32] = {0};
	
	if (info == NULL)
		return;
	
	info->cpu_usage = get_cpu_usage();
	
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &info->sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &info->sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &info->sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
		fh = NULL;
    }
	
	if ((fh = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r"))) {
        if (fscanf(fh, "%lu", &info->nf_conntrack_count) != 1)
            debug(LOG_CRIT, "Failed to read nf_conntrack_count");

        fclose(fh);
		fh = NULL;
    }
	
	// get first ssid
	if (uci_get_value("wireless", "ssid", ssid, 31)) {
		trim_newline(ssid);
		if(strlen(ssid) > 0) {
			if(g_ssid) 
				free(g_ssid);
			g_ssid = _httpd_escape(ssid);
		}
	}
	
	if(!g_version) {
		char version[32] = {0};
		if (uci_get_value("firmwareinfo", "firmware_version", version, 31)) {			
			trim_newline(version);
			if(strlen(version) > 0)
				g_version = safe_strdup(version);
		}
	}
	
	if(!g_type) {
		if ((fh = fopen("/var/sysinfo/board_type", "r"))) {
			char name[32] = {0};
			fgets(name, 32, fh);
			fclose(fh);
			fh = NULL;
			trim_newline(name);
			if(strlen(name) > 0)
				g_type = safe_strdup(name);
		}
	}
	
	if(!g_name) {
		if ((fh = fopen("/var/sysinfo/board_name", "r"))) {
			char name[32] = {0};
			fgets(name, 32, fh);
			fclose(fh);
			fh = NULL;
			trim_newline(name);
			if(strlen(name) > 0)
				g_name = safe_strdup(name);
		}
	}
	
	if(!g_channel_path) { 
		free(g_channel_path);
		g_channel_path = NULL;
	}

	char channel_path[128] = {0};
	if (uci_get_value("firmwareinfo", "channel_path", channel_path, 127)) {			
		trim_newline(channel_path);	
		if(strlen(channel_path) > 0)
			g_channel_path = safe_strdup(channel_path);
		debug(LOG_DEBUG, "g_channel_path is %s", g_channel_path);
	}
}

static void
process_ping_result(struct evhttp_request *req, void *ctx)
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
	int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
		    buffer, MAX_BUF-1);
	if (nread > 0)
		debug(LOG_DEBUG, "buffer is %s", buffer);
	
	if (nread <= 0) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        if (!authdown) {
			mark_auth_offline();
            fw_set_authdown();
            authdown = 1;
        }
    } else if (strstr(buffer, "Pong") == 0) {
        debug(LOG_WARNING, "Auth server did NOT say Pong!");
        if (!authdown) {
			mark_auth_offline();
            fw_set_authdown();
            authdown = 1;
        }
    } else {
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
			mark_auth_online();
            fw_set_authup();
            authdown = 0;
        }
    }
}

static void
evpings(void)
{
	struct sys_info info;
	memset(&info, 0, sizeof(info));
		
	get_sys_info(&info);
	
	char *uri = get_ping_uri(&info);
	if (uri == NULL)
		return; // impossibe 
	
	debug(LOG_DEBUG, "ping uri is %s", uri);
	
	int timeout = 2; // 2s
	evhttps_request(uri, timeout, process_ping_result);
	free(uri);
}
/** @internal
 * This function does the actual request.
 */
static void
ping(void)
{
    char *request = NULL;
    int sockfd;
    static int authdown = 0;
	
	struct sys_info info;
	memset(&info, 0, sizeof(info));
	
	get_sys_info(&info);
	
	/*
     * The ping thread does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd == -1) {
        /*
         * No auth servers for me to talk to
         */
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        return;
    }
	
    /*
     * Prep & send request
     */
	request = get_ping_request(&info);
	if (request == NULL)
		return; // impossible
    
    char *res = http_get(sockfd, request);
	free(request);
	close_auth_server();
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else if (strstr(res, "Pong") == 0) {
        debug(LOG_WARNING, "Auth server did NOT say Pong!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        free(res);
    } else {
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
        free(res);
    }
    return;
}
