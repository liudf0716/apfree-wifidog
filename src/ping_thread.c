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
    @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com.cn>
*/

#define _GNU_SOURCE

#include "common.h"
#include "conf.h"
#include "safe.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "wd_util.h"
#include "version.h"
#include "wd_client.h"

extern time_t started_time;

int g_online_clients;
char *g_version;
char *g_type;
char *g_name;
char *g_channel_path;
char *g_ssid;

static void fw_init_delay();
static void ping_work_cb(evutil_socket_t, short, void *);
static void process_ping_response(struct evhttp_request *, void *);

static void fw_init_delay()
{
	parse_inner_trusted_domain_list();
	parse_user_trusted_domain_list();
	
	fw_set_pan_domains_trusted();	
	fw_set_trusted_maclist();
}

static void 
ping_work_cb(evutil_socket_t fd, short event, void *arg) {
	struct wd_request_context *request_ctx = (struct wd_request_context *)arg;
	struct evhttp_request *req = NULL;
	struct evhttp_connection *evcon = NULL;
	struct sys_info info;
	memset(&info, 0, sizeof(info));

	if (wd_make_request(request_ctx, &evcon, &req, process_ping_response)) return;
		
	get_sys_info(&info);
	char *uri = get_ping_uri(&info);
	if (!uri) return; // impossibe 
	
	debug(LOG_DEBUG, "uri is %s", uri);

	evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
	free(uri);
}

/**
 * @brief ping process
 * 
 */
void
thread_ping(void *arg)
{
	fw_init_delay();
	wd_request_loop(ping_work_cb);
}

static long
check_and_get_wifidog_uptime(long sys_uptime)
{
    long wifidog_uptime = time(NULL) - started_time;
    if (wifidog_uptime > sys_uptime) {
        started_time = time(NULL);
        return 0;
    } else  
    	return wifidog_uptime;
}

/**
 * @brief get ping uri
 * 
 * @param info The system info structure
 * @return NULL fail or ping uri
 * 
 */ 
char *
get_ping_uri(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *uri = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&uri, 
			"%s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&fm_version=%s&type=%s&name=%s&channel_path=%s&wired_passed=%d&aw_version=%s",
			 auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             check_and_get_wifidog_uptime(info->sys_uptime),
			 g_online_clients,
			 offline_client_ageout(),
			 NULL != g_ssid?g_ssid:"NULL",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 NULL != g_channel_path?g_channel_path:"null",
             config_get_config()->wired_passed,
			 VERSION);
	if (nret < 0)
		return NULL;

	return uri;
}

/**
 * @brief get system info to info param
 * 
 * @param info Out param to store system info
 * 
 */ 
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
    }
	
	if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &info->sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
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
			g_ssid = evhttp_encode_uri(ssid);
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
			if (fgets(name, 31, fh)) {
				trim_newline(name);
				if(strlen(name) > 0)
					g_type = safe_strdup(name);
			}
			fclose(fh);
		}
	}
	
	if(!g_name) {
		if ((fh = fopen("/var/sysinfo/board_name", "r"))) {
			char name[32] = {0};
			if (fgets(name, 31, fh)) {
				trim_newline(name);
				if(strlen(name) > 0)
					g_name = safe_strdup(name);
			}
			fclose(fh);
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
	} else {
		g_channel_path = safe_strdup("apfree");
	}
	debug(LOG_DEBUG, "g_channel_path is %s", g_channel_path);
}

static void
process_ping_response(struct evhttp_request *req, void *ctx)
{
	static int authdown = 0;
	
	if (!req) {
		mark_auth_offline();
		if (!authdown) {		
            fw_set_authdown();
            authdown = 1;
        }
		return;
	}
	
	char buffer[MAX_BUF] = {0};
	int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
		    buffer, MAX_BUF-1);
	if (nread <= 0) {
		mark_auth_offline();
        debug(LOG_ERR, "There was a problem getting response from the auth server!");
        if (!authdown) {			
            fw_set_authdown();
            authdown = 1;
        }
    } else if (strstr(buffer, "Pong") == 0) {
		mark_auth_offline();
        debug(LOG_WARNING, "Auth server did NOT say Pong!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else {
    	mark_auth_online();
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
    }
}


