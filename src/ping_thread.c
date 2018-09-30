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
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org.cn>
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
#include "httpd_priv.h"
#include "https_client.h"

#define	PING_TIMEOUT	2

extern time_t started_time;

static void fw_init_delay();
static void ping_work_cb(evutil_socket_t, short, void *);
static void process_ping_response(struct evhttp_request *, void *);
static void fw_init_delay();

static void fw_init_delay()
{
	fw_set_pan_domains_trusted();
	parse_inner_trusted_domain_list();
	fw_set_inner_domains_trusted();
	parse_user_trusted_domain_list();
    fw_set_user_domains_trusted();
	fw_set_trusted_maclist();
	fw_set_untrusted_maclist();
}

void
wd_set_request_header(struct evhttp_request *req, const char *host)
{
	struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);

	if (host) evhttp_add_header(output_headers, "Host", host);

	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Cache-Control", "no-store, must-revalidate");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Expires", "0");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Pragma", "no-cache");
	evhttp_add_header(output_headers, "Connection", "close");
	evhttp_add_header(output_headers, "User-Agent", "ApFree WiFiDog");
}

int
wd_make_request(struct wd_request_context *request_ctx, void (*cb)(struct evhttp_request *, void *), void *data)
{
	struct bufferevent *bev = request_ctx->bev;
	struct event_base *base = request_ctx->base;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	t_auth_serv *auth_server = get_auth_server();

	if (!auth_server->authserv_use_ssl) {
		evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_http_port);
	} else {
		evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	}
	if (!evcon) {
		debug(LOG_ERR, "evhttp_connection_base_bufferevent_new failed");
		return 1;
	}

	evhttp_connection_set_timeout(evcon, PING_TIMEOUT); // 2 seconds

	req = evhttp_request_new(cb, data);
	if (!req) {
		debug(LOG_ERR, "evhttp_request_new failed");
		evhttp_connection_free(evcon);
		return 1;
	}

	wd_set_request_header(req, auth_server->authserv_hostname);

	request_ctx->evcon = evcon;
	request_ctx->req 	= req;
	if (request_ctx->data) free(request_ctx->data);
	request_ctx->data = NULL;

	return 0;
}

static void 
ping_work_cb(evutil_socket_t fd, short event, void *arg) {
	struct wd_request_context *request_ctx = (struct wd_request_context *)arg;
	struct timeval tv;
	struct sys_info info;
	memset(&info, 0, sizeof(info));

	if (wd_make_request(request_ctx, process_ping_response, NULL)) return;
		
	get_sys_info(&info);
	char *uri = get_ping_uri(&info);
	if (!uri) return; // impossibe 
	
	debug(LOG_DEBUG, "uri is %s", uri);

	evhttp_make_request(request_ctx->evcon, request_ctx->req, EVHTTP_REQ_GET, uri);
	free(uri);

	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval;
	event_add(request_ctx->ev_timeout, &tv);
}

void
wd_request_context_init(struct wd_request_context *request_ctx, 
	struct event_base *base, struct bufferevent *bev, struct event *ev_timeout)
{
	request_ctx->base		= base;
	request_ctx->bev 		= bev;
	request_ctx->ev_timeout	= ev_timeout;
}

void
thread_ping(void *arg)
{
	fw_init_delay();

	wd_request_loop(ping_work_cb);
}

void
wd_request_loop(void (*callback)(evutil_socket_t, short, void *))
{
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct bufferevent *bev;
	struct event_base *base;
	struct event ev_timeout;
	struct timeval tv;

	struct wd_request_context request_ctx;
	t_auth_serv *auth_server = get_auth_server();

	if (!RAND_poll()) termination_handler(0);

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) termination_handler(0);

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) termination_handler(0);

	base = event_base_new();
	if (!base) termination_handler(0);

	if (!auth_server->authserv_use_ssl) {
		bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	} else {
		bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	}
	if (bev == NULL) termination_handler(0);

	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	wd_request_context_init(&request_ctx, base, bev, &ev_timeout);
	
	event_assign(&ev_timeout, base, -1, 0, callback, (void*) &request_ctx);
	evutil_timerclear(&tv);
	tv.tv_sec = 1;
    event_add(&ev_timeout, &tv);

	event_base_dispatch(base);

	event_del(&ev_timeout);
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
             check_and_get_wifidog_uptime(info->sys_uptime),
			 g_online_clients,
			 offline_client_ageout(),
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
		debug(LOG_DEBUG, "g_channel_path is %s", g_channel_path);
	}
}

static void
process_ping_response(struct evhttp_request *req, void *ctx)
{
	static int authdown = 0;
	
	if (!req || req->response_code != 200) {
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


