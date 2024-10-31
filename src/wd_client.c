/* vim: set et sw=4 ts=4 sts=4 : */
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
/** 
 * @file wd_client.c
   @brief WIFIDOG CLIENT functions
   @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com.cn>
 */
#include "common.h"
#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "util.h"
#include "wd_util.h"
#include "wd_client.h"
#include "gateway.h"

/**
 * @brief get client's original url from request
 * 
 * @param req Client's http request
 * @return client's original encoded url which need to be free by caller
 *         failed return NULL
 * 
 */ 
char *
wd_get_orig_url(struct evhttp_request *req, int is_ssl)
{
    // Get the URI object from the request
    struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    if (!uri) {
        return NULL;
    }

    // Reconstruct the path and query components
    char path[4096] = {0};
    if (evhttp_uri_join(uri, path, sizeof(path) - 1) == -1) {
        return NULL;
    }
	debug(LOG_DEBUG, "path: %s", path);
	
    // Get the scheme, host, and port from the URI
    const char *scheme = evhttp_uri_get_scheme(uri);
    const char *host = evhttp_uri_get_host(uri);
    int port = evhttp_uri_get_port(uri);

    // Determine the scheme if not specified
    if (!scheme) {
        if (is_ssl) {
			scheme = "https";
		} else {
			scheme = "http";
		}
    }

    // Get the host from the request if not in the URI
    if (!host) {
        host = evhttp_request_get_host(req);
        if (!host) {
			debug(LOG_INFO, "No host in URI or request");
            return NULL;
        }
    }

    // Build the full URL
    char *full_url = NULL;
    if (port > 0 && port != 80 && port != 443) {
        safe_asprintf(&full_url, "%s://%s:%d%s", scheme, host, port, path);
    } else {
        safe_asprintf(&full_url, "%s://%s%s", scheme, host, path);
    }

    if (!full_url) {
		debug(LOG_INFO, "Failed to build full URL");
        return NULL;
    }
	debug(LOG_DEBUG, "full_url: %s", full_url);

    // Encode the URL
    char *encoded_url = evhttp_encode_uri(full_url);
    free(full_url);

    return encoded_url;
}

/**
 * @brief wifidog get full redirect url to auth server
 * 
 * @param req The http request
 * @param mac Client's mac 
 * @param remote_host Client's ip address
 * @return return redirect url which need to be free by caller
 * 
 */ 
char *
wd_get_redir_url_to_auth(struct evhttp_request *req, 
						 t_gateway_setting *gw_setting, 
						 const char *mac, 
						 const char *remote_host,
						 const uint16_t gw_port,
						 const char *device_id,
						 int is_ssl)
{
    t_auth_serv *auth_server = get_auth_server();
    char *orig_url = wd_get_orig_url(req, is_ssl);
    if (!orig_url) 
		orig_url= safe_strdup("null");
	char *gw_address = NULL;
	int is_ipv6 = 0;
	if (is_valid_ip6(remote_host)) {
		is_ipv6 = 1;
		gw_address = gw_setting->gw_address_v6;
	} else
		gw_address = gw_setting->gw_address_v4;

    char *redir_url = NULL;
    safe_asprintf(&redir_url, "%s://%s:%d%s%sgw_address=%s&is_ipv6=%d&gw_port=%d&device_id=%s&gw_id=%s&gw_channel=%s&ssid=%s&ip=%s&mac=%s&protocol=%s&url=%s",
        auth_server->authserv_use_ssl?"https":"http",
        auth_server->authserv_hostname,
        auth_server->authserv_use_ssl?auth_server->authserv_ssl_port:auth_server->authserv_http_port,
		auth_server->authserv_path,
		auth_server->authserv_login_script_path_fragment,
        gw_address,
		is_ipv6,
		gw_port,
		device_id,
		gw_setting->gw_id, 
        gw_setting->gw_channel?gw_setting->gw_channel:"null",
        g_ssid?g_ssid:"null",
        remote_host, 
		mac, 
		is_ssl?"https":"http",
		orig_url); 
		
    free(orig_url);
    return redir_url;
}

/**
 * @brief free wifidog request context
 * 
 */ 
void
wd_request_context_free(struct wd_request_context *context)
{
	if (context) free(context);
}

/**
 * @brief create wifidog request context
 * 
 * @param base The event_base
 * @param ssl The SSL
 * @param authserv_use_ssl Whether auth server used ssl or not
 * @return return wd_request_context which need to be free by caller
 * 
 */
struct wd_request_context *
wd_request_context_new(struct event_base *base, SSL *ssl, int authserv_use_ssl)
{
	struct bufferevent *bev;
	if (!authserv_use_ssl) {
		bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	} else {
		bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	}
	if (!bev) return NULL;

	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	struct wd_request_context * context = safe_malloc(sizeof(struct wd_request_context));
	context->base 	= base;
	context->ssl 	= ssl;
	context->bev	= bev;

	return context;
}

/**
 * @brief   wifidog loop for connecting auth server periodically
 * 
 * @param callback The function will be invoked every interval seconds during the loop
 */ 
void
wd_request_loop(void (*callback)(evutil_socket_t, short, void *))
{	
	if (!RAND_poll()) termination_handler(0);

	/* Create a new OpenSSL context */
	SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) termination_handler(0);

	SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) termination_handler(0);

	// authserv_hostname is the hostname of the auth server, must be domain name
    if (!SSL_set_tlsext_host_name(ssl, get_auth_server()->authserv_hostname)) {
        debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
        termination_handler(0);
    }

	struct event_base *base = event_base_new();
	if (!base) termination_handler(0);

	struct wd_request_context *request_ctx = wd_request_context_new(
		base, ssl, get_auth_server()->authserv_use_ssl);
	if (!request_ctx) termination_handler(0);

	struct event evtimer;
	struct timeval tv;

	// execute callback before shedule it
	if (callback) callback(-1, EV_PERSIST, request_ctx);

	event_assign(&evtimer, base, -1, EV_PERSIST, callback, (void*)request_ctx);
	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval;
    event_add(&evtimer, &tv);

	event_base_dispatch(base);

	if (evtimer_initialized(&evtimer)) event_del(&evtimer);
	if (base) event_base_free(base);
	if (ssl) SSL_free(ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	if (request_ctx) wd_request_context_free(request_ctx);
}

/**
 * @brief Set wifidog request header when connection auth server
 * 
 * @param req The http request
 * @param host The auth server's host
 */ 
void
wd_set_request_header(struct evhttp_request *req, const char *host)
{
	struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);

	evhttp_add_header(output_headers, "Host", host);
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Cache-Control", "no-store, must-revalidate");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Expires", "0");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Pragma", "no-cache");
	evhttp_add_header(output_headers, "Connection", "close");
	evhttp_add_header(output_headers, "User-Agent", "ApFree-WiFiDog");
}

/**
 * @brief make http client request to auth server 
 * 
 * @param request_ctx which has set event_base and bufferevent
 * @param evcon it's out param
 * @param req	it's out param
 * @param cb  it's callback function for evhttp_request_new
 * @return 1 fail or 0 success
 * 
 */
int
wd_make_request(struct wd_request_context *request_ctx, 
	struct evhttp_connection **evcon, struct evhttp_request **req,
	void (*cb)(struct evhttp_request *, void *))
{
	struct bufferevent *bev = request_ctx->bev;
	struct event_base *base = request_ctx->base;
	t_auth_serv *auth_server = get_auth_server();
	
	debug(LOG_DEBUG, "auth_server->authserv_use_ssl: %d", auth_server->authserv_use_ssl);
	if (!auth_server->authserv_use_ssl) {
		*evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_http_port);
	} else {
		*evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	}
	if (!*evcon) {
		debug(LOG_ERR, "evhttp_connection_base_bufferevent_new failed");
		return 1;
	}

	evhttp_connection_set_timeout(*evcon, WD_CONNECT_TIMEOUT); // 2 seconds

	*req = evhttp_request_new(cb, request_ctx);
	if (!*req) {
		debug(LOG_ERR, "evhttp_request_new failed");
		evhttp_connection_free(*evcon);
		return 1;
	}

	wd_set_request_header(*req, auth_server->authserv_hostname);

	return 0;
}
