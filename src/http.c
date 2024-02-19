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
/** @file http.c
  @brief HTTP IO functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire
  @author Copyright (C) 2007 David Bird <david@coova.com>
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> 

#include "common.h"
#include "auth.h"
#include "conf.h"
#include "centralserver.h"
#include "client_list.h"
#include "debug.h"
#include "firewall.h"
#include "http.h"
#include "gateway.h"
#include "ssl_redir.h"
#include "safe.h"
#include "util.h"
#include "wdctl_thread.h"
#include "wd_util.h"
#include "version.h"
#include "wd_client.h"

#define APPLE_REDIRECT_MSG  "<!DOCTYPE html>"	\
				"<html>"						\
				"<title>Success</title>"		\
				"<script type=\"text/javascript\">"	\
					"window.location.replace(\"%s\");"	\
				"</script>"	\
				"<body>"	\
				"Success"	\
				"</body>"	\
				"</html>"


extern struct evbuffer *evb_internet_offline_page, *evb_authserver_offline_page;
extern struct redir_file_buffer *wifidog_redir_html;

const char *apple_domains[] = {
					"captive.apple.com",
					"www.apple.com",
					NULL
};

const char *apple_wisper = "<!DOCTYPE html>"
				"<html>"
				"<script type=\"text/javascript\">"
					"window.setTimeout(function() {location.href = \"captive.apple.com/hotspot-detect.html\";}, 12000);"
				"</script>"
				"<body>"
				"</body>"
				"</html>";

static int
is_apple_captive(const char *domain)
{
    if (!domain) return 0;

	int i = 0;
	while(apple_domains[i]) {
		if(strcmp(domain, apple_domains[i++]) == 0)
			return 1;
	}

	return 0;
}

/**
 * @brief Treat apple wisper protocol
 * 
 * @param req The client http request
 * @param mac The client's mac
 * @param remote_host The client's ip address
 * @param redir_url The client redirect url
 * @param mode 2 not allow show apple device's captive page, 
 *             1 show apple's captive page and ok button appear
 * @return 1 end the http request or 0 continue it
 * 
 */
static int
process_apple_wisper(struct evhttp_request *req, const char *mac, const char *remote_host, const char *redir_url, const int mode)
{
	if(!is_apple_captive(evhttp_request_get_host(req))) return 0;

    if (mode == 2) { // not allow apple show its default captive page
        evhttp_send_reply(req, HTTP_OK, "OK", NULL);
        return 1;
    }

    int interval = 0;
    LOCK_OFFLINE_CLIENT_LIST();

    t_offline_client *o_client = offline_client_list_find_by_mac(mac);
    if(o_client == NULL) {
        o_client = offline_client_list_add(remote_host, mac);
    } else {
        o_client->last_login = time(NULL);
        interval = o_client->last_login - o_client->first_login;
    }
    
    o_client->hit_counts++;

    if(o_client->client_type == 1 ) {
        UNLOCK_OFFLINE_CLIENT_LIST();
        if(interval > 20) {
            fw_set_mac_temporary(mac, 0);	
            ev_http_send_apple_redirect(req, redir_url);
        } else if(o_client->hit_counts > 2)
            ev_http_send_apple_redirect(req, redir_url);
        else {
            ev_http_send_redirect(req, redir_url, "Redirect to login page");
        }
    } else {	
        o_client->client_type = 1;
        UNLOCK_OFFLINE_CLIENT_LIST();
        ev_http_replay_wisper(req);
    }
    return 1;
	
}

/**
 * @brief reply client error of gw internet offline or auth server offline
 * 
 * @param req  The http request
 * @param type 1: internet not online
 *             other: auth server ont online
 */
void
ev_http_reply_client_error(struct evhttp_request *req, enum reply_client_error_type type)
{
    switch(type) {
    case INTERNET_OFFLINE:
        evhttp_send_reply(req, 200, "OK", evb_internet_offline_page);
        break;
    case AUTHSERVER_OFFLINE:
    default:
        evhttp_send_reply(req, 200, "OK", evb_authserver_offline_page);
        break;
    }
}

/**
 * @brief reply client to resend its request
 * 
 */ 
void
ev_http_resend(struct evhttp_request *req)
{
    char *orig_url = wd_get_orig_url(req);
    if (!orig_url) {
        evhttp_send_error(req, HTTP_INTERNAL, NULL);
        return;
    }

    ev_http_send_redirect(req, orig_url, "resend its request");
    free(orig_url);
}

/**
 * @brief If the client already login but get different ip after reconnect gateway device
 * 
 * @return 1 end the http request or 0 continue the request
 */ 
static int
process_already_login_client(struct evhttp_request *req, const char *mac, const char *remote_host)
{
	if (!mac || !remote_host) return 0;
	
    int flag = 0;
	
    LOCK_CLIENT_LIST();
    t_client *clt = client_list_find_by_mac(mac);
    if (clt && strcmp(clt->ip, remote_host) != 0) { // the same client get different ip
        fw_deny(clt);
        free(clt->ip);
        clt->ip = safe_strdup(remote_host);
        fw_allow(clt, FW_MARK_KNOWN);
        debug(LOG_INFO, "client has login, replace it with new ip");
        flag = 1;
    }
    UNLOCK_CLIENT_LIST();

    if (flag) ev_http_resend(req);
    return flag;
}

static int
process_wired_device_pass(struct evhttp_request *req, const char *mac)
{
	if (!mac) return 0;
	
    if (br_is_device_wired(mac)) {
        debug(LOG_DEBUG, "wired_passed: add %s to trusted mac", mac);
        if (!is_trusted_mac(mac))
            add_trusted_maclist(mac);
        ev_http_resend(req);
        return 1;
    }
    return 0;
}

/**
 * @brief The 404 handler is also responsible for redirecting to the auth server
 * 
 */
void
ev_http_callback_404(struct evhttp_request *req, void *arg)
{
    if (!is_online()) {
        ev_http_reply_client_error(req, INTERNET_OFFLINE);
        return;
    }  

    if (!is_auth_online()) {
        ev_http_reply_client_error(req, AUTHSERVER_OFFLINE);
        return;
    } 

    char *remote_host = NULL;
    uint16_t port;
    evhttp_connection_get_peer(evhttp_request_get_connection(req), &remote_host, &port);
	if (remote_host == NULL) return;

    char mac[MAC_LENGTH] = {0};
    if (!br_arp_get_mac(remote_host, mac)) {
        evhttp_send_error(req, 200, "Cant get client's mac by its ip");
        return;
    }

    if (process_already_login_client(req, mac, remote_host)) return;

    const s_config *config = config_get_config();
    if (config->wired_passed && process_wired_device_pass(req, mac)) return;

    char *redir_url = wd_get_redir_url_to_auth(req, mac, remote_host);
    if (!redir_url) {
        evhttp_send_error(req, 200, "Cant get client's redirect to auth server's url");
        return;
    }
    
    if (!config->bypass_apple_cna && process_apple_wisper(req, mac, remote_host, redir_url, config->bypass_apple_cna))
        goto END;

    if (config->js_redir)
        ev_http_send_js_redirect(req, redir_url);
    else
        ev_http_send_redirect(req, redir_url, "Redirect to login page");

END:
    free(redir_url);
}

/**
 * 
 */ 
void
ev_http_callback_wifidog(struct evhttp_request *req, void *arg)
{
    ev_send_http_page(req, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

/**
 * 
 */ 
void
ev_http_callback_about(struct evhttp_request *req, void *arg)
{
    ev_send_http_page(req, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

/**
 * @brief Client's status request
 * 
 */ 
void
ev_http_callback_status(struct evhttp_request *req, void *arg)
{
    char *status = get_status_text();
    struct evbuffer *buffer = evbuffer_new();

    evbuffer_add_printf(buffer, "<html><body><pre>%s</pre></body></html>", status);
    evhttp_send_reply(req, HTTP_OK, "OK", buffer);

    free(status);
    evbuffer_free(buffer);
}

/**
 * @brief Convenience function to redirect the web browser to the auth server
 * 
 * @param req The request
 * @param url_fragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title
 */
void
ev_http_send_redirect_to_auth(struct evhttp_request *req, const char *url_fragment, const char *text)
{
    char *url;
    t_auth_serv *auth_server = get_auth_server();

    safe_asprintf(&url, "%s://%s:%d%s%s",
        auth_server->authserv_use_ssl?"https":"http",
        auth_server->authserv_hostname, 
        auth_server->authserv_use_ssl?auth_server->authserv_ssl_port:auth_server->authserv_http_port,
        auth_server->authserv_path, url_fragment);

    ev_http_send_redirect(req, url, text);
	free(url);
} 

/**
 * @brief Sends a redirect to the browser
 * @param req The http request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable
 */ 
void
ev_http_send_redirect(struct evhttp_request * req, const char *url, const char *text)
{
    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, 500, "Internal error");
        return;
    }
    struct evkeyvalq *header = evhttp_request_get_output_headers(req);
    evhttp_add_header(header, "Location", url);
    evbuffer_add_printf(evb, "<html><body>Please <a href='%s'>click here</a>.</body></html>", url);
    evhttp_send_reply(req, 307, text, evb);
    evbuffer_free(evb);
}

static void
ev_http_respond_options(struct evhttp_request *req)
{
    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, 500, "Internal error");
        return;
    }
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Headers", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");
    evbuffer_add_printf(evb, "options success");
    evhttp_send_reply(req, 204, "options success", evb);
    evbuffer_free(evb);
}

/**
 * @brief process client's login and logout request
 * 
 * @param req Client's http request
 * @param arg Auth server's request context
 * 
 */ 
void 
ev_http_callback_auth(struct evhttp_request *req, void *arg)
{
    struct wd_request_context *context = (struct wd_request_context *)arg;

    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        ev_http_respond_options(req);
        return;
    }

	evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");
	
    char *token = ev_http_find_query(req, "token");
    if (!token) {
        evhttp_send_error(req, 200, "Invalid token");
        return;
    } 

    char *remote_host = NULL;
    char *mac = NULL;
    // get remote_host and mac from request if possible
    // which support auth server side to permit client to login/logout
    remote_host = ev_http_find_query(req, "client_ip");
    mac = ev_http_find_query(req, "client_mac");
    if (!remote_host || !mac) {
        char *remote_ip = NULL;
        uint16_t port;
        if (mac) free(mac);
        if (remote_host) free(remote_host);
        mac = NULL;
        remote_host = NULL;
        evhttp_connection_get_peer(evhttp_request_get_connection(req), &remote_ip, &port);
        remote_host = safe_strdup(remote_ip);
        mac = arp_get(remote_host);
    }
    
    if (!mac || !remote_host) {
        free(token);
        if (mac) free(mac);
        if (remote_host) free(remote_host);
        evhttp_send_error(req, 200, "Failed to retrieve your MAC address");
        return;
    }  

    int new_client = 0;
    LOCK_CLIENT_LIST();
    t_client *client = client_list_find(remote_host, mac);
    if (!client && !(client = client_list_find_by_mac(mac))) { /* in case the same client but get differrent ip */
        client = client_list_add(remote_host, mac, token);
        new_client = 1;
    } else if (!client && (client = client_list_find_by_mac(mac))) {
        fw_deny(client);
        free(client->ip);
        free(client->token);
        client->ip = safe_strdup(remote_host);
        client->token = safe_strdup(token);
    }
    UNLOCK_CLIENT_LIST();
    free(mac);
    free(remote_host);

    char *logout = ev_http_find_query(req, "logout");
    if (logout) {
        free(logout);
        if (new_client) {
            debug(LOG_INFO, "Logout request from %s, but client not found, impossible here!", client->ip);
            safe_client_list_delete(client);
            evhttp_send_error(req, 200, "Logout request from unknown client");
        } else {
            debug(LOG_INFO, "Logout request from %s", client->ip);
            ev_logout_client(context, client);
        }
    } else {
        debug(LOG_INFO, "Login request from %s", client->ip);
        ev_authenticate_client(req, context, client);
    }
    free(token);
}

/**
 * @brief process client's disconnect request
 * 
 * @param req Client's http request
 * @param arg useless
 * 
 */ 
void 
ev_http_callback_disconnect(struct evhttp_request *req, void *arg)
{
    struct wd_request_context *context = (struct wd_request_context *)arg;
    const char *token = ev_http_find_query(req, "token");
    const char *mac = ev_http_find_query(req, "mac");

	evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");
	
    if (!token || !mac) {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        evhttp_send_error(req, HTTP_OK, "Both the token and MAC need to be specified");
        return;
    }

    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_mac(mac);
    UNLOCK_CLIENT_LIST();

    if (client && !strcmp(client->token, token)) {
        ev_logout_client(context, client);
    } else {
        debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac, token);
        evhttp_send_error(req, HTTP_OK, "Invalid token for MAC");
    }
}

/**
 * @brief Temporaray allow client to access internet a minute
 * 
 * @param req Client http request
 * 
 */
void 
ev_http_callback_temporary_pass(struct evhttp_request *req, void *arg)
{
    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        ev_http_respond_options(req);
        return;
    }
    
    const char *mac = ev_http_find_query(req, "mac");
    const char *timeout = ev_http_find_query(req, "timeout");
    if (!timeout) timeout = "0"; // default 5 minutes
	
	evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");
	
    if (mac) {
        debug(LOG_INFO, "Temporary passed %s timeout %s", mac, timeout);
        int ntimeout = atoi(timeout);
        if (ntimeout < 0) ntimeout = 0;
        fw_set_mac_temporary(mac, ntimeout);	
        evhttp_send_reply(req, HTTP_OK, "OK", NULL);
    } else {
        debug(LOG_INFO, "Temporary pass called without  MAC given");
        evhttp_send_error(req, HTTP_OK, "MAC need to be specified");
    }
} 

/**
 * @brief read html file to evbuffer
 * 
 * @param filename The html file
 * @param evb The html file read into evb
 * @return NULL failed or evb
 * 
 */ 
struct evbuffer *
ev_http_read_html_file(const char *filename, struct evbuffer *evb)
{
	if (!evb) return NULL;
	
	int fd = open(filename, O_RDONLY);
	if (fd == -1) {
		debug(LOG_CRIT, "Failed to open HTML message file %s: %s", strerror(errno), 
			filename);
		return NULL;
	}
	
	if (evbuffer_add_file(evb, fd, 0, -1)) {
		debug(LOG_CRIT, "Failed to read HTML message file %s: %s", strerror(errno), 
			filename);
		close(fd);
		return NULL;
	}

	close(fd);
	return evb;
}

/**
 * @brief Send html file to client; 
 * 
 * @param req The http request
 * @param title Replace $title of the html file with it
 * @param message Replace $message of the html file with it
 * @todo need more complex process engine
 */ 
void
ev_send_http_page(struct evhttp_request *req, const char *title, const char *message)
{
    struct stat st;
    s_config *config = config_get_config();
    int fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        evhttp_send_error(req, HTTP_NOCONTENT, NULL);
        return;
    }

    if (fstat(fd, &st) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        close(fd);
        evhttp_send_error(req, HTTP_NOCONTENT, NULL);
        return;
    }

    struct evbuffer *buffer = evbuffer_new();
    if (!buffer) {
        debug(LOG_CRIT, "Failed to evbuffer_new");
        close(fd);
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to evbuffer_new");
        return;
    }

    if (evbuffer_add_file(buffer, fd, 0, st.st_size)) {
        debug(LOG_CRIT, "Failed to read HTML message file");
        close(fd);
        evbuffer_free(buffer);
        evhttp_send_error(req, HTTP_INTERNAL, NULL);
        return;
    }
	
    evhttp_send_reply(req, HTTP_OK, "OK", buffer);
    evbuffer_free(buffer);
}

/** 
 * @brief send the web browser's page which will redirect to auth server by its js 
 * 
 * @param req The http request
 * @param url The redirect url by js
 */
void 
ev_http_send_js_redirect(struct evhttp_request *req, const char *redir_url)
{
    struct evbuffer *evb = evbuffer_new ();	

    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to evbuffer_new");
        return;
    }
	
	evbuffer_add(evb, wifidog_redir_html->front, wifidog_redir_html->front_len);
    evbuffer_add_printf(evb, WIFIDOG_REDIR_HTML_CONTENT, redir_url);
	evbuffer_add(evb, wifidog_redir_html->rear, wifidog_redir_html->rear_len);

    evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Cache-Control", "no-store, must-revalidate");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Expires", "0");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Pragma", "no-cache");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Connection", "close");

    evhttp_send_reply(req, 200, "OK", evb);

    evbuffer_free(evb);
}

/**
 * @brief tell apple device to redirect to redir_url
 * 
 * @param req The http request
 * @param redir_url redirect url of response
 * 
 */ 
void
ev_http_send_apple_redirect(struct evhttp_request *req, const char *redir_url)
{
    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to evbuffer_new");
        return;
    }
    evbuffer_add_printf(evb, APPLE_REDIRECT_MSG, redir_url);
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}

/**
 * @brief replay apple wisper detect request
 * 
 */
void
ev_http_replay_wisper(struct evhttp_request *req)
{
    struct evbuffer *evb = evbuffer_new ();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to evbuffer_new");
        return;
    }	
    evbuffer_add(evb, apple_wisper, strlen(apple_wisper));
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
} 

/**
 * @brief get query's value according to key
 * 
 * @param req The http request
 * @param key The key to search
 * @return NULL or key's value, the return value need to be free by caller
 */
char *
ev_http_find_query(struct evhttp_request *req, const char *key)
{
    const struct evhttp_uri *uri = evhttp_request_get_evhttp_uri(req);
    struct evkeyvalq query;

#define TAILQ_INIT(head) do {                   \
    (head)->tqh_first = NULL;                   \
    (head)->tqh_last = &(head)->tqh_first;      \
} while (0)

    TAILQ_INIT(&query);

    if (evhttp_parse_query_str(evhttp_uri_get_query(uri), &query))
        return NULL;
    
    char *r_val = NULL;
    const char *val = evhttp_find_header(&query, key);
    if (val) {
        r_val = safe_strdup(val);
    }

    evhttp_clear_headers(&query);

    return r_val;
}
