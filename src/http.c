
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
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

#define AW_LOCAL_REDIRECT_MSG  "<!DOCTYPE html>"	\
                "<html>"						\
                "<title>apfree-wifidog redirecting...</title>"		\
                "<script type=\"text/javascript\">"	\
                    "window.location.replace(\"%s\");"	\
                "</script>"	\
                "<body>"	\
                "apfree-wifidog redirecting..."	\
                "</body>"	\
                "</html>"

extern struct evbuffer *evb_internet_offline_page, *evb_authserver_offline_page;
extern redir_file_buffer_t *wifidog_redir_html;
extern pthread_mutex_t g_resource_lock;

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

static void ev_http_resend(struct evhttp_request *req);
static int process_already_login_client(struct evhttp_request *req, const char *mac, const char *remote_host);
static int process_wired_device_pass(struct evhttp_request *req, const char *mac);
static void ev_http_respond_options(struct evhttp_request *req);
static int process_apple_wisper(struct evhttp_request *req, const char *mac, const char *remote_host, const char *redir_url, const int mode);
static void ev_http_send_apple_redirect(struct evhttp_request *req, const char *redir_url);
static void ev_http_replay_wisper(struct evhttp_request *req);
static void ev_send_http_page(struct evhttp_request *req, const char *title, const char *msg);

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
            // fw_set_mac_temporary(mac, 0);	
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
 * @brief reply client to resend its request
 * 
 */ 
static void
ev_http_resend(struct evhttp_request *req)
{
    char *orig_url = wd_get_orig_url(req, 0);
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
 * @brief tell apple device to redirect to redir_url
 * 
 * @param req The http request
 * @param redir_url redirect url of response
 * 
 */ 
static void
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
static void
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
 * @brief reply client error of gw internet offline or auth server offline
 * 
 * @param req  The http request
 * @param type 1: internet not online
 *             other: auth server offline
 */
void
ev_http_reply_client_error(struct evhttp_request *req, enum reply_client_error_type type, 
    char *ip, char *port, char *proto, char *client_ip, char *client_mac)
{
    struct evbuffer *evb;
    switch(type) {
    case INTERNET_OFFLINE:
        evb = evbuffer_new();
        // lock extern pthread_mutex_t g_resource_lock;
        pthread_mutex_lock(&g_resource_lock);
        // copy evb_internet_offline_page to evb
        evbuffer_add(evb, evbuffer_pullup(evb_internet_offline_page, -1), evbuffer_get_length(evb_internet_offline_page));
        pthread_mutex_unlock(&g_resource_lock);
        break;
    case AUTHSERVER_OFFLINE:
        evb = evbuffer_new();
        pthread_mutex_lock(&g_resource_lock);
        evbuffer_add(evb, evbuffer_pullup(evb_authserver_offline_page, -1), evbuffer_get_length(evb_authserver_offline_page));
        pthread_mutex_unlock(&g_resource_lock);
        break;
    case LOCAL_AUTH:
    default:
        char redir_url[256] = {0};
        snprintf(redir_url, sizeof(redir_url), "%s://%s:%s/wifidog/local_auth?ip=%s&mac=%s", proto, ip, port, client_ip, client_mac);
        debug(LOG_DEBUG, "local auth redir_url: %s", redir_url);
        evb = evbuffer_new();
        evbuffer_add_printf(evb, AW_LOCAL_REDIRECT_MSG, redir_url);
        break;
    }
    debug(LOG_DEBUG, "reply client error");
    evhttp_send_reply(req, 200, "OK", evb);
    evbuffer_free(evb);
}

int
ev_http_connection_get_peer(struct evhttp_connection *evcon, char **remote_host, uint16_t *port)
{
    struct sockaddr_storage ss;
    char *ip = NULL;
    evhttp_connection_get_peer(evcon, &ip, port);
    if (ip == NULL) {
        debug(LOG_ERR, "evhttp_connection_get_peer failed");
        return 0;
    }

    struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&ss;
    if (inet_pton(AF_INET6, ip, &sin->sin6_addr) > 0) {
        if (IN6_IS_ADDR_V4MAPPED(&sin->sin6_addr)) {
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &sin->sin6_addr.s6_addr[12], 4);
            *remote_host = safe_malloc(INET_ADDRSTRLEN);
            if (!inet_ntop(AF_INET, &ipv4_addr, *remote_host, INET_ADDRSTRLEN)) {
                debug(LOG_ERR, "inet_ntop failed: %s", strerror(errno));
                free(*remote_host);
                return 0;
            }
        }
    }

    return 1;
}

/**
 * @brief The 404 handler is also responsible for redirecting to the auth server
 * 
 */
void
ev_http_callback_404(struct evhttp_request *req, void *arg)
{
    if (arg == NULL) {
        debug(LOG_ERR, "ev_http_callback_404 arg is NULL");
        evhttp_send_error(req, 404, "Not Found");
        return;
    }
    int is_ssl = *((int *)arg);
    free(arg);
    if (!is_online()) {
        debug(LOG_INFO, "Internet is offline");
        ev_http_reply_client_error(req, INTERNET_OFFLINE, NULL, NULL, NULL, NULL, NULL);
        return;
    }

    char *remote_host = NULL;
    uint16_t port;
    ev_http_connection_get_peer(evhttp_request_get_connection(req), &remote_host, &port);
	if (remote_host == NULL) return;

    struct bufferevent *bev = evhttp_connection_get_bufferevent(evhttp_request_get_connection(req));
    evutil_socket_t fd = bufferevent_getfd(bev);
    if (fd < 0) {
        debug(LOG_ERR, "bufferevent_getfd failed: %s", strerror(errno));
        evhttp_send_error(req, 200, "Cant get client's fd");
        return;
    }

    t_gateway_setting *gw_setting = get_gateway_setting_by_ipv4(remote_host);
    if (!gw_setting) {
        debug(LOG_ERR, "get_gateway_setting_by_ipv4 [%s] failed", remote_host);
        evhttp_send_error(req, 200, "Cant get gateway setting by client's ip");
        return;
    }

    s_config *config = config_get_config();
    char mac[MAC_LENGTH] = {0};
    if (is_bypass_mode()) {
        snprintf(mac, sizeof(mac), "%s", "00:00:00:00:00:00");
    } else if (!br_arp_get_mac(gw_setting, remote_host, mac)) {
        evhttp_send_error(req, 200, "Cant get client's mac by its ip");
        return;
    }
    
    if (!is_auth_online() || is_local_auth_mode()) {
        char gw_port[8] = {0};
        snprintf(gw_port, sizeof(gw_port), "%d", config_get_config()->gw_port);
        debug(LOG_INFO, "Auth server is offline");
        ev_http_reply_client_error(req, is_local_auth_mode()?LOCAL_AUTH:AUTHSERVER_OFFLINE, 
            gw_setting->gw_address_v4?gw_setting->gw_address_v4:gw_setting->gw_address_v6, 
            gw_port, "http", remote_host, mac);
        return;
    }    

    if (process_already_login_client(req, mac, remote_host)) return;

    if (!is_bypass_mode() &&
        config->wired_passed && 
        process_wired_device_pass(req, mac)) 
        return;

    char *redir_url = wd_get_redir_url_to_auth(req, gw_setting, mac, remote_host, config->gw_port, config->device_id, is_ssl);
    if (!redir_url) {
        evhttp_send_error(req, 200, "Cant get client's redirect to auth server's url");
        return;
    }
    
    if (!is_ssl &&
        !config->bypass_apple_cna && 
        process_apple_wisper(req, mac, remote_host, redir_url, config->bypass_apple_cna))
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
    debug(LOG_DEBUG, "ev_http_callback_auth: the request is %s", evhttp_request_get_uri(req));
    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        ev_http_respond_options(req);
        debug(LOG_INFO, "options request");
        return;
    }

	evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");
	
    char *token = ev_http_find_query(req, "token");
    if (!token) {
        evhttp_send_error(req, 200, "Invalid token");
        return;
    } 

    char *remote_host = ev_http_find_query(req, "client_ip");
    char *mac = ev_http_find_query(req, "client_mac");
    char *gw_id = ev_http_find_query(req, "gw_id");
    t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id);
    if (!gw_setting) {
        evhttp_send_error(req, 200, "Invalid gateway id");
        free(token);
        if (remote_host) free(remote_host);
        if (mac) free(mac);
        return;
    }
    
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
    if (!client) {
        client = client_list_find_by_mac(mac);
        if (!client) {
            client = client_list_add(remote_host, mac, token, gw_setting);
            new_client = 1;
        } else {
            fw_deny(client);
            free(client->ip);
            free(client->token);
            client->ip = safe_strdup(remote_host);
            client->token = safe_strdup(token);
        }
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
 * @brief process client's local pass request
 * 
 * @param req Client's http request
 * @param arg useless
 * 
 */
void
ev_http_callback_local_auth(struct evhttp_request *req, void *arg)
{
    s_config *config = config_get_config();
    if (config->auth_servers) {
        evhttp_send_error(req, HTTP_OK, "Only no auth server configured can use local pass");
        return;
    }

    // get the ip and mac of the client
    const char *mac = ev_http_find_query(req, "mac");
    const char *ip = ev_http_find_query(req, "ip");
    if (!mac || !ip) {
        evhttp_send_error(req, HTTP_OK, "MAC and IP need to be specified");
        goto END;
    }

    // fw_allow the client
    LOCK_CLIENT_LIST();
    fw_allow_ip_mac(ip, mac); 
    UNLOCK_CLIENT_LIST();

    // redirect the client to the internet
    ev_http_send_redirect(req, config->local_portal, "Redirect to internet");

END:
    if (mac) free((void *)mac);
    if (ip) free((void *)ip);
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
 * @brief process client's device request
 *
 * @param req Client's http request
 * @param arg useless
 *
 */
void
ev_http_callback_device(struct evhttp_request *req, void *arg)
{
    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        ev_http_respond_options(req);
        return;
    }

    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Origin", "*");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Access-Control-Allow-Methods", "GET,POST,OPTIONS,DELETE,PUT");

    // Get client IP from query string
    char *client_ip = ev_http_find_query(req, "client_ip");
    if (!client_ip) {
        evhttp_send_error(req, HTTP_OK, "Client IP need to be specified");
        return;
    }

    char if_name[IFNAMSIZ] = {0};
    if (!get_ifname_by_address(client_ip, if_name)) {
        debug(LOG_ERR, "get_ifname_by_address [%s] failed", client_ip);
        evhttp_send_error(req, 200, "Cant get client's interface name");
        free(client_ip);
        return;
    }


    if_name[IFNAMSIZ-1] = '\0';
    t_gateway_setting *gw_setting = get_gateway_setting_by_ifname(if_name);
    if (!gw_setting) {
        debug(LOG_ERR, "get_gateway_setting_by_ifname [%s] failed", if_name);
        evhttp_send_error(req, 200, "Cant get gateway setting by interface name");
        free(client_ip);
        return;
    }

    const char *json_query_result = query_bypass_user_status(client_ip, gw_setting->gw_id, gw_setting->gw_address_v4, QUERY_BY_IP);
    if (!json_query_result) {
        free(client_ip);
        evhttp_send_error(req, HTTP_OK, "Failed to query bypass user status");
        return;
    }
    free(client_ip);

    struct evbuffer *ev = evbuffer_new();
    if (!ev) {
        free((void *)json_query_result);
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create response buffer");
        return;
    }

    evbuffer_add(ev, json_query_result, strlen(json_query_result));
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_send_reply(req, HTTP_OK, "OK", ev);

    free((void *)json_query_result);
    evbuffer_free(ev);
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
static void
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
	
    pthread_mutex_lock(&g_resource_lock);
    evbuffer_add(evb, wifidog_redir_html->front, wifidog_redir_html->front_len);
    evbuffer_add_printf(evb, WIFIDOG_REDIR_HTML_CONTENT, redir_url);
    evbuffer_add(evb, wifidog_redir_html->rear, wifidog_redir_html->rear_len);
    pthread_mutex_unlock(&g_resource_lock);

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
