
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

// Define max allowed file size (10KB)
#define MAX_HTML_FILE_SIZE (10 * 1024)

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
                "<title>apfree-wifidog redirect ...</title>"		\
                "<script type=\"text/javascript\">"	\
                    "window.setTimeout(function() {location.href = \"%s\";}, 10);"  \
                "</script>"	\
                "<body>"	\
                "apfree-wifidog redirect ..."	\
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
static int process_already_login_client(struct evhttp_request *req, const char *mac, const char *remote_host, const int addr_type);
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
        orig_url = safe_strdup(config_get_config()->local_portal);
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
process_already_login_client(struct evhttp_request *req, const char *mac, const char *remote_host, const int addr_type)
{
	if (!mac || !remote_host) {
        debug(LOG_ERR, "mac or remote_host is NULL");
        return 0;
    }

    int flag = 0;
	
    LOCK_CLIENT_LIST();
    t_client *clt = client_list_find_by_mac(mac);
    if (clt)
        debug(LOG_DEBUG, "Client %s info: ip [%s] ip6 [%s] remote_host [%s] remote_mac [%s] addr_type [%d]",
            clt->mac,
            clt->ip ? clt->ip : "N/A",
            clt->ip6 ? clt->ip6 : "N/A",
            remote_host, mac, addr_type);
    if (clt && ((addr_type == 1 && clt->ip && strcmp(clt->ip, remote_host) != 0) ||
        (addr_type == 2 && clt->ip6 && strcmp(clt->ip6, remote_host) != 0))) { // the same client get different ip
        fw_deny(clt);
        free(clt->ip);
        if (addr_type == 1) {
            free(clt->ip);
            clt->ip = safe_strdup(remote_host);
        } else {
            free(clt->ip6);
            clt->ip6 = safe_strdup(remote_host);
        }
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
 * @brief Replace multiple placeholders in a template string with their corresponding values
 *
 * @param template The template string containing placeholders
 * @param placeholders Array of placeholder strings to be replaced
 * @param values Array of values to replace the placeholders with
 * @param count Number of placeholder/value pairs
 * @return Newly allocated string with replacements made, or NULL on failure
 */
static char *
replace_placeholder_multi(const char *template, const char **placeholders, const char **values, size_t count) {
    if (!template || !placeholders || !values || count == 0) {
        return NULL;
    }

    int need_replace = 0;
    for (size_t i = 0; i < count; i++) {
        if (!placeholders[i] || !values[i]) {
            debug(LOG_ERR, "Invalid placeholder or value");
            return NULL;
        }
        if (strstr(template, placeholders[i])) {
            need_replace = 1;
        }
    }

    if (!need_replace) {
        debug(LOG_DEBUG, "No placeholders found in template");
        return safe_strdup(template);
    }

    // Calculate required buffer size
    size_t total_len = strlen(template) + 1;
    size_t *placeholder_lens = malloc(count * sizeof(size_t));
    size_t *value_lens = malloc(count * sizeof(size_t));
    
    if (!placeholder_lens || !value_lens) {
        free(placeholder_lens);
        free(value_lens);
        return NULL;
    }

    for (size_t i = 0; i < count; i++) {
        placeholder_lens[i] = strlen(placeholders[i]);
        value_lens[i] = strlen(values[i]);
        // Adjust total length by difference between placeholder and value lengths
        if (value_lens[i] > placeholder_lens[i]) {
            total_len += value_lens[i] - placeholder_lens[i];
        }
    }

    // Allocate final buffer
    char *result = malloc(total_len);
    if (!result) {
        free(placeholder_lens);
        free(value_lens);
        return NULL;
    }

    const char *src = template;
    char *dst = result;
    
    while (*src) {
        int replaced = 0;
        for (size_t i = 0; i < count; i++) {
            if (strncmp(src, placeholders[i], placeholder_lens[i]) == 0) {
                memcpy(dst, values[i], value_lens[i]);
                dst += value_lens[i];
                src += placeholder_lens[i];
                replaced = 1;
                break;
            }
        }
        if (!replaced) {
            *dst++ = *src++;
        }
    }
    *dst = '\0';

    free(placeholder_lens);
    free(value_lens);
    return result;
}

static struct evbuffer *
process_custom_auth_offline_page(const char *ip, const char *port, const char *proto, const char *client_ip, const char *client_mac)
{
    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        return NULL;
    }

    const char *placeholders[] = {
        "{{ip}}",
        "{{port}}",
        "{{proto}}",
        "{{client_ip}}",
        "{{client_mac}}"
    };

    const char *values[] = {
        ip,
        port,
        proto,
        client_ip,
        client_mac
    };

    char *page = replace_placeholder_multi((const char *)evbuffer_pullup(evb_authserver_offline_page, -1), placeholders, values, sizeof(placeholders) / sizeof(placeholders[0]));
    if (!page) {
        evbuffer_free(evb);
        return NULL;
    }

    evbuffer_add(evb, page, strlen(page));
    free(page);
    return evb;
}


/**
 * @brief reply client error of gw internet offline or auth server offline
 * 
 * @param req  The http request
 * @param type 1: internet not online
 *             other: auth server offline
 */
void
ev_http_reply_client_error(struct evhttp_request *req, enum reply_client_page_type type, 
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
    case LOCAL_CUSTROM_AUTH:
        pthread_mutex_lock(&g_resource_lock);
        evb = process_custom_auth_offline_page(ip, port, proto, client_ip, client_mac);
        pthread_mutex_unlock(&g_resource_lock);
        break;
    case LOCAL_AUTH:
    default:
        char redir_url[256] = {0};
        if (!is_valid_ip(ip))
            snprintf(redir_url, sizeof(redir_url), "%s://[%s]:%s/wifidog/local_auth?ip=%s&mac=%s", proto, ip, port, client_ip, client_mac);
        else
            snprintf(redir_url, sizeof(redir_url), "%s://%s:%s/wifidog/local_auth?ip=%s&mac=%s", proto, ip, port, client_ip, client_mac);
        debug(LOG_DEBUG, "local auth redir_url: %s", redir_url);
        evb = evbuffer_new();
        evbuffer_add_printf(evb, AW_LOCAL_REDIRECT_MSG, redir_url);
        break;
    }

    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to evbuffer_new");
        debug(LOG_ERR, "Failed to evbuffer_new");
        return;
    }

    debug(LOG_DEBUG, "reply client type: %d", type);
    evhttp_send_reply(req, 200, "OK", evb);
    evbuffer_free(evb);
}

int
ev_http_connection_get_peer(struct evhttp_connection *evcon, char **remote_host, uint16_t *port)
{
    char *ip = NULL;
    evhttp_connection_get_peer(evcon, &ip, port);
    if (ip == NULL) {
        debug(LOG_ERR, "evhttp_connection_get_peer failed");
        return 0;
    }
    debug(LOG_DEBUG, "get peer ip is %s", ip);

    struct sockaddr_storage ss;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    
    // Try IPv6 first
    if (inet_pton(AF_INET6, ip, &sin6->sin6_addr) > 0) {
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            // Handle IPv4-mapped IPv6 address
            struct in_addr ipv4_addr;
            memcpy(&ipv4_addr, &sin6->sin6_addr.s6_addr[12], 4);
            *remote_host = safe_malloc(INET_ADDRSTRLEN);
            if (!inet_ntop(AF_INET, &ipv4_addr, *remote_host, INET_ADDRSTRLEN)) {
                debug(LOG_ERR, "inet_ntop failed for IPv4-mapped address: %s", strerror(errno));
                free(*remote_host);
                return 0;
            }
            debug(LOG_INFO, "IPv4-mapped IPv6 address detected, converted to IPv4: %s", *remote_host);
            return 1; // IPv4
        } else {
            // Native IPv6 address
            *remote_host = safe_malloc(INET6_ADDRSTRLEN);
            if (!inet_ntop(AF_INET6, &sin6->sin6_addr, *remote_host, INET6_ADDRSTRLEN)) {
                debug(LOG_ERR, "inet_ntop failed for IPv6 address: %s", strerror(errno));
                free(*remote_host);
                return 0;
            }
            debug(LOG_INFO, "IPv6 address detected: %s", *remote_host);
            return 2; // IPv6
        }
    } 
    // Try IPv4
    else if (inet_pton(AF_INET, ip, &sin->sin_addr) > 0) {
        *remote_host = safe_malloc(INET_ADDRSTRLEN);
        if (!inet_ntop(AF_INET, &sin->sin_addr, *remote_host, INET_ADDRSTRLEN)) {
            debug(LOG_ERR, "inet_ntop failed for IPv4 address: %s", strerror(errno));
            free(*remote_host);
            return 0;
        }
        debug(LOG_INFO, "IPv4 address detected: %s", *remote_host);
        return 1; // IPv4
    }

    // If we get here, the address format was invalid
    debug(LOG_ERR, "Invalid IP address format: %s", ip);
    *remote_host = NULL;
    return 0;
}

/**
 * @brief Determine what type of offline page to show to clients
 * 
 * @return LOCAL_CUSTROM_AUTH if using custom auth offline page
 *         LOCAL_AUTH if using local auth mode without custom page
 *         AUTHSERVER_OFFLINE if auth server is offline in normal mode
 */
static enum reply_client_page_type
get_authserver_offline_page_type()
{
    // First check if we're in local auth mode
    if (!is_local_auth_mode()) {
        return AUTHSERVER_OFFLINE;
    }
    
    // In local auth mode, check if custom page is configured
    return is_custom_auth_offline_page() ? LOCAL_CUSTROM_AUTH : LOCAL_AUTH;
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
    if (!is_online()) {
        debug(LOG_INFO, "Internet is offline");
        ev_http_reply_client_error(req, INTERNET_OFFLINE, NULL, NULL, NULL, NULL, NULL);
        return;
    }

    char *remote_host = NULL;
    uint16_t port;
    int addr_type = ev_http_connection_get_peer(evhttp_request_get_connection(req), &remote_host, &port);
	if (addr_type == 0) return;
    

    struct bufferevent *bev = evhttp_connection_get_bufferevent(evhttp_request_get_connection(req));
    evutil_socket_t fd = bufferevent_getfd(bev);
    if (fd < 0) {
        debug(LOG_ERR, "bufferevent_getfd failed: %s", strerror(errno));
        evhttp_send_error(req, 200, "Cant get client's fd");
        return;
    }

    t_gateway_setting *gw_setting = get_gateway_setting_by_addr(remote_host, addr_type);
    if (!gw_setting) {
        debug(LOG_ERR, "Failed to get gateway settings for address [%s] type [%d]", remote_host, addr_type);
        evhttp_send_error(req, 200, "Cant get gateway setting by client's ip");
        return;
    }

    s_config *config = config_get_config();
    char mac[MAC_LENGTH] = {0};
    if (is_bypass_mode()) {
        snprintf(mac, sizeof(mac), "%s", "00:00:00:00:00:00");
    } else if (!br_arp_get_mac(gw_setting, remote_host, mac)) {
        debug(LOG_INFO, "get client's mac by ip [%s] failed", remote_host);
        evhttp_send_error(req, 200, "Cant get client's mac by its ip");
        return;
    }
    
    debug(LOG_INFO, "ev_http_callback_404 [%s : %s] address type [%d]", remote_host, mac, addr_type);

    if (process_already_login_client(req, mac, remote_host, addr_type)) return;

    if (!is_auth_online() || is_local_auth_mode()) {
        char gw_port[8] = {0};
        snprintf(gw_port, sizeof(gw_port), "%d", config_get_config()->gw_port);
        enum reply_client_page_type r_type = get_authserver_offline_page_type();
        debug(LOG_DEBUG, "Auth server is offline and its reply type is %d", r_type);
        ev_http_reply_client_error(req, r_type, 
            addr_type==1?gw_setting->gw_address_v4:gw_setting->gw_address_v6, 
            gw_port, "http", remote_host, mac);
        return;
    }    

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
        config->bypass_apple_cna && 
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

    evbuffer_add_printf(evb, 
        "<html><head>"
        "<script type=\"text/javascript\">"
        "setTimeout(function() { window.location.href = '%s'; }, 100);"
        "</script></head>"
        "<body>Please wait, redirecting... If nothing happens, <a href='%s'>click here</a>.</body></html>",
        url, url);

    evhttp_send_reply(req, 200, text, evb);
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

static void
gen_random_token(char *token, size_t len)
{
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (size_t i = 0; i < len; i++) {
        token[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    token[len] = '\0';
}

void
ev_http_send_user_redirect_page(struct evhttp_request *req, const char *redir_url)
{
    #define REDIRECT_PAGE_TEMPLATE \
        "<html>" \
        "<head>" \
            "<title>Redirecting...</title>" \
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" \
            "<script type=\"text/javascript\">" \
            "setTimeout(function() {" \
                "window.location.href = '%s';" \
            "}, 1000);" \
            "</script>" \
            "<style>" \
            "body { font-size: 24px; text-align: center; margin: 20px; }" \
            "h1 { font-size: 36px; }" \
            "a { font-size: 28px; }" \
            "</style>" \
        "</head>" \
        "<body>" \
            "<h1>Redirecting...</h1>" \
            "<p>If you are not redirected automatically, follow the <a href='%s'>link</a>.</p>" \
        "</body>" \
        "</html>"

    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        evhttp_send_error(req, HTTP_INTERNAL, "Failed to create response buffer");
        return;
    }

    evbuffer_add_printf(evb, REDIRECT_PAGE_TEMPLATE, redir_url, redir_url);
    evhttp_add_header(evhttp_request_get_output_headers(req), 
                     "Content-Type", "text/html; charset=UTF-8");
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
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
        debug(LOG_INFO, "Local auth called without MAC and IP specified");
        evhttp_send_error(req, HTTP_OK, "MAC and IP need to be specified");
        goto END;
    }

    uint32_t addr_type = 0;
    if (is_valid_ip(ip))
        addr_type = 1;
    else if (is_valid_ip6(ip))
        addr_type = 2;
    if (!addr_type) {
        debug(LOG_INFO, "Invalid IP address format [%s]", ip);
        evhttp_send_error(req, HTTP_OK, "Invalid IP address format");
        goto END;
    }

    t_gateway_setting *gw = get_gateway_setting_by_addr(ip, addr_type);
    if (!gw) {
        evhttp_send_error(req, HTTP_OK, "Cant get gateway setting by client's ip");
        goto END;
    }

    // fw_allow the client
    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_mac(mac);
    if (!client) {
        // New client - add and allow
        char rtoken[16] = {0};
        gen_random_token(rtoken, sizeof(rtoken) - 1);
        client = client_list_add(ip, mac, rtoken, gw);
        fw_allow(client, FW_MARK_KNOWN);
        debug(LOG_INFO, "Local pass %s %s ", mac, ip);
    } else if ((addr_type == 1 && client->ip && strcmp(client->ip, ip) != 0) ||
               (addr_type == 2 && client->ip6 && strcmp(client->ip6, ip) != 0)) {
        // Client exists but IP changed - deny old and allow new
        debug(LOG_INFO, "Local pass %s with different IP %s", mac, ip);
        fw_deny(client);
        if (addr_type == 1) {
            if (client->ip) free(client->ip);
            client->ip = safe_strdup(ip);
        } else {
            if (client->ip6) free(client->ip6);
            client->ip6 = safe_strdup(ip);
        }
        fw_allow(client, FW_MARK_KNOWN);
    } else if ((addr_type == 1 && !client->ip) || (addr_type == 2 && !client->ip6)) {
        // Client exists but missing IP field - deny and allow
        debug(LOG_INFO, "Local pass %s adding missing IP type %d", mac, addr_type);
        if (addr_type == 1) {
            client->ip = safe_strdup(ip);
        } else {
            client->ip6 = safe_strdup(ip);
        }
        fw_allow_ip_mac(ip, mac , FW_MARK_KNOWN);
    } else {
        UNLOCK_CLIENT_LIST();
        // Existing client with same IP - just allow
        debug(LOG_INFO, "Local pass %s %s already login", mac, ip);
        ev_http_send_user_redirect_page(req, config->local_portal);
        goto END;
    }
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
    if (!evb || !filename) return NULL;
    
    // check size of filename, it is great than 10k then exit
    struct stat st;
    if (stat(filename, &st) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML file %s: %s", filename, strerror(errno));
        return NULL;
    }

    if (st.st_size > MAX_HTML_FILE_SIZE) {
        debug(LOG_CRIT, "HTML file %s too large: %ld bytes (max %d)", 
              filename, (long)st.st_size, MAX_HTML_FILE_SIZE);
        return NULL;
    }

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", filename, strerror(errno));
        return NULL;
    }
    
    if (evbuffer_add_file(evb, fd, 0, st.st_size)) {
        debug(LOG_CRIT, "Failed to read HTML message file %s: %s", filename, strerror(errno));
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
