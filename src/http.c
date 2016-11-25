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
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>

 */
/* Note that libcs other than GLIBC also use this macro to enable vasprintf */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "httpd.h"

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "auth.h"
#include "firewall.h"
#include "http.h"
#include "client_list.h"
#include "common.h"
#include "centralserver.h"
#include "util.h"
#include "wd_util.h"
#include "gateway.h"

#include "version.h"

const char *apple_domains[] = {
					"captive.apple.com",
					"www.apple.com",
					NULL
};

const char *js_redirect_msg = "<!DOCTYPE html>"
				"<html>"
				"<script type=\"text/javascript\">"
					"window.location.replace(\"$redir_url\");"
				"</script>"
				"<body>"
				"</body>"
				"</html>";
const char *apple_redirect_msg = "<!DOCTYPE html>"
				"<html>"
				"<title>Success</title>"
				"<script type=\"text/javascript\">"
					"window.location.replace(\"$redir_url\");"
				"</script>"
				"<body>"
				"Success"
				"</body>"
				"</html>";

const char *apple_wisper = "<!DOCTYPE html>"
				"<html>"
				"<script type=\"text/javascript\">"
					"window.setTimeout(function() {location.href = \"captive.apple.com/hotspot-detect.html\";}, 12000);"
				"</script>"
				"<body>"
				"</body>"
				"</html>";

static int
_is_apple_captive(const char *domain)
{
	int i = 0;
	while(apple_domains[i] != NULL) {
		if(strcmp(domain, apple_domains[i]) == 0)
			return 1;
		i++;
	}

	return 0;
}

static int
_special_process(request *r, const char *mac, const char *redir_url)
{
	t_offline_client *o_client = NULL;

	if(_is_apple_captive(r->request.host)) {
		int interval = 0;
		LOCK_OFFLINE_CLIENT_LIST();
    	o_client = offline_client_list_find_by_mac(mac);
    	if(o_client == NULL) {
    		o_client = offline_client_list_add(r->clientAddr, mac);
    	} else {
			o_client->last_login = time(NULL);
			interval = o_client->last_login - o_client->first_login;
		}

		debug(LOG_DEBUG, "Into captive.apple.com hit_counts %d interval %d http version %d\n", 
				o_client->hit_counts, interval, r->request.version);
    	
		o_client->hit_counts++;

		if(o_client->client_type == 1 ) {
    		UNLOCK_OFFLINE_CLIENT_LIST();
			if(interval > 20 && r->request.version == HTTP_1_0) {
				fw_set_mac_temporary(mac, 0);	
				http_send_apple_redirect(r, redir_url);
			} else if(o_client->hit_counts > 2 && r->request.version == HTTP_1_0)
				http_send_apple_redirect(r, redir_url);
			else {
				http_send_redirect(r, redir_url, "Redirect to login page");
			}
		} else {	
			o_client->client_type = 1;
			UNLOCK_OFFLINE_CLIENT_LIST();
			http_relay_wisper(r);
		}
		return 1;
	} 

	return 0;
}
//<<< liudf added end

/** The 404 handler is also responsible for redirecting to the auth server */
void
http_callback_404(httpd * webserver, request * r, int error_code)
{  	
    if (!is_online()) {
		char *msg = evb_2_string(evb_internet_offline_page);
        send_http_page_direct(r, msg);
		free(msg);
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              r->clientAddr);
    } else if (!is_auth_online()) {
		char *msg = evb_2_string(evb_authserver_offline_page);
        send_http_page_direct(r, msg);
		free(msg);
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              r->clientAddr);
    } else {
		/* Re-direct them to auth server */
		const s_config *config = config_get_config();
		char tmp_url[MAX_BUF] = {0};  
		char *mac = arp_get(r->clientAddr);
		
		snprintf(tmp_url, (sizeof(tmp_url) - 1), "http://%s%s%s%s",
             r->request.host, r->request.path, r->request.query[0] ? "?" : "", r->request.query);
		
    	char *url = httpdUrlEncode(tmp_url);	
		char *redir_url = evhttpd_get_full_redir_url(mac!=NULL?mac:"ff:ff:ff:ff:ff:ff", peer_addr, url);
        if (mac) {                 
			t_client *clt = NULL;
            debug(LOG_DEBUG, "Got client MAC address for ip %s: %s", r->clientAddr, mac);	
			
			//>>> liudf 20160106 added
			if(_special_process(r, mac, redir_url)) {
            	goto end_process;
			}
			
			// if device has login; but after long time reconnected router, its ip changed
			LOCK_CLIENT_LIST();
			clt = client_list_find_by_mac(mac);
			if(clt && strcmp(clt->ip, r->clientAddr) != 0) {
				fw_deny(clt);
				free(clt->ip);
				clt->ip = safe_strdup(r->clientAddr);
				fw_allow(clt, FW_MARK_KNOWN);
				UNLOCK_CLIENT_LIST();
				http_send_redirect(r, tmp_url, "device has login");
            	goto end_process;
			}
			UNLOCK_CLIENT_LIST();
        }
		
        debug(LOG_DEBUG, "Captured %s requesting [%s] and re-directing them to login page", r->clientAddr, url);
		if(config->js_filter)
			http_send_js_redirect(r, redir_url);
		else
			http_send_redirect(r, redir_url, "Redirect to login page");
		
end_process:
		if (redir_url) free(redir_url);
		if (mac) free(mac);
		if (url) free(url);
    }
}

void
http_callback_wifidog(httpd * webserver, request * r)
{
    send_http_page(r, "WiFiDog", "Please use the menu to navigate the features of this WiFiDog installation.");
}

void
http_callback_about(httpd * webserver, request * r)
{
    send_http_page(r, "About WiFiDog", "This is WiFiDog version <strong>" VERSION "</strong>");
}

void
http_callback_status(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    char *status = NULL;
    char *buf;

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Status page requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    status = get_status_text();
    safe_asprintf(&buf, "<pre>%s</pre>", status);
    send_http_page(r, "WiFiDog Status", buf);
    free(buf);
    free(status);
}

/** @brief Convenience function to redirect the web browser to the auth server
 * @param r The request
 * @param urlFragment The end of the auth server URL to redirect to (the part after path)
 * @param text The text to include in the redirect header ant the mnual redirect title */
void
http_send_redirect_to_auth(request * r, const char *urlFragment, const char *text)
{
    char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }

    char *url = NULL;
    safe_asprintf(&url, "%s://%s:%d%s%s",
                  protocol, auth_server->authserv_hostname, port, auth_server->authserv_path, urlFragment);
    http_send_redirect(r, url, text);
    free(url);
}

/** @brief Sends a redirect to the web browser 
 * @param r The request
 * @param url The url to redirect to
 * @param text The text to include in the redirect header and the manual redirect link title.  NULL is acceptable */
void
http_send_redirect(request * r, const char *url, const char *text)
{
    char *message = NULL;
    char *header = NULL;
    char *response = NULL;
    /* Re-direct them to auth server */
    debug(LOG_DEBUG, "Redirecting client browser to %s", url);
    safe_asprintf(&header, "Location: %s", url);
	// liudf 20160104; change 302 to 307
    safe_asprintf(&response, "307 %s\r\n", text ? text : "Redirecting");
    httpdSetResponse(r, response);
    httpdAddHeader(r, header);
    free(response);
    free(header);

    safe_asprintf(&message, "<html><body>Please <a href='%s'>click here</a>.</body></html>", url);
    httpdOutPutDirect(r, message);
	_httpd_closeSocket(r);
    free(message);
}

void
http_callback_auth(httpd * webserver, request * r)
{
    t_client *client;
    httpVar *token;
    char *mac;
    httpVar *logout = httpdGetVariableByName(r, "logout");

    if ((token = httpdGetVariableByName(r, "token"))) {
        /* They supplied variable "token" */
        if (!(mac = arp_get(r->clientAddr))) {
            /* We could not get their MAC address */
            debug(LOG_ERR, "Failed to retrieve MAC address for ip %s", r->clientAddr);
            send_http_page(r, "WiFiDog Error", "Failed to retrieve your MAC address");
        } else {
            /* We have their MAC address */
            LOCK_CLIENT_LIST();

            if ((client = client_list_find(r->clientAddr, mac)) == NULL) {
                debug(LOG_DEBUG, "New client for %s", r->clientAddr);
                client_list_add(r->clientAddr, mac, token->value);
            } else if (logout) {
                logout_client(client);
            } else {
                debug(LOG_DEBUG, "Client for %s is already in the client list", client->ip);
            }

            UNLOCK_CLIENT_LIST();
            if (!logout) { /* applies for case 1 and 3 from above if */
                authenticate_client(r);
            }
            free(mac);
        }
    } else {
        /* They did not supply variable "token" */
        send_http_page(r, "WiFiDog error", "Invalid token");
    }
}

void
http_callback_disconnect(httpd * webserver, request * r)
{
    const s_config *config = config_get_config();
    /* XXX How do you change the status code for the response?? */
    httpVar *token = httpdGetVariableByName(r, "token");
    httpVar *mac = httpdGetVariableByName(r, "mac");

    if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

    if (token && mac) {
        t_client *client;

        LOCK_CLIENT_LIST();
        client = client_list_find_by_mac(mac->value);

        if (!client || strcmp(client->token, token->value)) {
            UNLOCK_CLIENT_LIST();
            debug(LOG_INFO, "Disconnect %s with incorrect token %s", mac->value, token->value);
            httpdOutput(r, "Invalid token for MAC");
            return;
        }

        /* TODO: get current firewall counters */
        logout_client(client);
        UNLOCK_CLIENT_LIST();

    } else {
        debug(LOG_INFO, "Disconnect called without both token and MAC given");
        httpdOutput(r, "Both the token and MAC need to be specified");
        return;
    }

    return;
}

// liudf added 20160421
void
http_callback_temporary_pass(httpd * webserver, request * r)
{	
    const s_config *config = config_get_config();
    httpVar *mac = httpdGetVariableByName(r, "mac");
	
	if (config->httpdusername &&
        (strcmp(config->httpdusername, r->request.authUser) ||
         strcmp(config->httpdpassword, r->request.authPassword))) {
        debug(LOG_INFO, "Disconnect requested, forcing authentication");
        httpdForceAuthenticate(r, config->httpdrealm);
        return;
    }

	if(mac) {
        debug(LOG_INFO, "Temporary passed %s", mac->value);
		fw_set_mac_temporary(mac->value, 0);	
        httpdOutput(r, "startWeChatAuth();");
	} else {
        debug(LOG_INFO, "Temporary pass called without  MAC given");
        httpdOutput(r, "MAC need to be specified");
        return;
    }

	return;
}

void
send_http_page(request * r, const char *title, const char *message)
{
    s_config *config = config_get_config();
    char *buffer;
    struct stat stat_info;
    int fd;
    ssize_t written;

    fd = open(config->htmlmsgfile, O_RDONLY);
    if (fd == -1) {
        debug(LOG_CRIT, "Failed to open HTML message file %s: %s", config->htmlmsgfile, strerror(errno));
        return;
    }

    if (fstat(fd, &stat_info) == -1) {
        debug(LOG_CRIT, "Failed to stat HTML message file: %s", strerror(errno));
        close(fd);
        return;
    }
    // Cast from long to unsigned int
    buffer = (char *)safe_malloc((size_t) stat_info.st_size + 1);
    written = read(fd, buffer, (size_t) stat_info.st_size);
    if (written == -1) {
        debug(LOG_CRIT, "Failed to read HTML message file: %s", strerror(errno));
        free(buffer);
        close(fd);
        return;
    }
    close(fd);

    buffer[written] = 0;
    httpdAddVariable(r, "title", title);
    httpdAddVariable(r, "message", message);
    httpdAddVariable(r, "nodeID", config->gw_id);
    httpdOutput(r, buffer);
    free(buffer);
}

//>>> liudf added 20160104
void
http_send_js_redirect(request *r, const char *redir_url)
{
	struct evbuffer *evb = evbuffer_new ();	
	
	evbuffer_add_buffer(evb, wifidog_redir_html->evb_front);
	evbuffer_add_printf(evb, WIFIDOG_REDIR_HTML_CONTENT, redir_url);
	evbuffer_add_buffer(evb, wifidog_redir_html->evb_rear);
	
	char *redirect_html = evb_2_string(evb);
    
	httpdOutputDirect(r, redirect_html);
	_httpd_closeSocket(r);
	
	free(redirect_html);
	evbuffer_free (evb);
}

void
http_send_apple_redirect(request *r, const char *redir_url)
{
    httpdAddVariable(r, "redir_url", redir_url);
    httpdOutput(r, apple_redirect_msg);
	_httpd_closeSocket(r);
}

void
http_relay_wisper(request *r)
{
	httpdOutputDirect(r, apple_wisper);
	_httpd_closeSocket(r);
}

void send_http_page_direct(request *r,  char *msg) 
{
	httpdOutputDirect(r, msg);
	_httpd_closeSocket(r);
}

//<<< liudf added end
