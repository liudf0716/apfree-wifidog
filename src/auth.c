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
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
	@author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#define _GNU_SOURCE

#include "common.h"
#include "httpd.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"
#include "https_client.h"
#include "ping_thread.h"

static void client_timeout_check_cb(evutil_socket_t, short, void *);

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    wd_request_loop(client_timeout_check_cb);
}

static void 
client_timeout_check_cb(evutil_socket_t fd, short event, void *arg) {
	struct wd_request_context *context = (struct wd_request_context *)arg;
	struct timeval tv;
	
	debug(LOG_DEBUG, "client_timeout_check_cb begin");

    ev_fw_sync_with_authserver(context);

	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval;
	event_add(context->ev_timeout, &tv);
}

void
ev_logout_client(void *ctx, t_client *client)
{
    struct wd_request_context *context = (struct wd_request_context *)ctx;
    const s_config *config = config_get_config();

    fw_deny(client);

    UNLOCK_CLIENT_LIST();
    client_list_remove(client);
    LOCK_CLIENT_LIST();

    if (config->auth_servers != NULL) {   
        char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, online_client, client);
        if (uri) {
            struct auth_response_client *clt_res = safe_malloc(sizeof(struct auth_response_client));
            clt_res->type = request_type_logout;
            clt_res->client = client;
            if (context->data) free(context->data);     
            context->data = clt_res;
            wd_make_request(context, process_auth_server_response, context);
            evhttp_make_request(context->evcon, context->req, EVHTTP_REQ_GET, uri);
            free(uri);
        } 
    }
}

/**
 * @brief Logout a client and report to auth server.
 *
 * This function assumes it is being called with the client lock held! This
 * function remove the client from the client list and free its memory, so
 * client is no langer valid when this method returns.
 *
 * @param client Points to the client to be logged out
 */
void
logout_client(t_client * client)
{
    t_authresponse authresponse;
    const s_config *config = config_get_config();
    fw_deny(client);
    client_list_remove(client);

    /* Advertise the logout if we have an auth server */
    if (config->auth_servers != NULL) {
        UNLOCK_CLIENT_LIST();
        auth_server_request(&authresponse, REQUEST_TYPE_LOGOUT,
                            client->ip, client->mac, client->token,
                            client->counters.incoming, client->counters.outgoing, 
							client->counters.incoming_delta, client->counters.outgoing_delta,
							//>>> liudf added 20160112
							client->first_login, (client->counters.last_updated - client->first_login),
							client->name?client->name:"null", client->wired);
		close_auth_server();
        if (authresponse.authcode == AUTH_ERROR)
            debug(LOG_WARNING, "Auth server error when reporting logout");
        LOCK_CLIENT_LIST();
    }

    client_free_node(client);
}

/** Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
@param r httpd request struct
*/
void
authenticate_client(request * r)
{
    t_client *client, *tmp;
    t_authresponse auth_response; 
    char *urlFragment = NULL;

    LOCK_CLIENT_LIST();
    client = client_dup(client_list_find_by_ip(r->clientAddr));
    UNLOCK_CLIENT_LIST();

    if (client == NULL) {
        debug(LOG_ERR, "authenticate_client(): Could not find client for %s", r->clientAddr);
        return;
    }

    s_config    *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        struct evhttps_request_context *context = evhttps_context_init();
        if (!context) {
            client_list_destroy(client);
            return;
        }

        char *uri = get_auth_uri(REQUEST_TYPE_LOGIN, online_client, client);
        if (uri) {
            struct auth_response_client authresponse_client;
            memset(&authresponse_client, 0, sizeof(authresponse_client));
            authresponse_client.type    = request_type_login;
            authresponse_client.client  = client;
            authresponse_client.req     = r;
            evhttps_request(context, uri, 2, process_auth_server_response, &authresponse_client);
            free(uri);
        }

        evhttps_context_exit(context);
        return;
    }

    char *token = NULL;
    httpVar *var = NULL;
    /* Users could try to log in(so there is a valid token in
     * request) even after they have logged in, try to deal with
     * this */
    if ((var = httpdGetVariableByName(r, "token")) != NULL) {
        token = safe_strdup(var->value);
    } else {
        token = safe_strdup(client->token);
    }

	//<<<
    /* 
     * At this point we've released the lock while we do an HTTP request since it could
     * take multiple seconds to do and the gateway would effectively be frozen if we
     * kept the lock.
     */
    auth_server_request(&auth_response, REQUEST_TYPE_LOGIN, client->ip, client->mac, token, 0, 0, 0, 0, 0, 0, "null", client->wired);
	close_auth_server(); 
	
    /* Prepare some variables we'll need below */
    
    
    LOCK_CLIENT_LIST();
    /* can't trust the client to still exist after n seconds have passed */
    tmp = client_list_find_by_client(client);
    if (NULL == tmp) {
        debug(LOG_ERR, "authenticate_client(): Could not find client node for %s (%s)", client->ip, client->mac);
        UNLOCK_CLIENT_LIST();
        client_list_destroy(client);    /* Free the cloned client */
        free(token);
        return;
    }

    client_list_destroy(client);        /* Free the cloned client */
    client = tmp;
    if (strcmp(token, client->token) != 0) {
        /* If token changed, save it. */
        free(client->token);
        client->token = token;
    } else {
        free(token);
    }
    
	
    switch (auth_response.authcode) {

    case AUTH_ERROR:
		/* Error talking to central server */
        debug(LOG_ERR, "Got ERROR from central server authenticating token %s from %s at %s", client->token, client->ip,
              client->mac);
		client_list_delete(client);	
    	UNLOCK_CLIENT_LIST();
        
        send_http_page(r, "Error!", "Error: We did not get a valid answer from the central server");
        break;

    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO,
              "Got DENIED from central server authenticating token %s from %s at %s - deleting from firewall and redirecting them to denied message",
              client->token, client->ip, client->mac);
        fw_deny(client);
		client_list_delete(client);
    	UNLOCK_CLIENT_LIST();
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to denied message");
        free(urlFragment);
        break;

    case AUTH_VALIDATION:
        fw_allow(client, FW_MARK_PROBATION);
    	UNLOCK_CLIENT_LIST();
        /* They just got validated for X minutes to check their email */
        debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
              "- adding to firewall and redirecting them to activate message", client->token, client->ip, client->mac);
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to activate message");
        free(urlFragment);
        break;

    case AUTH_ALLOWED:
        fw_allow(client, FW_MARK_KNOWN);
        UNLOCK_CLIENT_LIST();
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
              "adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
    	
		//>>> liudf added 20160112
		client->first_login = time(NULL);
		client->is_online = 1;
        {
            LOCK_OFFLINE_CLIENT_LIST();
            t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
            if(o_client)
                offline_client_list_delete(o_client);
            UNLOCK_OFFLINE_CLIENT_LIST();
        }
		
		//<<< liudf added end
        served_this_session++;
		if(httpdGetVariableByName(r, "type")) {
        	send_http_page_direct(r, "<htm><body>weixin auth success!</body><html>");
		} else {
        	safe_asprintf(&urlFragment, "%sgw_id=%s&channel_path=%s&mac=%s&name=%s", 
				auth_server->authserv_portal_script_path_fragment, 
				config->gw_id,
				g_channel_path?g_channel_path:"null",
				client->mac?client->mac:"null",
				client->name?client->name:"null");
        	http_send_redirect_to_auth(r, urlFragment, "Redirect to portal");
        	free(urlFragment);
		}
        break;

    case AUTH_VALIDATION_FAILED:
		/* Client had X minutes to validate account by email and didn't = too late */
        debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
              "- redirecting them to failed_validation message", client->token, client->ip, client->mac);
		client_list_delete(client);
    	UNLOCK_CLIENT_LIST();
        
        safe_asprintf(&urlFragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        http_send_redirect_to_auth(r, urlFragment, "Redirect to failed validation message");
        free(urlFragment);
        break;

    default:
		debug(LOG_WARNING,
              "I don't know what the validation code %d means for token %s from %s at %s - sending error message",
              auth_response.authcode, client->token, client->ip, client->mac);
		client_list_delete(client);	
    	UNLOCK_CLIENT_LIST();
        
        send_http_page_direct(r, "<htm><body>Internal Error, We can not validate your request at this time</body></html>");
        break;

    }

    return;
}
