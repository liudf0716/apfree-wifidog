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
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "centralserver.h"
#include "firewall.h"
#include "version.h"
#include "debug.h"
#include "wd_client.h"
#include "http.h"
#include "ping_thread.h"

/**
 * @brief process auth server's roam request
 * The response json like this:
 * {"roam":"yes|no", "client":{"token":"client_token", "first_login":"first login time"}} 
 * 
 * @param ctx The wifidog's request context, need to free its data member
 * 
 */ 
static void
process_auth_server_roam(struct evhttp_request *req, void *ctx)
{
    struct roam_req_info *roam = ((struct wd_request_context *)ctx)->data;
    if (!req) {
        mark_auth_offline();
        free(roam);
        return;
    }

    debug(LOG_DEBUG, "process auth server roam response");
	
    char buffer[MAX_BUF] = {0};
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) > 0 ) {
        mark_auth_online();
    } else {
        mark_auth_offline();
        free(roam);
        return;
    }

    json_object *roam_info = json_tokener_parse(buffer);
    if(roam_info == NULL) {
        debug(LOG_ERR, "error parse json info %s!", buffer);
        free(roam);
        return ;
    }

    json_object *roam_jo = NULL;
    if ( !json_object_object_get_ex(roam_info, "roam", &roam_jo)) {
        json_object_put(roam_info);
        free(roam);
        return ;
    }
    
    const char *is_roam = json_object_get_string(roam_jo);
    if(is_roam && strcmp(is_roam, "yes") == 0) {
        json_object *client = NULL;
        if( json_object_object_get_ex(roam_info, "client", &client)) {
            add_online_client(roam->ip, roam->mac, client);
        } else {
			debug(LOG_ERR, "no roam client info!!!!!");
		}
    }

    json_object_put(roam_info);
    free(roam);
}

/**
 * @brief get roam request uri
 * 
 */ 
static char *
get_roam_request_uri(s_config *config, t_auth_serv *auth_server, const char *mac)
{
    char *roam_uri = NULL;
    safe_asprintf(&roam_uri, "%sroam?gw_id=%s&mac=%s&channel_path=%s", 
        auth_server->authserv_path,
        config->gw_id,
		mac,
		g_channel_path?g_channel_path:"null");
    return roam_uri;
}

/**
 * @brief wifidog make roam quest to auth server
 * 
 * @param roam The roam request data, need to be free 
 * 
 */ 
void 
make_roam_request(struct wd_request_context *context, struct roam_req_info *roam)
{
    char *uri = get_roam_request_uri(config_get_config(), get_auth_server(), roam->mac);
    if (!uri) {
        free(roam);
        return;
    }

    debug(LOG_DEBUG, "roam request uri [%s]", uri);

    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req      = NULL;
    context->data = roam; 
    wd_make_request(context, &evcon, &req, process_auth_server_roam);
    evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    free(uri);
}

static void
process_auth_server_login_v2(struct evhttp_request *req, void *ctx)
{
	auth_req_info *auth = ((struct wd_request_context *)ctx)->data;
	debug(LOG_DEBUG, "process auth server login2 response");
	
    char buffer[MAX_BUF] = {0};
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) <= 0 ) {
		free(auth);
		return;
	}
	
	json_object *json_ret = json_tokener_parse(buffer);
	json_object *ret_code = NULL;
	json_object_object_get_ex(json_ret, "ret_code", &ret_code);
	int retCode = json_object_get_int(ret_code);
	if (retCode != 0) {
		free(auth);
		debug(LOG_INFO, "add test client failure: %d", retCode);
		return;
	}
	
	json_object *client = NULL;
	if( json_object_object_get_ex(json_ret, "client", &client)) {
		add_online_client(auth->ip, auth->mac, client);
	} else {
		debug(LOG_ERR, "no roam client info!!!!!");
	}
	
	json_object_put(json_ret);
	free(auth);
}

/**
 * @brief get login2 request uri
 * 
 */ 
static char *
get_login_v2_request_uri(s_config *config, t_auth_serv *auth_server, const auth_req_info *auth)
{
    char *login2_uri = NULL;
    safe_asprintf(&login2_uri, "%slogin2?gw_id=%s&gw_address=%s&gw_port=%d&mac=%s&channel_path=%s&cltIp=%s", 
        auth_server->authserv_path,
        config->gw_id,
		config->gw_address,
		config->gw_port,
		auth->mac,
		g_channel_path?g_channel_path:"null",
		auth->ip);
    return login2_uri;
}

/**
 * @brief wifidog make auth quest to auth server
 * 
 * @param auth The auth request data, need to be free 
 * 
 */ 
void 
make_auth_request(struct wd_request_context *context, auth_req_info *auth)
{
	char *uri = get_login_v2_request_uri(config_get_config(), get_auth_server(), auth);
    if (!uri) {
        free(auth);
        return;
    }
    debug(LOG_DEBUG, "login2 request uri [%s]", uri);

    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req      = NULL;
    context->data = auth;
    if (!wd_make_request(context, &evcon, &req, process_auth_server_login_v2)) {
        evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    } else {
        free(auth);
    }
    free(uri);
}

/**
 * @brief get auth counter v2 uri
 * @return need to be free by the caller
 * 
 */ 
char *
get_auth_counter_v2_uri()
{
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;
    safe_asprintf(&uri, "%s%sstage=%s",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             REQUEST_TYPE_COUNTERS_V2);
    assert(uri != NULL);
    debug(LOG_DEBUG, "auth counter v2 uri is [%s]", uri);
    return uri;
}

/**
 * @brief get client's auth request uri according to its type
 * 
 */ 
char * 
get_auth_uri(const char *request_type, client_type_t type, void *data)
{
    char *ip = NULL, *mac = NULL, *name = NULL, *safe_token = NULL;
    unsigned long long int incoming = 0,  outgoing = 0, incoming_delta = 0, outgoing_delta = 0;
    time_t first_login = 0;
    uint32_t online_time = 0, wired = 0;

    switch(type) {
    case ONLINE_CLIENT:
    {
        t_client *o_client = (t_client *)data;
        ip  = o_client->ip;
        mac = o_client->mac;
        safe_token = o_client->token;
        if (o_client->name)
            name = o_client->name;
        first_login = o_client->first_login;
        incoming = o_client->counters.incoming;
        outgoing = o_client->counters.outgoing;
        incoming_delta  = o_client->counters.incoming_delta;
        outgoing_delta  = o_client->counters.outgoing_delta;
        wired = o_client->wired;
        online_time = time(0) - first_login;
        break;
    }    
    case TRUSTED_CLIENT:
    {
        t_trusted_mac *t_mac = (t_trusted_mac *)data;
        ip  = t_mac->ip;
        mac = t_mac->mac;
        wired = br_is_device_wired(mac);
        break;
    }
    default:
        return NULL;
    }

    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;
    int nret = 0;
    if (config->deltatraffic) {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%u",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, 
             safe_token?safe_token:"null", 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null", wired);
    } else {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&channel_path=%s&name=%s&wired=%u",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, mac, 
             safe_token?safe_token:"null", 
             incoming, 
             outgoing, 
             (long long)first_login,
             online_time,
             config->gw_id,
             g_channel_path?g_channel_path:"null", 
             name?name:"null", wired);
    }

    return nret>0?uri:NULL;
}

/**
 * @brief parse response from auth server
 * 
 */ 
static int
parse_auth_server_response(t_authresponse *authresponse, struct evhttp_request *req) 
{
    if (!req) {
        mark_auth_offline();
        return 0;
    }
	
    char buffer[MAX_BUF] = {0};
	char *tmp = NULL;
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) > 0 && 
        (tmp = strstr(buffer, "Auth: "))) {
        mark_auth_online();
        if (sscanf(tmp, "Auth: %d", (int *)&authresponse->authcode) == 1) {
            debug(LOG_INFO, "Auth server returned authentication code %d", authresponse->authcode);
            return 1;
        }
    } else
        mark_auth_offline();
    debug(LOG_WARNING, "Auth server did not return expected authentication code");
    return 0;
}

/**
 * @brief Treat client's logout response from auth server
 * 
 * @param req The http request
 * 
 */ 
void 
process_auth_server_logout(struct evhttp_request *req, void *ctx) 
{
    t_authresponse authresponse;
    memset(&authresponse, 0, sizeof(t_authresponse));
    if (parse_auth_server_response(&authresponse, req)) {
        if (authresponse.authcode == 0) {
            // get client from ctx
            t_client *client = (t_client *)((struct wd_request_context *)ctx)->data;
            fw_deny(client);
            debug(LOG_INFO, "Client %s logged out successfully", client->ip);
            safe_client_list_delete(client);  
        }
    } else {
        debug(LOG_ERR, "parse_auth_server_response failed");
    }
    ((struct wd_request_context *)ctx)->data = NULL;
}

/**
 * @brief Reply wifidog's client login response from auth server
 * 
 * @param authresponse Auth server's response to client's request
 * @param req Client's request
 * @param context Wifidog's http request context to auth server
 * 
 */
static void
client_login_request_reply(t_authresponse *authresponse, 
        struct evhttp_request *req, struct wd_request_context *context)
{
    t_client *client = (t_client *)context->data;
    context->data = NULL;
    t_auth_serv *auth_server = get_auth_server();
    char *url_fragment = NULL;

    if (!req) {
        debug(LOG_ERR, "Got NULL request in client_login_request_reply");
        evhttp_send_error(req, 200, "Internal Error, We can not validate your request at this time");
        safe_client_list_delete(client);
        return;
    }

    switch (authresponse->authcode) {
    case AUTH_ERROR:
        /* Error talking to central server */
        debug(LOG_ERR, "Got ERROR from central server authenticating token %s from %s at %s", client->token, client->ip,
              client->mac);
		safe_client_list_delete(client);
        evhttp_send_error(req, 200, "Error: We did not get a valid answer from the central server");
        break;
    case AUTH_DENIED:
        /* Central server said invalid token */
        debug(LOG_INFO,
              "Got DENIED from central server authenticating token %s from %s at %s - deleting from firewall and redirecting them to denied message",
              client->token, client->ip, client->mac);
        fw_deny(client);
		safe_client_list_delete(client);
        safe_asprintf(&url_fragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_DENIED);
        ev_http_send_redirect_to_auth(req, url_fragment, "Redirect to denied message");
        free(url_fragment);
        break;
    case AUTH_VALIDATION:
        fw_allow(client, FW_MARK_PROBATION);
        /* They just got validated for X minutes to check their email */
        debug(LOG_INFO, "Got VALIDATION from central server authenticating token %s from %s at %s"
              "- adding to firewall and redirecting them to activate message", client->token, client->ip, client->mac);
        safe_asprintf(&url_fragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
        ev_http_send_redirect_to_auth(req, url_fragment, "Redirect to activate message");
        free(url_fragment);
        break;
    case AUTH_ALLOWED:
        fw_allow(client, FW_MARK_KNOWN);
        /* Logged in successfully as a regular account */
        debug(LOG_INFO, "Got ALLOWED from central server authenticating token %s from %s at %s - "
              "adding to firewall and redirecting them to portal", client->token, client->ip, client->mac);
    	
		client->first_login = time(NULL);
		client->is_online = 1;
        {
            LOCK_OFFLINE_CLIENT_LIST();
            t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
            if(o_client)
                offline_client_list_delete(o_client);
            UNLOCK_OFFLINE_CLIENT_LIST();
        }
		
        served_this_session++;
		if(ev_http_find_query(req, "type")) {
        	evhttp_send_error(req, 200, "weixin auth success!");
		} else {
        	safe_asprintf(&url_fragment, "%sgw_id=%s&channel_path=%s&mac=%s&name=%s", 
				auth_server->authserv_portal_script_path_fragment, 
				config_get_config()->gw_id,
				g_channel_path?g_channel_path:"null",
				client->mac?client->mac:"null",
				client->name?client->name:"null");
        	ev_http_send_redirect_to_auth(req, url_fragment, "Redirect to portal");
        	free(url_fragment);
		}
        break;
    case AUTH_VALIDATION_FAILED:
        /* Client had X minutes to validate account by email and didn't = too late */
        debug(LOG_INFO, "Got VALIDATION_FAILED from central server authenticating token %s from %s at %s "
              "- redirecting them to failed_validation message", client->token, client->ip, client->mac);
		safe_client_list_delete(client);
        
        safe_asprintf(&url_fragment, "%smessage=%s",
                      auth_server->authserv_msg_script_path_fragment, GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        ev_http_send_redirect_to_auth(req, url_fragment, "Redirect to failed validation message");
        free(url_fragment);
        break;
    default:
        debug(LOG_WARNING,
              "I don't know what the validation code %d means for token %s from %s at %s - sending error message",
              authresponse->authcode, client->token, client->ip, client->mac);
		safe_client_list_delete(client);
        
        evhttp_send_error(req, 200, "Internal Error, We can not validate your request at this time");
        break;
    }
}

/**
 * @brief process wifidog's client login response from auth server
 */ 
void 
process_auth_server_login(struct evhttp_request *req, void *ctx) 
{
    t_authresponse authresponse;
    memset(&authresponse, 0, sizeof(t_authresponse));
    if (parse_auth_server_response(&authresponse, req))
        client_login_request_reply(&authresponse, ((struct wd_request_context *)ctx)->clt_req, ctx);
    else {
        // free client in ctx
        t_client *p1 = (t_client *)((struct wd_request_context *)ctx)->data;
        debug(LOG_ERR, "parse_auth_server_response failed, free client %s", p1->ip);
        safe_client_list_delete(p1);
        evhttp_send_error(((struct wd_request_context *)ctx)->clt_req, 200, 
            "Internal Error, We can not validate your request at this time");
    }
}

/**
 * @brief reply wifidog client's counter response from auth server and free the dup client
 * 
 */
static void
client_counter_request_reply(t_authresponse *authresponse, 
        struct evhttp_request *req, struct wd_request_context *context)
{
    s_config *config = config_get_config();
    t_client *p1 = (t_client *)context->data;
    context->data = NULL;

    time_t current_time = time(NULL);
    debug(LOG_DEBUG,
            "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
            p1->ip, p1->counters.last_updated, current_time - p1->counters.last_updated,
            config->checkinterval * config->clienttimeout, current_time);
    if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
        /* Timing out user */
        debug(LOG_DEBUG, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
                p1->ip, config->checkinterval * config->clienttimeout);
        LOCK_CLIENT_LIST();
        t_client *client = client_list_find_by_client(p1);
        UNLOCK_CLIENT_LIST();
        if (client) {
            ev_logout_client(context, client);
        } else {
            debug(LOG_NOTICE, "Client was already removed. Not logging out.");
        }
    } else {
        /*
            * This handles any change in
            * the status this allows us
            * to change the status of a
            * user while he's connected
            *
            * Only run if we have an auth server
            * configured!
            */
        fw_client_process_from_authserver_response(authresponse, p1);
    }
    client_free_node(p1);
} 

/**
 * @brief process wifidog's client counter response from auth server
 * 
 */
void
process_auth_server_counter(struct evhttp_request *req, void *ctx)
{
    t_authresponse authresponse;
    memset(&authresponse, 0, sizeof(t_authresponse));
    if (parse_auth_server_response(&authresponse, req))
        client_counter_request_reply(&authresponse, req, ctx);
    else {
        // free client in ctx
        t_client *p1 = (t_client *)((struct wd_request_context *)ctx)->data;
        debug(LOG_ERR, "parse_auth_server_response failed, free client %s", p1->ip);
        client_free_node(p1);
        ((struct wd_request_context *)ctx)->data = NULL;
    }
} 

/**
 * @intern
 * @brief read api response from wifidog auth server, need to be free by caller
 *  
 */
static char *
read_api_response(struct evhttp_request *req)
{
    struct evbuffer *in = evhttp_request_get_input_buffer(req);
    size_t len = evbuffer_get_length(in);
    char *res = calloc(1, len+1);
    if (res) {
        memcpy(res, evbuffer_pullup(in, len), len);
    }
    evbuffer_drain(in, len);

    return res;
}

/**
 * @brief reply wifidog client's counter response from auth server and free the dup client
 * 
 */
static void
client_counter_request_reply_v2(t_authresponse *authresponse, 
        struct evhttp_request *req, struct wd_request_context *context)
{
    s_config *config = config_get_config();
    LOCK_CLIENT_LIST();
    t_client *p1 = client_list_find_by_client_id(authresponse->client_id);
    if (!p1) {
        UNLOCK_CLIENT_LIST();
        return;
    }

    time_t current_time = time(NULL);
    debug(LOG_DEBUG,
            "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
            p1->ip, p1->counters.last_updated, current_time - p1->counters.last_updated,
            config->checkinterval * config->clienttimeout, current_time);
    if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
        UNLOCK_CLIENT_LIST();
        /* Timing out user */
        debug(LOG_DEBUG, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
                p1->ip, config->checkinterval * config->clienttimeout);
        ev_logout_client(context, p1);     
    } else {
        UNLOCK_CLIENT_LIST();
        /*
            * This handles any change in
            * the status this allows us
            * to change the status of a
            * user while he's connected
            *
            * Only run if we have an auth server
            * configured!
            */
        fw_client_process_from_authserver_response(authresponse, p1);
    }
} 

/**
 * @brief v2 of process_auth_server_counter
 * 
 * auth response is {gw_id:"gw_id",auth_op:[{"id":clt_id,"auth_code":authcode}, ....]}
 * 
 */ 
void
process_auth_server_counter_v2(struct evhttp_request *req, void *ctx)
{
    if (!req) {
        mark_auth_offline();
        return;
    }
	
    char *buff = read_api_response(req);
    if (!buff) return;

    debug(LOG_DEBUG, "Auth response [%s]", buff);

    json_object *j_result = json_tokener_parse(buff);
    if (!j_result) {
        goto ERR;
    }

    json_object *j_auth_op = json_object_object_get(j_result, "auth_op");
    if (!j_auth_op) {
        goto ERR;
    }
    assert(json_object_get_type(j_auth_op) == json_type_array);

    for(int idx = 0; idx < json_object_array_length(j_auth_op); idx++) {
        json_object *j_op = json_object_array_get_idx(j_auth_op, idx);
        assert(j_op != NULL);
        json_object *j_id = json_object_object_get(j_op, "id");
        json_object *j_auth_code = json_object_object_get(j_op, "auth_code");
        assert(j_id != NULL && j_auth_code != NULL);
        int id = json_object_get_int(j_id);
        int auth_code = json_object_get_int(j_auth_code);
        t_authresponse authresponse;
        authresponse.client_id = id;
        authresponse.authcode = auth_code;
        client_counter_request_reply_v2(&authresponse, req, ctx);
    }
	
	json_object *j_client_timeout = json_object_object_get(j_result, "clientTimeout");
	if (j_client_timeout) {
		int clientTimeout = json_object_get_int(j_client_timeout);
		s_config *config = config_get_config();
		LOCK_CLIENT_LIST();
		config->clienttimeout = clientTimeout;
		UNLOCK_CLIENT_LIST();
	}
    
ERR:
    if (j_result) json_object_put(j_result);
    free(buff);
}
