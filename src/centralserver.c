
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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
get_roam_request_uri(t_gateway_setting *gw_setting, t_auth_serv *auth_server, const char *mac)
{
    char *roam_uri = NULL;
    safe_asprintf(&roam_uri, "%sroam?gw_id=%s&mac=%s&gw_channel=%s", 
        auth_server->authserv_path,
        gw_setting->gw_id,
		mac,
		gw_setting->gw_channel);
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
    // TODO:  find valid gateway setting
    char *uri = get_roam_request_uri(get_gateway_settings(), get_auth_server(), roam->mac);
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
get_login_v2_request_uri(t_gateway_setting *gw_setting, t_auth_serv *auth_server, const auth_req_info *auth)
{
    char *login2_uri = NULL;
    safe_asprintf(&login2_uri, "%slogin2?gw_id=%s&gw_address=%s&gw_port=%d&mac=%s&gw_channel=%s&ip=%s", 
        auth_server->authserv_path,
        gw_setting->gw_id,
		gw_setting->gw_address_v4,
		config_get_config()->gw_port,
		auth->mac,
		gw_setting->gw_channel,
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
    // TODO:  find valid gateway setting
	char *uri = get_login_v2_request_uri(get_gateway_settings(), get_auth_server(), auth);
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
    const char *gw_id = NULL;
    const char *gw_channel = NULL;
    const char *device_id = get_device_id();

    switch(type) {
    case ONLINE_CLIENT:
    {
        t_client *o_client = (t_client *)data;
        ip  = o_client->ip;
        mac = o_client->mac;
        safe_token = o_client->token;
        if (o_client->name)
            name = o_client->name;
        if (!o_client->first_login)
            first_login = time(0);
        else
            first_login = o_client->first_login;
        incoming = o_client->counters.incoming;
        outgoing = o_client->counters.outgoing;
        incoming_delta  = o_client->counters.incoming_delta;
        outgoing_delta  = o_client->counters.outgoing_delta;
        wired = o_client->wired;
        online_time = time(0) - first_login;
        gw_id = o_client->gw_setting->gw_id;
        gw_channel = o_client->gw_setting->gw_channel;
        break;
    }    
    case TRUSTED_CLIENT:
    default:
        return NULL;
    }

    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;
    int nret = 0;
    if (config->deltatraffic) {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&incomingdelta=%llu&outgoingdelta=%llu&first_login=%lld&online_time=%u&gw_id=%s&gw_channel=%s&name=%s&wired=%u&device_id=%s",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, 
             mac, 
             safe_token?safe_token:"null", 
             incoming, 
             outgoing, 
             incoming_delta, 
             outgoing_delta,
             (long long)first_login,
             online_time,
             gw_id,
             gw_channel, 
             name?name:"null", 
             wired,
             device_id);
    } else {
        nret = safe_asprintf(&uri, 
             "%s%sstage=%s&ip=%s&mac=%s&token=%s&incoming=%llu&outgoing=%llu&first_login=%lld&online_time=%u&gw_id=%s&gw_channel=%s&name=%s&wired=%u&device_id=%s",
             auth_server->authserv_path,
             auth_server->authserv_auth_script_path_fragment,
             request_type,
             ip, 
             mac, 
             safe_token?safe_token:"null", 
             incoming, 
             outgoing, 
             (long long)first_login,
             online_time,
             gw_id,
             gw_channel, 
             name?name:"null", 
             wired,
             device_id);
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
            assert(client->gw_setting);
        	safe_asprintf(&url_fragment, "%sgw_id=%s&gw_channel=%s&mac=%s&name=%s", 
				auth_server->authserv_portal_script_path_fragment, 
				client->gw_setting->gw_id,
				client->gw_setting->gw_channel,
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
 * @brief Process client counter response from auth server
 * 
 * This function processes the authentication server's response for client counters.
 * It performs the following:
 * 1. Parses auth server response to get authentication code
 * 2. If successful, processes the counter response for the client
 * 3. If parsing fails, frees the client data
 *
 * The counter response is used to:
 * - Track client activity and timeout status
 * - Process any auth status changes from server
 * - Clean up client data if needed
 *
 * @param req HTTP request from auth server containing response
 * @param ctx Request context containing client state
 */
void
process_auth_server_counter(struct evhttp_request *req, void *ctx)
{
    t_authresponse authresponse;
    memset(&authresponse, 0, sizeof(t_authresponse));

    // Parse the auth server's response
    if (parse_auth_server_response(&authresponse, req)) {
        // Successfully parsed - process the counter response
        client_counter_request_reply(&authresponse, req, ctx);
    } else {
        // Failed to parse - clean up client data
        t_client *client = (t_client *)((struct wd_request_context *)ctx)->data;
        debug(LOG_ERR, "Failed to parse auth server response for client %s", 
              client ? client->ip : "unknown");
        
        if (client) {
            client_free_node(client);
        }
        ((struct wd_request_context *)ctx)->data = NULL;
    }
}

/**
 * @brief Read and return the HTTP response body from an auth server request
 *
 * This function reads the complete response body from the auth server HTTP request
 * and returns it as a null-terminated string. The response data needs to be freed
 * by the caller.
 *
 * @param req The HTTP request containing the response buffer
 * @return Dynamically allocated string containing response body, or NULL on error. 
 *         Caller must free the returned string.
 */
static char *
read_api_response(struct evhttp_request *req)
{
    if (!req) {
        return NULL;
    }

    // Get the input buffer containing response data
    struct evbuffer *input_buf = evhttp_request_get_input_buffer(req);
    if (!input_buf) {
        return NULL;
    }

    // Get response length and allocate buffer 
    size_t response_len = evbuffer_get_length(input_buf);
    char *response_data = calloc(1, response_len + 1); // +1 for null terminator
    if (!response_data) {
        debug(LOG_ERR, "Failed to allocate memory for API response");
        return NULL;
    }

    // Copy response data and drain the buffer
    if (evbuffer_copyout(input_buf, response_data, response_len) < 0) {
        debug(LOG_ERR, "Failed to copy API response data");
        free(response_data);
        return NULL;
    }
    evbuffer_drain(input_buf, response_len);

    return response_data;
}

/**
 * @brief Process counter response for a single client from auth server
 * 
 * This function handles the counter response for an individual client,
 * checking if they have timed out and processing their auth server response.
 * It performs the following:
 * 1. Finds client by ID from the client list
 * 2. Checks if client has timed out based on last activity
 * 3. Either logs out timed out clients or processes their auth status change
 *
 * @param authresponse Authentication response containing client ID and auth code
 * @param req HTTP request from auth server
 * @param context Request context containing client state
 */
static void
client_counter_request_reply_v2(t_authresponse *authresponse, 
    struct evhttp_request *req, struct wd_request_context *context)
{
    s_config *config = config_get_config();

    // Find client by ID with lock protection
    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_client_id(authresponse->client_id);
    if (!client) {
        UNLOCK_CLIENT_LIST();
        return;
    }

    // Check client timeout
    time_t current_time = time(NULL);
    time_t idle_time = current_time - client->counters.last_updated;
    time_t timeout = config->checkinterval * config->clienttimeout;

    debug(LOG_DEBUG,
      "Client %s timeout check: Last updated=%ld, Idle time=%ld, Timeout=%ld, Current time=%ld",
      client->ip, client->counters.last_updated, idle_time, timeout, current_time);

    if (idle_time >= timeout) {
        UNLOCK_CLIENT_LIST(); 
        debug(LOG_DEBUG, "Client %s timed out after %ld seconds of inactivity",
            client->ip, idle_time);
        ev_logout_client(context, client);
    } else {
        UNLOCK_CLIENT_LIST();
        // Process any status changes from auth server
        fw_client_process_from_authserver_response(authresponse, client);
    }
}

/**
 * @brief Process a single auth operation JSON object from the auth server
 *
 * Handles a JSON object containing gateway ID and array of auth operations:
 * {
 *   "gw_id": "gateway_id",
 *   "auth_op": [
 *     {
 *       "id": client_id,
 *       "auth_code": auth_code 
 *     }
 *   ]
 * }
 *
 * @param j_result JSON object containing gateway ID and auth operations
 * @param req HTTP request from auth server
 * @param ctx Request context
 */
static void
handle_json_object_from_auth_server(json_object *j_result, struct evhttp_request *req, void *ctx) 
{
    // Extract gateway ID and auth operations array
    json_object *j_gw_id = json_object_object_get(j_result, "gw_id");
    json_object *j_auth_op = json_object_object_get(j_result, "auth_op");
    
    // Validate required fields exist and auth_op is an array
    if (!j_gw_id || !j_auth_op || json_object_get_type(j_auth_op) != json_type_array) {
        debug(LOG_ERR, "Invalid JSON object format from auth server");
        return;
    }

    // Process each auth operation
    int auth_op_count = json_object_array_length(j_auth_op);
    for (int idx = 0; idx < auth_op_count; idx++) {
        json_object *j_op = json_object_array_get_idx(j_auth_op, idx);
        if (!j_op) continue;

        // Extract client ID and auth code
        json_object *j_id = json_object_object_get(j_op, "id");
        json_object *j_auth_code = json_object_object_get(j_op, "auth_code");
        if (!j_id || !j_auth_code) continue;

        // Create auth response and process it
        t_authresponse authresponse = {
            .client_id = json_object_get_int(j_id),
            .authcode = json_object_get_int(j_auth_code)
        };
        client_counter_request_reply_v2(&authresponse, req, ctx);
    }
}

/**
 * @brief Process array of auth operation results from auth server
 *
 * Handles an array of auth operation JSON objects returned from the server
 *
 * @param j_result JSON array of auth operation results
 * @param req HTTP request from auth server  
 * @param ctx Request context
 */
static void
handle_json_array_from_auth_server(json_object *j_result, struct evhttp_request *req, void *ctx)
{
    if (json_object_get_type(j_result) != json_type_array) {
        debug(LOG_ERR, "Expected JSON array from auth server");
        return;
    }

    // Process each result object in the array
    int result_count = json_object_array_length(j_result);
    for (int idx = 0; idx < result_count; idx++) {
        json_object *j_op = json_object_array_get_idx(j_result, idx);
        if (j_op) {
            handle_json_object_from_auth_server(j_op, req, ctx);
        }
    }
}

/**
 * @brief Process auth server's counter response (version 2)
 * 
 * Processes the authentication server's counter response in JSON format.
 * The expected JSON response format is:
 * {
 *   "result": [
 *     {
 *       "gw_id": "gateway_id",
 *       "auth_op": [
 *         {
 *           "id": client_id,
 *           "auth_code": auth_code
 *         },
 *         ...
 *       ]
 *     },
 *     ...
 *   ]
 * }
 * 
 * @param req The HTTP request from auth server
 * @param ctx The request context
 */ 
void
process_auth_server_counter_v2(struct evhttp_request *req, void *ctx)
{
    if (!req) {
        mark_auth_offline();
        return;
    }

    // Read the response data
    char *response_data = read_api_response(req);
    if (!response_data) {
        debug(LOG_ERR, "Failed to read API response");
        return;
    }

    debug(LOG_DEBUG, "Auth response [%s]", response_data);

    // Parse JSON response
    json_object *json_response = json_tokener_parse(response_data);
    if (!json_response) {
        debug(LOG_ERR, "Failed to parse JSON response");
        free(response_data);
        return;
    }

    // Get result array from response
    json_object *result_array = NULL;
    if (!json_object_object_get_ex(json_response, "result", &result_array)) {
        debug(LOG_ERR, "No 'result' field in JSON response");
        json_object_put(json_response);
        free(response_data);
        return;
    }

    // Process the result array
    handle_json_array_from_auth_server(result_array, req, ctx);

    // Cleanup
    json_object_put(json_response);
    free(response_data);
}
