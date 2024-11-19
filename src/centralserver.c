
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
 * @brief Process authentication server's roaming response
 *
 * Handles JSON response from auth server for roaming requests.
 * Expected JSON format:
 * {
 *   "roam": "yes|no",           // Whether roaming is allowed
 *   "client": {                 // Client info if roaming allowed
 *     "token": "client_token",
 *     "first_login": "timestamp"
 *     ...
 *   }
 * }
 *
 * If roaming is allowed and client info provided, adds client to online list.
 * 
 * @param req HTTP request containing auth server response
 * @param ctx Request context containing roam info that must be freed
 */
static void
process_auth_server_roam(struct evhttp_request *req, void *ctx)
{
    struct roam_req_info *roam = ((struct wd_request_context *)ctx)->data;
    
    // Validate request
    if (!req) {
        mark_auth_offline();
        free(roam);
        return;
    }

    debug(LOG_DEBUG, "Processing auth server roam response");

    // Read response data
    char buffer[MAX_BUF] = {0};
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) > 0) {
        mark_auth_online();
    } else {
        mark_auth_offline();
        free(roam);
        return;
    }

    // Parse JSON response
    json_object *roam_info = json_tokener_parse(buffer);
    if (!roam_info) {
        debug(LOG_ERR, "Failed to parse JSON response: %s", buffer);
        free(roam);
        return;
    }

    // Check roaming status
    json_object *roam_jo = NULL;
    if (!json_object_object_get_ex(roam_info, "roam", &roam_jo)) {
        json_object_put(roam_info);
        free(roam);
        return;
    }
    
    // Process roaming client if allowed
    const char *is_roam = json_object_get_string(roam_jo);
    if (is_roam && strcmp(is_roam, "yes") == 0) {
        json_object *client = NULL;
        if (json_object_object_get_ex(roam_info, "client", &client)) {
            add_online_client(roam->ip, roam->mac, client);
        } else {
            debug(LOG_ERR, "Missing client info in roaming response");
        }
    }

    json_object_put(roam_info);
    free(roam);
}

/**
 * @brief Get roaming request URI for auth server
 *
 * Constructs the URI used for roaming validation requests.
 * The URI includes parameters:
 * - Gateway ID and channel
 * - Client MAC address
 *
 * @param gw_setting Gateway settings containing ID and channel
 * @param auth_server Auth server configuration
 * @param mac Client MAC address to validate
 * @return Dynamically allocated URI string, NULL on error. Caller must free.
 */
static char *
get_roam_request_uri(t_gateway_setting *gw_setting, 
                    t_auth_serv *auth_server, 
                    const char *mac)
{
    char *roam_uri = NULL;
    if (safe_asprintf(&roam_uri,
            "%sroam?gw_id=%s&mac=%s&gw_channel=%s",
            auth_server->authserv_path,
            gw_setting->gw_id,
            mac,
            gw_setting->gw_channel) < 0) {
        return NULL;
    }
    return roam_uri;
}

/**
 * @brief Make roaming validation request to auth server
 *
 * Sends request to validate if client is allowed to roam to this gateway.
 * Request flow:
 * 1. Constructs roaming URI with client MAC and gateway details
 * 2. Creates HTTP connection and request
 * 3. Sends request to auth server
 * 4. Response handled by process_auth_server_roam()
 *
 * @param context Request context for tracking state
 * @param roam Roaming request data, freed after use
 */
void 
make_roam_request(struct wd_request_context *context, struct roam_req_info *roam)
{
    char *uri = get_roam_request_uri(get_gateway_settings(), 
                                   get_auth_server(), 
                                   roam->mac);
    if (!uri) {
        debug(LOG_ERR, "Failed to create roaming request URI");
        free(roam);
        return;
    }

    debug(LOG_DEBUG, "Roaming request URI: [%s]", uri);

    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req = NULL;
    context->data = roam;

    if (!wd_make_request(context, &evcon, &req, process_auth_server_roam)) {
        evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    } else {
        debug(LOG_ERR, "Failed to create HTTP request");
        free(roam);
    }

    free(uri);
}

/**
 * @brief Process authentication server's v2 login response
 *
 * Handles JSON response from auth server for v2 login requests.
 * Expected JSON format:
 * {
 *   "ret_code": 0,            // 0 = success, non-zero = failure
 *   "client": {               // Client authentication details
 *     "token": "...",
 *     "first_login": "...",
 *     ...
 *   }
 * }
 *
 * @param req HTTP request containing auth server response
 * @param ctx Request context containing auth info that must be freed
 */
static void
process_auth_server_login_v2(struct evhttp_request *req, void *ctx)
{
    auth_req_info *auth = ((struct wd_request_context *)ctx)->data;
    debug(LOG_DEBUG, "Processing auth server login v2 response");

    // Read response data
    char buffer[MAX_BUF] = {0};
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) <= 0) {
        debug(LOG_ERR, "Failed to read auth server response");
        free(auth);
        return;
    }

    // Parse JSON response
    json_object *json_resp = json_tokener_parse(buffer);
    if (!json_resp) {
        debug(LOG_ERR, "Failed to parse JSON response");
        free(auth);
        return;
    }

    // Check return code
    json_object *ret_code = NULL;
    if (!json_object_object_get_ex(json_resp, "ret_code", &ret_code)) {
        debug(LOG_ERR, "Missing ret_code in response");
        json_object_put(json_resp);
        free(auth);
        return;
    }

    int retCode = json_object_get_int(ret_code);
    if (retCode != 0) {
        debug(LOG_INFO, "Authentication failed with code: %d", retCode);
        json_object_put(json_resp);
        free(auth);
        return;
    }

    // Process client info if present
    json_object *client = NULL;
    if (json_object_object_get_ex(json_resp, "client", &client)) {
        add_online_client(auth->ip, auth->mac, client);
    } else {
        debug(LOG_ERR, "Missing client info in successful response");
    }

    json_object_put(json_resp);
    free(auth);
}

/**
 * @brief Get login v2 request URI for authenticating clients
 *
 * Constructs the URI used for v2 login requests to the auth server.
 * The URI includes parameters like:
 * - Gateway ID and channel 
 * - Gateway address and port
 * - Client MAC and IP address
 *
 * @param gw_setting Gateway settings containing ID, address etc
 * @param auth_server Auth server configuration 
 * @param auth Authentication request info with client details
 * @return Dynamically allocated string containing complete URI.
 *         Must be freed by caller.
 *         Returns NULL on memory allocation failure.
 */
static char *
get_login_v2_request_uri(t_gateway_setting *gw_setting, 
                        t_auth_serv *auth_server,
                        const auth_req_info *auth)
{
    char *login_uri = NULL;
    if (safe_asprintf(&login_uri,
            "%slogin2?gw_id=%s&gw_address=%s&gw_port=%d"
            "&mac=%s&gw_channel=%s&ip=%s",
            auth_server->authserv_path,
            gw_setting->gw_id,
            gw_setting->gw_address_v4,
            config_get_config()->gw_port,
            auth->mac,
            gw_setting->gw_channel,
            auth->ip) < 0) {
        return NULL;
    }
    return login_uri;
}

/**
 * @brief Make authentication request to auth server
 *
 * Sends a v2 login request to authenticate a client with the auth server.
 * Request flow:
 * 1. Constructs login URI with client and gateway details
 * 2. Creates HTTP connection and request
 * 3. Sends request to auth server
 * 4. Response handled by process_auth_server_login_v2()
 *
 * @param context Request context for tracking state
 * @param auth Authentication request data, freed after use
 */
void 
make_auth_request(struct wd_request_context *context, auth_req_info *auth)
{
    char *uri = get_login_v2_request_uri(get_gateway_settings(), 
                                        get_auth_server(), 
                                        auth);
    if (!uri) {
        debug(LOG_ERR, "Failed to create login v2 URI");
        free(auth);
        return;
    }

    debug(LOG_DEBUG, "Login v2 request URI: [%s]", uri);

    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req = NULL;
    context->data = auth;

    // Create and send HTTP request
    if (!wd_make_request(context, &evcon, &req, process_auth_server_login_v2)) {
        evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    } else {
        debug(LOG_ERR, "Failed to create HTTP request");
        free(auth);
    }

    free(uri);
}

/**
 * @brief Get the URI for v2 counter authentication requests
 * 
 * Constructs the URI used for sending client counter information to the auth server
 * using the v2 protocol. The URI is built from:
 * - Auth server base path
 * - Auth script path fragment
 * - Counter v2 request type
 *
 * @return Dynamically allocated string containing the complete URI.
 *         Must be freed by caller.
 *         Returns NULL on memory allocation failure.
 */
char *
get_auth_counter_v2_uri(void)
{
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;

    // Combine paths and request type into full URI
    if (safe_asprintf(&uri, "%s%sstage=%s",
                      auth_server->authserv_path,
                      auth_server->authserv_auth_script_path_fragment,
                      REQUEST_TYPE_COUNTERS_V2) < 0) {
        debug(LOG_ERR, "Failed to allocate memory for counter v2 URI");
        return NULL;
    }

    debug(LOG_DEBUG, "Counter v2 auth URI: [%s]", uri);
    return uri;
}

/**
 * @brief Builds authentication request URI for a client
 *
 * Constructs the full URI for authentication requests to the auth server based on:
 * - Client type (online or trusted)
 * - Request type (auth, logout, etc)
 * - Client state (traffic counters, login time, etc)
 * 
 * The URI includes parameters like:
 * - IP and MAC address
 * - Auth token 
 * - Traffic statistics
 * - Login time and duration
 * - Gateway ID and channel
 * - Device identifiers
 *
 * @param request_type Type of auth request (e.g. "login", "counter")
 * @param type Type of client (ONLINE_CLIENT or TRUSTED_CLIENT)
 * @param data Client data (t_client* for online clients)
 * @return Dynamically allocated URI string, NULL on error. Caller must free.
 */
char * 
get_auth_uri(const char *request_type, client_type_t type, void *data)
{
    // Client parameters
    char *ip = NULL, *mac = NULL, *name = NULL;
    char *safe_token = NULL;
    const char *gw_id = NULL, *gw_channel = NULL;
    const char *device_id = get_device_id();
    
    // Traffic and timing stats
    unsigned long long int incoming = 0, outgoing = 0;
    unsigned long long int incoming_delta = 0, outgoing_delta = 0;
    time_t first_login = 0;
    uint32_t online_time = 0, wired = 0;

    // Extract client info based on type
    switch(type) {
    case ONLINE_CLIENT: {
        t_client *client = (t_client *)data;
        
        // Basic identifiers
        ip = client->ip;
        mac = client->mac; 
        safe_token = client->token;
        name = client->name;
        
        // Traffic stats
        incoming = client->counters.incoming;
        outgoing = client->counters.outgoing;
        incoming_delta = client->counters.incoming_delta;
        outgoing_delta = client->counters.outgoing_delta;
        
        // Timing and status
        first_login = client->first_login ? client->first_login : time(0);
        online_time = time(0) - first_login;
        wired = client->wired;
        
        // Gateway info
        gw_id = client->gw_setting->gw_id;
        gw_channel = client->gw_setting->gw_channel;
        break;
    }    
    
    case TRUSTED_CLIENT:
    default:
        return NULL;
    }

    // Get config and auth server settings
    s_config *config = config_get_config();
    t_auth_serv *auth_server = get_auth_server();
    char *uri = NULL;

    // Build URI with or without delta traffic stats
    if (config->deltatraffic) {
        if (safe_asprintf(&uri, 
            "%s%sstage=%s&ip=%s&mac=%s&token=%s"
            "&incoming=%llu&outgoing=%llu"
            "&incomingdelta=%llu&outgoingdelta=%llu"
            "&first_login=%lld&online_time=%u"
            "&gw_id=%s&gw_channel=%s"
            "&name=%s&wired=%u&device_id=%s",
            auth_server->authserv_path,
            auth_server->authserv_auth_script_path_fragment,
            request_type, ip, mac,
            safe_token ? safe_token : "null",
            incoming, outgoing,
            incoming_delta, outgoing_delta,
            (long long)first_login, online_time,
            gw_id, gw_channel,
            name ? name : "null",
            wired, device_id) < 0) {
            return NULL;
        }
    } else {
        if (safe_asprintf(&uri,
            "%s%sstage=%s&ip=%s&mac=%s&token=%s"
            "&incoming=%llu&outgoing=%llu"
            "&first_login=%lld&online_time=%u"
            "&gw_id=%s&gw_channel=%s"
            "&name=%s&wired=%u&device_id=%s",
            auth_server->authserv_path,
            auth_server->authserv_auth_script_path_fragment,
            request_type, ip, mac,
            safe_token ? safe_token : "null",
            incoming, outgoing,
            (long long)first_login, online_time, 
            gw_id, gw_channel,
            name ? name : "null",
            wired, device_id) < 0) {
            return NULL;
        }
    }

    return uri;
}

/**
 * @brief Parse authentication response from auth server
 * 
 * This function parses the authentication response received from the auth server.
 * The expected response format is "Auth: <code>" where code is an integer 
 * representing the authentication status.
 *
 * It also maintains the auth server online/offline status based on response.
 *
 * @param authresponse Pointer to store parsed authentication response
 * @param req HTTP request containing auth server response
 * @return 1 if response was successfully parsed, 0 otherwise
 */
static int
parse_auth_server_response(t_authresponse *authresponse, struct evhttp_request *req) 
{
    if (!req) {
        mark_auth_offline();
        return 0;
    }

    char buffer[MAX_BUF] = {0};
    char *auth_marker = NULL;
    
    // Read response into buffer
    if (evbuffer_remove(evhttp_request_get_input_buffer(req), buffer, MAX_BUF-1) <= 0) {
        mark_auth_offline();
        debug(LOG_WARNING, "Failed to read auth server response");
        return 0;
    }

    // Look for "Auth: " marker
    auth_marker = strstr(buffer, "Auth: ");
    if (!auth_marker) {
        mark_auth_offline();
        debug(LOG_WARNING, "Auth server response missing 'Auth: ' marker");
        return 0;
    }

    // Parse auth code
    mark_auth_online();
    if (sscanf(auth_marker, "Auth: %d", (int *)&authresponse->authcode) == 1) {
        debug(LOG_INFO, "Auth server returned authentication code %d", 
              authresponse->authcode);
        return 1;
    }

    debug(LOG_WARNING, "Failed to parse auth code from server response");
    return 0;
}

/**
 * @brief Process client logout response from auth server
 * 
 * This function handles the authentication server's response to a client logout
 * request. If the auth code is 0 (success), it:
 * 1. Denies the client firewall access
 * 2. Logs the successful logout
 * 3. Removes the client from the client list
 *
 * @param req HTTP request containing auth server response
 * @param ctx Request context containing client state
 */
void 
process_auth_server_logout(struct evhttp_request *req, void *ctx) 
{
    struct wd_request_context *context = (struct wd_request_context *)ctx;
    t_client *client = (t_client *)context->data;
    t_authresponse authresponse = {0};

    if (!parse_auth_server_response(&authresponse, req)) {
        debug(LOG_ERR, "Failed to parse auth server logout response");
        goto cleanup;
    }

    if (authresponse.authcode == 0) {
        // Successful logout
        if (client) {
            fw_deny(client);
            debug(LOG_INFO, "Client %s logged out successfully", client->ip);
            safe_client_list_delete(client);
        }
    } else {
        debug(LOG_WARNING, "Auth server returned non-zero code %d for logout",
              authresponse.authcode);
    }

cleanup:
    context->data = NULL; // Clear client pointer from context
}

/**
 * @brief Handle successful client authentication
 *
 * Processes a client that has been successfully authenticated:
 * 1. Updates firewall to allow access
 * 2. Sets client online status and login time
 * 3. Removes from offline client list
 * 4. Redirects client to appropriate destination
 *
 * @param client Authenticated client
 * @param req Original client HTTP request  
 * @param auth_server Auth server configuration
 */
static void 
handle_auth_allowed(t_client *client, struct evhttp_request *req, 
                   t_auth_serv *auth_server)
{
    char *url_fragment = NULL;
    
    debug(LOG_INFO, "Access granted for token %s from %s at %s",
          client->token, client->ip, client->mac);

    // Update client status
    fw_allow(client, FW_MARK_KNOWN);
    client->first_login = time(NULL);
    client->is_online = 1;
    served_this_session++;

    // Remove from offline list if present
    LOCK_OFFLINE_CLIENT_LIST();
    t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
    if(o_client) {
        offline_client_list_delete(o_client);
    }
    UNLOCK_OFFLINE_CLIENT_LIST();

    // Handle WeChat auth or normal portal redirect
    if(ev_http_find_query(req, "type")) {
        evhttp_send_error(req, 200, "WeChat auth success!");
    } else {
        assert(client->gw_setting);
        safe_asprintf(&url_fragment, "%sgw_id=%s&gw_channel=%s&mac=%s&name=%s", 
                     auth_server->authserv_portal_script_path_fragment,
                     client->gw_setting->gw_id,
                     client->gw_setting->gw_channel,
                     client->mac ? client->mac : "null",
                     client->name ? client->name : "null");
        ev_http_send_redirect_to_auth(req, url_fragment, "Redirect to portal");
        free(url_fragment);
    }
}

/**
 * @brief Process and reply to a client's login request based on auth server response
 *
 * This function handles the authentication server's response for a client login
 * and performs the appropriate actions based on the auth code:
 * - AUTH_ERROR: Server communication error
 * - AUTH_DENIED: Invalid credentials 
 * - AUTH_VALIDATION: Temporary access granted for validation
 * - AUTH_ALLOWED: Full access granted
 * - AUTH_VALIDATION_FAILED: Email validation timeout
 *
 * Actions include:
 * 1. Updating firewall rules
 * 2. Managing client state
 * 3. Sending appropriate redirect/response to client
 *
 * @param authresponse Authentication response from server
 * @param req Original client HTTP request
 * @param context Request context containing client state
 */
static void
client_login_request_reply(t_authresponse *authresponse, 
                         struct evhttp_request *req, 
                         struct wd_request_context *context)
{
    t_client *client = (t_client *)context->data;
    context->data = NULL;
    t_auth_serv *auth_server = get_auth_server();
    char *url_fragment = NULL;

    // Validate request
    if (!req) {
        debug(LOG_ERR, "Got NULL request in client_login_request_reply");
        evhttp_send_error(req, 200, "Internal Error: Unable to validate request");
        safe_client_list_delete(client);
        return;
    }

    // Process based on auth code
    switch (authresponse->authcode) {
    case AUTH_ERROR:
        debug(LOG_ERR, "Auth server error for token %s from %s at %s", 
              client->token, client->ip, client->mac);
        safe_client_list_delete(client);
        evhttp_send_error(req, 200, "Error: Invalid response from auth server");
        break;

    case AUTH_DENIED:
        debug(LOG_INFO, "Access denied for token %s from %s at %s", 
              client->token, client->ip, client->mac);
        fw_deny(client);
        safe_client_list_delete(client);
        safe_asprintf(&url_fragment, "%smessage=%s",
                     auth_server->authserv_msg_script_path_fragment, 
                     GATEWAY_MESSAGE_DENIED);
        ev_http_send_redirect_to_auth(req, url_fragment, "Access denied");
        free(url_fragment);
        break;

    case AUTH_VALIDATION:
        debug(LOG_INFO, "Validation access granted for token %s from %s at %s",
              client->token, client->ip, client->mac);
        fw_allow(client, FW_MARK_PROBATION);
        safe_asprintf(&url_fragment, "%smessage=%s",
                     auth_server->authserv_msg_script_path_fragment,
                     GATEWAY_MESSAGE_ACTIVATE_ACCOUNT);
        ev_http_send_redirect_to_auth(req, url_fragment, "Activate account");
        free(url_fragment);
        break;

    case AUTH_ALLOWED:
        handle_auth_allowed(client, req, auth_server);
        break;

    case AUTH_VALIDATION_FAILED:
        debug(LOG_INFO, "Validation failed for token %s from %s at %s",
              client->token, client->ip, client->mac);
        safe_client_list_delete(client);
        safe_asprintf(&url_fragment, "%smessage=%s",
                     auth_server->authserv_msg_script_path_fragment,
                     GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED);
        ev_http_send_redirect_to_auth(req, url_fragment, "Validation failed");
        free(url_fragment);
        break;

    default:
        debug(LOG_WARNING, "Unknown validation code %d for token %s from %s at %s",
              authresponse->authcode, client->token, client->ip, client->mac);
        safe_client_list_delete(client);
        evhttp_send_error(req, 200, "Internal Error: Invalid auth code");
        break;
    }
}

/**
 * @brief Process client login response from auth server
 *
 * This function handles the authentication server's response for a client login request.
 * It performs the following:
 * 1. Parses the auth server response to get authentication code
 * 2. If successful, processes the login response and updates client state 
 * 3. If parsing fails, removes client and sends error response
 *
 * The login response determines whether to:
 * - Allow/deny client access
 * - Redirect client to portal/validation page
 * - Remove client from system
 *
 * @param req HTTP request from auth server containing response
 * @param ctx Request context containing client state and original client request
 */
void 
process_auth_server_login(struct evhttp_request *req, void *ctx) 
{
    t_authresponse authresponse;
    struct wd_request_context *context = (struct wd_request_context *)ctx;
    t_client *client = (t_client *)context->data;

    memset(&authresponse, 0, sizeof(t_authresponse));

    if (parse_auth_server_response(&authresponse, req)) {
        // Successfully parsed - process the login response
        client_login_request_reply(&authresponse, context->clt_req, context);
    } else {
        // Failed to parse - remove client and send error
        debug(LOG_ERR, "Failed to parse auth server response for client %s",
              client ? client->ip : "unknown");

        if (client) {
            safe_client_list_delete(client);
        }

        evhttp_send_error(context->clt_req, 200,
            "Internal Error: Unable to validate your request at this time");
    }
}

/**
 * @brief Process auth server's counter response for a client and manage client timeout
 * 
 * This function handles the counter response from the auth server for a specific client.
 * It performs the following:
 * 1. Checks if client has timed out based on last activity
 * 2. If timed out, removes client and denies firewall access
 * 3. If not timed out, processes any status changes from auth server
 * 4. Frees the duplicate client data
 *
 * @param authresponse Authentication response from server
 * @param req HTTP request containing response 
 * @param context Request context containing client state
 */
static void
client_counter_request_reply(t_authresponse *authresponse,
                           struct evhttp_request *req, 
                           struct wd_request_context *context)
{
    s_config *config = config_get_config();
    t_client *client = (t_client *)context->data;
    context->data = NULL;

    // Calculate timeout values
    time_t current_time = time(NULL);
    time_t idle_time = current_time - client->counters.last_updated;
    time_t timeout = config->checkinterval * config->clienttimeout;

    debug(LOG_DEBUG,
          "Client %s timeout check: Last updated=%ld, Idle time=%ld, Timeout=%ld, Current time=%ld",
          client->ip, client->counters.last_updated, idle_time, timeout, current_time);

    if (idle_time >= timeout) {
        // Client has timed out - remove them
        debug(LOG_DEBUG, "Client %s timed out after %ld seconds of inactivity",
              client->ip, idle_time);

        LOCK_CLIENT_LIST();
        t_client *active_client = client_list_find_by_client(client);
        UNLOCK_CLIENT_LIST();

        if (active_client) {
            ev_logout_client(context, active_client);
        } else {
            debug(LOG_NOTICE, "Client was already removed. Not logging out.");
        }
    } else {
        // Client still active - process any status changes
        fw_client_process_from_authserver_response(authresponse, client);
    }

    // Free the duplicate client data
    client_free_node(client);
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
