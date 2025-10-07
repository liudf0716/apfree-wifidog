// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "api_handlers.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "client_list.h"
#include "gateway.h"
#include "fw_iptables.h"
#include "fw_nft.h"
#include "wd_util.h"
#include "safe.h"
#include "wdctlx_thread.h"
#include "ping_thread.h"

// Forward declaration of ws_send function (will be implemented in ws_thread.c)
extern void ws_send(struct evbuffer *buf, const char *msg, const size_t len, int frame_type);

// WebSocket frame types
#define TEXT_FRAME 0x1

/**
 * @brief WebSocket-specific send response implementation
 * 
 * @param ctx Transport context (should be struct bufferevent*)
 * @param message Message to send
 * @param length Length of message
 * @return 0 on success, -1 on error
 */
static int websocket_send_response(void *ctx, const char *message, size_t length) {
    struct bufferevent *bev = (struct bufferevent *)ctx;
    if (!bev || !message) {
        return -1;
    }
    
    ws_send(bufferevent_get_output(bev), message, length, TEXT_FRAME);
    return 0;
}

/**
 * @brief Create a WebSocket transport context
 * 
 * @param bev The bufferevent for WebSocket connection
 * @return Allocated transport context, or NULL on error
 */
api_transport_context_t* create_websocket_transport_context(struct bufferevent *bev) {
    if (!bev) {
        return NULL;
    }
    
    api_transport_context_t *transport = malloc(sizeof(api_transport_context_t));
    if (!transport) {
        return NULL;
    }
    
    transport->transport_ctx = bev;
    transport->send_response = websocket_send_response;
    transport->protocol_name = "websocket";
    
    return transport;
}

/**
 * @brief Destroy transport context
 * 
 * @param transport Transport context to destroy
 */
void destroy_transport_context(api_transport_context_t *transport) {
    if (transport) {
        // Note: We don't free transport_ctx as it's managed by the caller
        free(transport);
    }
}

/**
 * @brief Send a response using the transport abstraction
 * 
 * @param transport Transport context
 * @param message Message to send
 * @return 0 on success, -1 on error
 */
static int send_response(api_transport_context_t *transport, const char *message) {
    if (!transport || !transport->send_response || !message) {
        debug(LOG_ERR, "Invalid transport context or message");
        return -1;
    }
    
    debug(LOG_DEBUG, "Sending response via %s: %.100s%s", 
          transport->protocol_name ? transport->protocol_name : "unknown",
          message, strlen(message) > 100 ? "..." : "");
    
    return transport->send_response(transport->transport_ctx, message, strlen(message));
}

/**
 * @brief Safe UCI configuration setter with input validation
 * 
 * @param config_path UCI configuration path
 * @param value Value to set
 * @return 0 on success, -1 on error
 */
static int set_uci_config(const char *config_path, const char *value) {
    if (!config_path || !value) {
        debug(LOG_ERR, "Invalid parameters for UCI config");
        return -1;
    }
    
    // Validate config_path format (should contain only alphanumeric, dots, underscores)
    for (const char *p = config_path; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '_') {
            debug(LOG_ERR, "Invalid character in config path: %s", config_path);
            return -1;
        }
    }
    
    // Escape single quotes in value to prevent injection
    size_t escaped_len = strlen(value) * 2 + 1;
    char *escaped_value = malloc(escaped_len);
    if (!escaped_value) {
        debug(LOG_ERR, "Memory allocation failed for escaped value");
        return -1;
    }
    
    char *dst = escaped_value;
    for (const char *src = value; *src; src++) {
        if (*src == '\'') {
            *dst++ = '\'';
            *dst++ = '\\';
            *dst++ = '\'';
            *dst++ = '\'';
        } else {
            *dst++ = *src;
        }
    }
    *dst = '\0';
    
    char cmd[1024];
    int ret = snprintf(cmd, sizeof(cmd), "uci set %s='%s'", config_path, escaped_value);
    free(escaped_value);
    
    if (ret >= sizeof(cmd)) {
        debug(LOG_ERR, "UCI command too long");
        return -1;
    }
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        debug(LOG_ERR, "Failed to execute UCI command: %s", cmd);
        return -1;
    }
    
    int result = pclose(fp);
    if (result != 0) {
        debug(LOG_ERR, "UCI command failed with code %d: %s", result, cmd);
        return -1;
    }
    
    return 0;
}

/**
 * @brief Helper function to commit UCI changes
 */
static int commit_uci_changes(void) {
    FILE *fp = popen("uci commit wireless", "r");
    if (!fp) {
        debug(LOG_ERR, "Failed to commit UCI changes");
        return -1;
    }
    
    int result = pclose(fp);
    if (result != 0) {
        debug(LOG_ERR, "UCI commit failed with code %d", result);
        return -1;
    }
    
    return 0;
}

void handle_heartbeat_request(json_object *j_heartbeat)
{
	// Mark auth server as online when receiving heartbeat response
	mark_auth_online();
	
	// Extract gateway array from response
	json_object *gw_array = json_object_object_get(j_heartbeat, "gateway");
	if (!gw_array || !json_object_is_type(gw_array, json_type_array)) {
		debug(LOG_ERR, "Heartbeat: Invalid or missing gateway array");
		return;
	}

	// Track if any gateway states changed
	bool state_changed = false;
	
	// Process each gateway in the array
	int gw_count = json_object_array_length(gw_array);
	for (int i = 0; i < gw_count; i++) {
		json_object *gw = json_object_array_get_idx(gw_array, i);
		json_object *gw_id = json_object_object_get(gw, "gw_id");
		json_object *auth_mode = json_object_object_get(gw, "auth_mode");

		// Validate required fields exist
		if (!gw_id || !auth_mode) {
			debug(LOG_ERR, "Heartbeat: Missing required gateway fields");
			continue;
		}

		// Get gateway values
		const char *gw_id_str = json_object_get_string(gw_id);
		int new_auth_mode = json_object_get_int(auth_mode);

		// Find matching local gateway
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (!gw_setting) {
			debug(LOG_ERR, "Heartbeat: Gateway %s not found", gw_id_str);
			continue;
		}

		// Update auth mode if changed
		if (gw_setting->auth_mode != new_auth_mode) {
			debug(LOG_DEBUG, "Heartbeat: Gateway %s auth mode changed to %d", 
				  gw_id_str, new_auth_mode);
			gw_setting->auth_mode = new_auth_mode;
			state_changed = true;
		}
	}

	// Reload firewall if any states changed
	if (state_changed) {
		debug(LOG_DEBUG, "Gateway states changed, reloading firewall rules");
#ifdef AW_FW4
		nft_reload_gw();
#endif
	}
}

void handle_tmp_pass_request(json_object *j_tmp_pass)
{
	// Check if portal auth is disabled
	if (is_portal_auth_disabled()) {
		debug(LOG_WARNING, "Portal authentication is disabled, ignoring tmp_pass request from server");
		return;
	}
	
	// Extract required client MAC
	json_object *client_mac = json_object_object_get(j_tmp_pass, "client_mac");
	if (!client_mac) {
		debug(LOG_ERR, "Temporary pass: Missing client MAC address");
		return;
	}
	const char *client_mac_str = json_object_get_string(client_mac);

	// Get optional timeout value, default 5 minutes
	uint32_t timeout_value = 5 * 60;
	json_object *timeout = json_object_object_get(j_tmp_pass, "timeout");
	if (timeout) {
		timeout_value = json_object_get_int(timeout);
	}

	// Set temporary firewall access
	fw_set_mac_temporary(client_mac_str, timeout_value);
	debug(LOG_DEBUG, "Set temporary access for MAC %s with timeout %u seconds", 
		  client_mac_str, timeout_value);
}

/**
 * @brief Handles a request to get authenticated client information by MAC address.
 *
 * This function processes a WebSocket request to retrieve detailed information
 * about a specific authenticated client using their MAC address.
 *
 * @param j_req The JSON request object containing the MAC address
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_get_client_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_mac;
    
    debug(LOG_INFO, "Get client info request received");
    
    // Extract MAC address from request
    if (!json_object_object_get_ex(j_req, "mac", &j_mac)) {
        debug(LOG_ERR, "Missing 'mac' field in get_client_info request");
        
        json_object *j_type = json_object_new_string("get_client_info_error");
        json_object *j_error = json_object_new_string("Missing 'mac' field in request");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    const char *mac_str = json_object_get_string(j_mac);
    if (!mac_str || strlen(mac_str) == 0) {
        debug(LOG_ERR, "Invalid MAC address in get_client_info request");
        
        json_object *j_type = json_object_new_string("get_client_info_error");
        json_object *j_error = json_object_new_string("Invalid MAC address");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Update client counters before retrieving information
    debug(LOG_DEBUG, "Updating client counters before retrieving info for MAC: %s", mac_str);
    if (fw_counters_update() == -1) {
        debug(LOG_WARNING, "Failed to update client counters, proceeding with cached data");
    }
    
    // Search for client by MAC address
    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_mac(mac_str);
    
    if (!client) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_INFO, "Client with MAC %s not found", mac_str);
        
        json_object *j_type = json_object_new_string("get_client_info_error");
        json_object *j_error = json_object_new_string("Client not found");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Create response data object
    json_object *j_data = json_object_new_object();
    
    // Add client basic information
    json_object_object_add(j_data, "id", json_object_new_int64(client->id));
    
    if (client->ip) {
        json_object_object_add(j_data, "ip", json_object_new_string(client->ip));
    }
    
    if (client->ip6) {
        json_object_object_add(j_data, "ip6", json_object_new_string(client->ip6));
    }
    
    if (client->mac) {
        json_object_object_add(j_data, "mac", json_object_new_string(client->mac));
    }
    
    if (client->token) {
        json_object_object_add(j_data, "token", json_object_new_string(client->token));
    }
    
    json_object_object_add(j_data, "fw_connection_state", json_object_new_int(client->fw_connection_state));
    
    if (client->name) {
        json_object_object_add(j_data, "name", json_object_new_string(client->name));
    }
    
    json_object_object_add(j_data, "is_online", json_object_new_int(client->is_online));
    json_object_object_add(j_data, "wired", json_object_new_int(client->wired));
    json_object_object_add(j_data, "first_login", json_object_new_int64(client->first_login));
    
    // Add IPv4 counters
    json_object *j_counters = json_object_new_object();
    json_object_object_add(j_counters, "incoming_bytes", json_object_new_int64(client->counters.incoming_bytes));
    json_object_object_add(j_counters, "incoming_packets", json_object_new_int64(client->counters.incoming_packets));
    json_object_object_add(j_counters, "outgoing_bytes", json_object_new_int64(client->counters.outgoing_bytes));
    json_object_object_add(j_counters, "outgoing_packets", json_object_new_int64(client->counters.outgoing_packets));
    json_object_object_add(j_counters, "incoming_rate", json_object_new_int(client->counters.incoming_rate));
    json_object_object_add(j_counters, "outgoing_rate", json_object_new_int(client->counters.outgoing_rate));
    json_object_object_add(j_counters, "last_updated", json_object_new_int64(client->counters.last_updated));
    json_object_object_add(j_data, "counters", j_counters);
    
    // Add IPv6 counters
    json_object *j_counters6 = json_object_new_object();
    json_object_object_add(j_counters6, "incoming_bytes", json_object_new_int64(client->counters6.incoming_bytes));
    json_object_object_add(j_counters6, "incoming_packets", json_object_new_int64(client->counters6.incoming_packets));
    json_object_object_add(j_counters6, "outgoing_bytes", json_object_new_int64(client->counters6.outgoing_bytes));
    json_object_object_add(j_counters6, "outgoing_packets", json_object_new_int64(client->counters6.outgoing_packets));
    json_object_object_add(j_counters6, "incoming_rate", json_object_new_int(client->counters6.incoming_rate));
    json_object_object_add(j_counters6, "outgoing_rate", json_object_new_int(client->counters6.outgoing_rate));
    json_object_object_add(j_counters6, "last_updated", json_object_new_int64(client->counters6.last_updated));
    json_object_object_add(j_data, "counters6", j_counters6);
    
    UNLOCK_CLIENT_LIST();
    
    // Build success response
    json_object *j_type = json_object_new_string("get_client_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);
    
    // Send response
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending client info response: %s", response_str);
    send_response(transport, response_str);
    
    // Cleanup
    json_object_put(j_response);
    
    debug(LOG_INFO, "Client info for MAC %s sent successfully", mac_str);
}

/**
 * @brief Handle client kickoff request from WebSocket server
 *
 * Processes client disconnection requests with validation of device ID,
 * gateway ID, and client existence before removing the client.
 *
 * @param j_auth The JSON request object containing client and device information
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_kickoff_request(json_object *j_auth, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring kickoff request from server");
        
        // Send error response
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Portal authentication is disabled"));
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Extract and validate required fields
    json_object *client_ip = json_object_object_get(j_auth, "client_ip");
    json_object *client_mac = json_object_object_get(j_auth, "client_mac");
    json_object *device_id = json_object_object_get(j_auth, "device_id");
    json_object *gw_id = json_object_object_get(j_auth, "gw_id");

    if (!client_ip || !client_mac || !device_id || !gw_id) {
        debug(LOG_ERR, "Kickoff: Missing required fields in request");
        
        // Send error response
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required fields in request"));
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Get field values
    const char *client_ip_str = json_object_get_string(client_ip);
    const char *client_mac_str = json_object_get_string(client_mac);
    const char *device_id_str = json_object_get_string(device_id);
    const char *gw_id_str = json_object_get_string(gw_id);

    // Find target client
    t_client *client = client_list_find(client_ip_str, client_mac_str);
    if (!client) {
        debug(LOG_ERR, "Kickoff: Client %s (%s) not found", 
              client_mac_str, client_ip_str);
        
        // Send error response with client info
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Client not found"));
        json_object_object_add(j_response, "client_ip", json_object_new_string(client_ip_str));
        json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Validate device ID matches
    const char *local_device_id = get_device_id();
    if (!local_device_id || strcmp(local_device_id, device_id_str) != 0) {
        debug(LOG_ERR, "Kickoff: Device ID mismatch - expected %s", device_id_str);
        
        // Send error response
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Device ID mismatch"));
        json_object_object_add(j_response, "expected_device_id", json_object_new_string(device_id_str));
        json_object_object_add(j_response, "actual_device_id", json_object_new_string(local_device_id ? local_device_id : "null"));
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Validate gateway ID matches
    if (!client->gw_setting || strcmp(client->gw_setting->gw_id, gw_id_str) != 0) {
        debug(LOG_ERR, "Kickoff: Gateway mismatch for client %s - expected %s",
              client_mac_str, gw_id_str);
        
        // Send error response
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Gateway ID mismatch"));
        json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
        json_object_object_add(j_response, "expected_gw_id", json_object_new_string(gw_id_str));
        json_object_object_add(j_response, "actual_gw_id", json_object_new_string(client->gw_setting ? client->gw_setting->gw_id : "null"));
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Remove client
    LOCK_CLIENT_LIST();
    fw_deny(client);
    client_list_remove(client);
    client_free_node(client);
    UNLOCK_CLIENT_LIST();

    debug(LOG_DEBUG, "Kicked off client %s (%s)", client_mac_str, client_ip_str);
    
    // Send success response
    json_object_object_add(j_response, "type", json_object_new_string("kickoff_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "client_ip", json_object_new_string(client_ip_str));
    json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
    json_object_object_add(j_response, "message", json_object_new_string("Client kicked off successfully"));
    
    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
}

/**
 * @brief Handle authentication request from WebSocket server
 *
 * Processes client authentication requests, adding clients to the allowed list
 * or enabling once-auth mode based on the request parameters.
 *
 * @param j_auth The JSON authentication request object
 */
void handle_auth_request(json_object *j_auth) {
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring auth request from server");
        return;
    }
    
    // Extract required fields
    json_object *token = json_object_object_get(j_auth, "token");
    json_object *client_ip = json_object_object_get(j_auth, "client_ip");
    json_object *client_mac = json_object_object_get(j_auth, "client_mac");
    json_object *gw_id = json_object_object_get(j_auth, "gw_id");
    json_object *once_auth = json_object_object_get(j_auth, "once_auth");
    json_object *client_name = json_object_object_get(j_auth, "client_name");

    // Validate required fields
    if (!token || !client_ip || !client_mac || !gw_id || !once_auth) {
        debug(LOG_ERR, "Auth: Missing required fields in JSON response");
        return;
    }

    const char *gw_id_str = json_object_get_string(gw_id);
    t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
    if (!gw_setting) {
        debug(LOG_ERR, "Auth: Gateway %s not found", gw_id_str);
        return;
    }

    // Handle once-auth mode
    if (json_object_get_boolean(once_auth)) {
        gw_setting->auth_mode = 0;
        debug(LOG_DEBUG, "Auth: Once-auth enabled, setting gateway %s auth mode to 0", gw_id_str);
#ifdef AW_FW4
        nft_reload_gw();
#endif
        return;
    }

    // Handle regular authentication
    const char *client_ip_str = json_object_get_string(client_ip);
    const char *client_mac_str = json_object_get_string(client_mac);
    const char *token_str = json_object_get_string(token);

    // Skip if client already exists
    if (client_list_find(client_ip_str, client_mac_str)) {
        debug(LOG_DEBUG, "Auth: Client %s (%s) already authenticated", 
              client_mac_str, client_ip_str);
        return;
    }

    // Add new client with firewall rules
    LOCK_CLIENT_LIST();
    t_client *client = client_list_add(client_ip_str, client_mac_str, token_str, gw_setting);
    fw_allow(client, FW_MARK_KNOWN);

    // Set optional client name if provided
    if (client_name) {
        const char *name_str = json_object_get_string(client_name);
        if (name_str && strlen(name_str) > 0) {
            // Validate client name length and characters
            if (strlen(name_str) <= 64) {
                if (client->name) {
                    free(client->name);
                }
                client->name = strdup(name_str);
            } else {
                debug(LOG_WARNING, "Client name too long, truncating");
                if (client->name) {
                    free(client->name);
                }
                client->name = strndup(name_str, 64);
            }
        }
    }

    client->first_login = time(NULL);
    client->is_online = 1;
    UNLOCK_CLIENT_LIST();

    // Remove from offline list if present
    LOCK_OFFLINE_CLIENT_LIST();
    t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);
    if (o_client) {
        offline_client_list_delete(o_client);
    }
    UNLOCK_OFFLINE_CLIENT_LIST();

    debug(LOG_DEBUG, "Auth: Added client %s (%s) with token %s",
          client_mac_str, client_ip_str, token_str);
}

/**
 * @brief Handles a request for firmware information.
 *
 * This function is called when a "get_firmware_info" message is received.
 * It reads firmware information from /etc/openwrt_release and sends it back
 * as a JSON response.
 *
 * @param j_req The JSON request object (unused for this request type)
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_get_firmware_info_request(json_object *j_req, api_transport_context_t *transport) {
    FILE *fp;
    char buffer[256];
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    debug(LOG_INFO, "Get firmware info request received");

    // Execute command to get firmware information
    fp = popen("cat /etc/openwrt_release 2>/dev/null", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute firmware info command");
        
        // Send error response
        json_object *j_type = json_object_new_string("firmware_info_error");
        json_object *j_error = json_object_new_string("Failed to execute command");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Parse the output and build JSON response
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Remove newline character
        buffer[strcspn(buffer, "\n")] = 0;

        // Parse key=value pairs
        char *key = strtok(buffer, "=");
        char *value = strtok(NULL, "=");

        if (key && value) {
            // Remove quotes from value if present
            if (value[0] == '\'' && value[strlen(value)-1] == '\'') {
                value[strlen(value)-1] = 0;
                value++;
            }
            // Validate key contains only safe characters
            bool valid_key = true;
            for (char *p = key; *p; p++) {
                if (!isalnum(*p) && *p != '_') {
                    valid_key = false;
                    break;
                }
            }
            if (valid_key) {
                json_object_object_add(j_data, key, json_object_new_string(value));
            }
        }
    }

    pclose(fp);

    // Build success response
    json_object *j_type = json_object_new_string("firmware_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);

    // Send response
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending firmware info response: %s", response_str);
    send_response(transport, response_str);

    // Cleanup
    json_object_put(j_response);

    debug(LOG_INFO, "Firmware info sent successfully");
}

/**
 * @brief Handles a request for firmware upgrade.
 *
 * This function is called when a "firmware_upgrade" message is received.
 * It executes the sysupgrade command with the provided firmware URL.
 *
 * @param j_req The JSON request object containing the firmware URL
 * @param transport The transport context for sending responses
 */
void handle_firmware_upgrade_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_url, *j_force;
    
    debug(LOG_INFO, "Firmware upgrade request received");
    
    // Extract URL from request
    if (!json_object_object_get_ex(j_req, "url", &j_url)) {
        debug(LOG_ERR, "Missing 'url' field in firmware upgrade request");
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Missing or invalid 'url' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    const char *url_str = json_object_get_string(j_url);
    if (!url_str || strlen(url_str) == 0) {
        debug(LOG_ERR, "Invalid URL in firmware upgrade request");
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Missing or invalid 'url' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Validate URL format (basic check for HTTP/HTTPS)
    if (strncmp(url_str, "http://", 7) != 0 && strncmp(url_str, "https://", 8) != 0) {
        debug(LOG_ERR, "Invalid URL protocol in firmware upgrade request: %s", url_str);
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Invalid URL protocol, only HTTP/HTTPS allowed");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Validate URL length
    if (strlen(url_str) > 256) {
        debug(LOG_ERR, "URL too long in firmware upgrade request");
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("URL too long");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    // Check for force flag
    bool force_upgrade = false;
    if (json_object_object_get_ex(j_req, "force", &j_force)) {
        force_upgrade = json_object_get_boolean(j_force);
    }
    
    debug(LOG_INFO, "Starting firmware upgrade from URL: %s (force: %s)", 
          url_str, force_upgrade ? "true" : "false");
    
    // Send success response before starting upgrade
    json_object *j_type = json_object_new_string("firmware_upgrade_response");
    json_object *j_status = json_object_new_string("success");
    json_object *j_message = json_object_new_string("Firmware upgrade initiated successfully");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "status", j_status);
    json_object_object_add(j_response, "message", j_message);
    
    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
    
    // Execute sysupgrade command with proper escaping
    char *escaped_url = malloc(strlen(url_str) * 2 + 1);
    if (!escaped_url) {
        debug(LOG_ERR, "Memory allocation failed for URL escaping");
        return;
    }
    
    // Escape shell special characters
    char *dst = escaped_url;
    for (const char *src = url_str; *src; src++) {
        if (*src == '\'' || *src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src;
    }
    *dst = '\0';
    
    char command[512];
    int ret;
    if (force_upgrade) {
        ret = snprintf(command, sizeof(command), "sysupgrade -F '%s' &", escaped_url);
    } else {
        ret = snprintf(command, sizeof(command), "sysupgrade '%s' &", escaped_url);
    }
    
    free(escaped_url);
    
    if (ret >= sizeof(command)) {
        debug(LOG_ERR, "Sysupgrade command too long");
        return;
    }
    
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute sysupgrade command");
        return;
    }
    
    pclose(fp);
    debug(LOG_INFO, "Firmware upgrade command executed successfully - system may reboot");
}

/**
 * @brief Handles a request to reboot the device.
 *
 * This function is called when a "reboot_device" message is received.
 * It executes the reboot command immediately.
 *
 * @param j_req The JSON request object (unused for this request type)
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_reboot_device_request(json_object *j_req, api_transport_context_t *transport) {
    debug(LOG_INFO, "Reboot device request received");
    
    // Execute reboot command immediately
    FILE *fp = popen("reboot &", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute reboot command");
        
        // Send error response
        json_object *j_response = json_object_new_object();
        json_object *j_type = json_object_new_string("reboot_device_error");
        json_object *j_error = json_object_new_string("Failed to execute reboot command");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }
    
    pclose(fp);
    
    // No response sent back as the device will reboot immediately
    debug(LOG_INFO, "Device is rebooting now");
}

/**
 * @brief Handles a request to update device information.
 *
 * This function is called when an "update_device_info" message is received.
 * It updates device configuration parameters and saves them to UCI.
 *
 * @param j_req The JSON request object containing device information
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_update_device_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_device_info;

    debug(LOG_INFO, "Update device info request received");

    if (!json_object_object_get_ex(j_req, "device_info", &j_device_info)) {
        debug(LOG_ERR, "Update device info request missing 'device_info' field");
        
        json_object *j_type = json_object_new_string("update_device_info_error");
        json_object *j_error = json_object_new_string("Missing 'device_info' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    t_device_info *device_info = get_device_info();
    if (!device_info) {
        device_info = safe_malloc(sizeof(t_device_info));
        memset(device_info, 0, sizeof(t_device_info));
        config_get_config()->device_info = device_info;
    }

    json_object *j_ap_device_id, *j_ap_mac_address, *j_ap_longitude, *j_ap_latitude, *j_location_id;

    // Update device ID if provided
    if (json_object_object_get_ex(j_device_info, "ap_device_id", &j_ap_device_id)) {
        const char *ap_device_id = json_object_get_string(j_ap_device_id);
        if (ap_device_id && strlen(ap_device_id) > 0 && strlen(ap_device_id) <= 64) {
            if (device_info->ap_device_id) free(device_info->ap_device_id);
            device_info->ap_device_id = safe_strdup(ap_device_id);
            uci_set_value("wifidogx", "common", "ap_device_id", ap_device_id);
            debug(LOG_DEBUG, "Updated ap_device_id: %s", ap_device_id);
        } else {
            debug(LOG_WARNING, "Invalid ap_device_id length");
        }
    }

    // Update MAC address if provided
    if (json_object_object_get_ex(j_device_info, "ap_mac_address", &j_ap_mac_address)) {
        const char *ap_mac_address = json_object_get_string(j_ap_mac_address);
        if (ap_mac_address && strlen(ap_mac_address) > 0 && strlen(ap_mac_address) <= 18) {
            if (device_info->ap_mac_address) free(device_info->ap_mac_address);
            device_info->ap_mac_address = safe_strdup(ap_mac_address);
            uci_set_value("wifidogx", "common", "ap_mac_address", ap_mac_address);
            debug(LOG_DEBUG, "Updated ap_mac_address: %s", ap_mac_address);
        } else {
            debug(LOG_WARNING, "Invalid ap_mac_address format");
        }
    }

    // Update longitude if provided
    if (json_object_object_get_ex(j_device_info, "ap_longitude", &j_ap_longitude)) {
        const char *ap_longitude = json_object_get_string(j_ap_longitude);
        if (ap_longitude && strlen(ap_longitude) > 0 && strlen(ap_longitude) <= 32) {
            if (device_info->ap_longitude) free(device_info->ap_longitude);
            device_info->ap_longitude = safe_strdup(ap_longitude);
            uci_set_value("wifidogx", "common", "ap_longitude", ap_longitude);
            debug(LOG_DEBUG, "Updated ap_longitude: %s", ap_longitude);
        } else {
            debug(LOG_WARNING, "Invalid ap_longitude format");
        }
    }

    // Update latitude if provided
    if (json_object_object_get_ex(j_device_info, "ap_latitude", &j_ap_latitude)) {
        const char *ap_latitude = json_object_get_string(j_ap_latitude);
        if (ap_latitude && strlen(ap_latitude) > 0 && strlen(ap_latitude) <= 32) {
            if (device_info->ap_latitude) free(device_info->ap_latitude);
            device_info->ap_latitude = safe_strdup(ap_latitude);
            uci_set_value("wifidogx", "common", "ap_latitude", ap_latitude);
            debug(LOG_DEBUG, "Updated ap_latitude: %s", ap_latitude);
        } else {
            debug(LOG_WARNING, "Invalid ap_latitude format");
        }
    }

    // Update location ID if provided
    if (json_object_object_get_ex(j_device_info, "location_id", &j_location_id)) {
        const char *location_id = json_object_get_string(j_location_id);
        if (location_id && strlen(location_id) > 0 && strlen(location_id) <= 64) {
            if (device_info->location_id) free(device_info->location_id);
            device_info->location_id = safe_strdup(location_id);
            uci_set_value("wifidogx", "common", "location_id", location_id);
            debug(LOG_DEBUG, "Updated location_id: %s", location_id);
        } else {
            debug(LOG_WARNING, "Invalid location_id format");
        }
    }

    // Send success response
    json_object *j_type = json_object_new_string("update_device_info_response");
    json_object *j_status = json_object_new_string("success");
    json_object *j_message = json_object_new_string("Device info updated successfully");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "status", j_status);
    json_object_object_add(j_response, "message", j_message);

    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);

    debug(LOG_INFO, "Device info updated successfully");
}

/**
 * @brief Handles a request to get complete Wi-Fi configuration information.
 *
 * This function is called when a "get_wifi_info" message is received.
 * It executes "uci show wireless" to retrieve complete wireless configuration,
 * parses the output, and sends comprehensive information back to the client.
 *
 * @param j_req The JSON request object (unused for this request type)
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_get_wifi_info_request(json_object *j_req, api_transport_context_t *transport) {
    FILE *fp;
    char buffer[512];
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    
    debug(LOG_INFO, "Get WiFi info request received");
    
    // Storage for device and interface information
    struct wifi_device_info devices[8];
    struct wifi_interface_info interfaces[32];
    int device_count = 0;
    int interface_count = 0;
    
    // Initialize storage
    memset(devices, 0, sizeof(devices));
    memset(interfaces, 0, sizeof(interfaces));

    // Execute command to get all wireless configuration
    fp = popen("uci show wireless", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to run command uci show wireless");
        
        json_object *j_type = json_object_new_string("get_wifi_info_error");
        json_object *j_error = json_object_new_string("Failed to execute command");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    // Parse UCI output
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;

        char *key = strtok(buffer, "=");
        char *value_with_quotes = strtok(NULL, "=");

        if (key && value_with_quotes) {
            // Remove single quotes from value
            char *value = value_with_quotes;
            if (value[0] == '\'' && value[strlen(value) - 1] == '\'') {
                value = value + 1;
                value[strlen(value) - 1] = '\0';
            }

            // Parse wireless configuration
            if (strstr(key, "wireless.") == key) {
                char *key_copy = strdup(key);
                if (!key_copy) continue;
                
                char *parts[4];
                int part_count = 0;
                
                char *token = strtok(key_copy, ".");
                while (token && part_count < 4) {
                    parts[part_count++] = token;
                    token = strtok(NULL, ".");
                }

                if (part_count >= 3) {
                    char *section_name = parts[1];
                    char *option = parts[2];

                    // Check if this is a wifi-device section
                    if (strstr(section_name, "radio") == section_name) {
                        // Find or create device entry
                        int idx = -1;
                        for (int i = 0; i < device_count; i++) {
                            if (strcmp(devices[i].device_name, section_name) == 0) {
                                idx = i;
                                break;
                            }
                        }
                        if (idx == -1 && device_count < 8) {
                            idx = device_count++;
                            strncpy(devices[idx].device_name, section_name, sizeof(devices[idx].device_name) - 1);
                            devices[idx].device_name[sizeof(devices[idx].device_name) - 1] = '\0';
                        }

                        if (idx >= 0) {
                            if (strcmp(option, "type") == 0) {
                                strncpy(devices[idx].type, value, sizeof(devices[idx].type) - 1);
                                devices[idx].type[sizeof(devices[idx].type) - 1] = '\0';
                            } else if (strcmp(option, "path") == 0) {
                                strncpy(devices[idx].path, value, sizeof(devices[idx].path) - 1);
                                devices[idx].path[sizeof(devices[idx].path) - 1] = '\0';
                            } else if (strcmp(option, "band") == 0) {
                                strncpy(devices[idx].band, value, sizeof(devices[idx].band) - 1);
                                devices[idx].band[sizeof(devices[idx].band) - 1] = '\0';
                            } else if (strcmp(option, "channel") == 0) {
                                devices[idx].channel = atoi(value);
                            } else if (strcmp(option, "htmode") == 0) {
                                strncpy(devices[idx].htmode, value, sizeof(devices[idx].htmode) - 1);
                                devices[idx].htmode[sizeof(devices[idx].htmode) - 1] = '\0';
                            } else if (strcmp(option, "cell_density") == 0) {
                                devices[idx].cell_density = atoi(value);
                            }
                        }
                    } else {
                        // This is a wifi-iface section
                        int idx = -1;
                        for (int i = 0; i < interface_count; i++) {
                            if (strcmp(interfaces[i].interface_name, section_name) == 0) {
                                idx = i;
                                break;
                            }
                        }
                        if (idx == -1 && interface_count < 32) {
                            idx = interface_count++;
                            strncpy(interfaces[idx].interface_name, section_name, sizeof(interfaces[idx].interface_name) - 1);
                            interfaces[idx].interface_name[sizeof(interfaces[idx].interface_name) - 1] = '\0';
                        }

                        if (idx >= 0) {
                            if (strcmp(option, "device") == 0) {
                                strncpy(interfaces[idx].device, value, sizeof(interfaces[idx].device) - 1);
                                interfaces[idx].device[sizeof(interfaces[idx].device) - 1] = '\0';
                            } else if (strcmp(option, "mode") == 0) {
                                strncpy(interfaces[idx].mode, value, sizeof(interfaces[idx].mode) - 1);
                                interfaces[idx].mode[sizeof(interfaces[idx].mode) - 1] = '\0';
                            } else if (strcmp(option, "ssid") == 0) {
                                strncpy(interfaces[idx].ssid, value, sizeof(interfaces[idx].ssid) - 1);
                                interfaces[idx].ssid[sizeof(interfaces[idx].ssid) - 1] = '\0';
                            } else if (strcmp(option, "key") == 0) {
                                strncpy(interfaces[idx].key, value, sizeof(interfaces[idx].key) - 1);
                                interfaces[idx].key[sizeof(interfaces[idx].key) - 1] = '\0';
                            } else if (strcmp(option, "encryption") == 0) {
                                strncpy(interfaces[idx].encryption, value, sizeof(interfaces[idx].encryption) - 1);
                                interfaces[idx].encryption[sizeof(interfaces[idx].encryption) - 1] = '\0';
                            } else if (strcmp(option, "network") == 0) {
                                strncpy(interfaces[idx].network, value, sizeof(interfaces[idx].network) - 1);
                                interfaces[idx].network[sizeof(interfaces[idx].network) - 1] = '\0';
                            } else if (strcmp(option, "mesh_id") == 0) {
                                strncpy(interfaces[idx].mesh_id, value, sizeof(interfaces[idx].mesh_id) - 1);
                                interfaces[idx].mesh_id[sizeof(interfaces[idx].mesh_id) - 1] = '\0';
                            } else if (strcmp(option, "disabled") == 0) {
                                interfaces[idx].disabled = atoi(value);
                            }
                        }
                    }
                }
                free(key_copy);
            }
        }
    }
    pclose(fp);

    // Build JSON response for each radio device
    for (int d = 0; d < device_count; d++) {
        json_object *j_radio = json_object_new_object();
        
        // Add device information
        json_object_object_add(j_radio, "type", json_object_new_string(devices[d].type));
        json_object_object_add(j_radio, "path", json_object_new_string(devices[d].path));
        json_object_object_add(j_radio, "band", json_object_new_string(devices[d].band));
        json_object_object_add(j_radio, "channel", json_object_new_int(devices[d].channel));
        json_object_object_add(j_radio, "htmode", json_object_new_string(devices[d].htmode));
        json_object_object_add(j_radio, "cell_density", json_object_new_int(devices[d].cell_density));
        
        // Add interfaces for this radio
        json_object *j_interfaces = json_object_new_array();
        for (int i = 0; i < interface_count; i++) {
            if (strcmp(interfaces[i].device, devices[d].device_name) == 0) {
                json_object *j_iface = json_object_new_object();
                json_object_object_add(j_iface, "interface_name", json_object_new_string(interfaces[i].interface_name));
                json_object_object_add(j_iface, "mode", json_object_new_string(interfaces[i].mode));
                json_object_object_add(j_iface, "network", json_object_new_string(interfaces[i].network));
                json_object_object_add(j_iface, "encryption", json_object_new_string(interfaces[i].encryption));
                json_object_object_add(j_iface, "disabled", json_object_new_boolean(interfaces[i].disabled));
                
                if (strlen(interfaces[i].ssid) > 0) {
                    json_object_object_add(j_iface, "ssid", json_object_new_string(interfaces[i].ssid));
                }
                if (strlen(interfaces[i].key) > 0) {
                    json_object_object_add(j_iface, "key", json_object_new_string(interfaces[i].key));
                }
                if (strlen(interfaces[i].mesh_id) > 0) {
                    json_object_object_add(j_iface, "mesh_id", json_object_new_string(interfaces[i].mesh_id));
                }
                
                json_object_array_add(j_interfaces, j_iface);
            }
        }
        json_object_object_add(j_radio, "interfaces", j_interfaces);
        
        // Add radio to data
        json_object_object_add(j_data, devices[d].device_name, j_radio);
    }

    // Get available network interfaces list for WiFi configuration (only static proto)
    json_object *j_networks = json_object_new_array();
    
    // First, get all network interfaces with proto=static
    fp = popen("uci show network 2>/dev/null | grep '\\.proto=.static.'", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp) != NULL) {
            buffer[strcspn(buffer, "\n")] = 0;
            char *key = strtok(buffer, "=");
            
            if (key && strstr(key, "network.") == key && strstr(key, ".proto")) {
                char *key_copy = strdup(key);
                if (!key_copy) continue;
                
                char *parts[4];
                int part_count = 0;
                
                char *token = strtok(key_copy, ".");
                while (token && part_count < 4) {
                    parts[part_count++] = token;
                    token = strtok(NULL, ".");
                }
                
                if (part_count >= 3 && strcmp(parts[2], "proto") == 0) {
                    char *interface_name = parts[1];
                    // Skip system interfaces
                    if (strcmp(interface_name, "loopback") != 0 && 
                        strcmp(interface_name, "globals") != 0) {
                        
                        // Check if this interface is already in the array
                        int found = 0;
                        int array_len = json_object_array_length(j_networks);
                        for (int i = 0; i < array_len; i++) {
                            json_object *existing = json_object_array_get_idx(j_networks, i);
                            if (existing) {
                                const char *existing_name = json_object_get_string(existing);
                                if (existing_name && strcmp(existing_name, interface_name) == 0) {
                                    found = 1;
                                    break;
                                }
                            }
                        }
                        
                        if (!found) {
                            json_object_array_add(j_networks, json_object_new_string(interface_name));
                        }
                    }
                }
                free(key_copy);
            }
        }
        pclose(fp);
    }
    json_object_object_add(j_data, "available_networks", j_networks);

    // Build success response
    json_object *j_type = json_object_new_string("get_wifi_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending complete Wi-Fi info response");
    send_response(transport, response_str);

    // Cleanup
    json_object_put(j_response);
    
    debug(LOG_INFO, "WiFi info sent successfully");
}

void handle_get_trusted_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
}

void handle_sync_trusted_domain_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    // Clear existing trusted domains from memory
    clear_trusted_domains();
    
    // Clear existing trusted domains from UCI configuration
    uci_del_list_option("wifidogx", "common", "trusted_domains");

    if (json_object_object_get_ex(j_req, "domains", &j_domains) && json_object_is_type(j_domains, json_type_array)) {
        int array_len = json_object_array_length(j_domains);
        for (int i = 0; i < array_len; i++) {
            json_object *j_domain = json_object_array_get_idx(j_domains, i);
            if (json_object_is_type(j_domain, json_type_string)) {
                const char *domain_str = json_object_get_string(j_domain);
                add_trusted_domains(domain_str);
                uci_add_list_value("wifidogx", "common", "trusted_domains", domain_str);
            }
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_domain_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted domains synchronized successfully"));
    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
}

void handle_get_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_wildcard_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
}

void handle_sync_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    // Clear existing trusted wildcard domains from memory
    clear_trusted_wildcard_domains();
    
    // Clear existing trusted wildcard domains from UCI configuration
    uci_del_list_option("wifidogx", "common", "trusted_wildcard_domains");

    if (json_object_object_get_ex(j_req, "domains", &j_domains) && json_object_is_type(j_domains, json_type_array)) {
        int array_len = json_object_array_length(j_domains);
        for (int i = 0; i < array_len; i++) {
            json_object *j_domain = json_object_array_get_idx(j_domains, i);
            if (json_object_is_type(j_domain, json_type_string)) {
                const char *domain_str = json_object_get_string(j_domain);
                add_trusted_wildcard_domains(domain_str);
                uci_add_list_value("wifidogx", "common", "trusted_wildcard_domains", domain_str);
            }
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted wildcard domains synchronized successfully"));
    const char *response_str = json_object_to_json_string(j_response);
    send_response(transport, response_str);
    json_object_put(j_response);
}

void handle_set_wifi_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data;

    if (!json_object_object_get_ex(j_req, "data", &j_data)) {
        debug(LOG_ERR, "Set wifi info request missing 'data' field");
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'data' field"));
        const char *response_str = json_object_to_json_string(j_response);
        send_response(transport, response_str);
        json_object_put(j_response);
        return;
    }

    int success = 1;
    char error_msg[256] = {0};

    // Process each radio device configuration
    json_object_object_foreach(j_data, radio_name, j_radio_config) {
        // Skip non-radio entries
        if (strstr(radio_name, "radio") != radio_name) {
            continue;
        }

        debug(LOG_INFO, "Configuring radio: %s", radio_name);

        // Configure radio device settings
        json_object *j_value;
        if (json_object_object_get_ex(j_radio_config, "channel", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.channel", radio_name);
            if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set channel for %s", radio_name);
            }
        }

        if (json_object_object_get_ex(j_radio_config, "htmode", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.htmode", radio_name);
            if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set htmode for %s", radio_name);
            }
        }

        if (json_object_object_get_ex(j_radio_config, "cell_density", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.cell_density", radio_name);
            char value_str[16];
            snprintf(value_str, sizeof(value_str), "%d", json_object_get_int(j_value));
            if (set_uci_config(config_path, value_str) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set cell_density for %s", radio_name);
            }
        }

        // Configure interfaces for this radio
        json_object *j_interfaces;
        if (json_object_object_get_ex(j_radio_config, "interfaces", &j_interfaces)) {
            int interface_count = json_object_array_length(j_interfaces);
            
            for (int i = 0; i < interface_count; i++) {
                json_object *j_interface = json_object_array_get_idx(j_interfaces, i);
                if (!j_interface) continue;

                json_object *j_iface_name;
                if (!json_object_object_get_ex(j_interface, "interface_name", &j_iface_name)) {
                    continue;
                }
                
                const char *interface_name = json_object_get_string(j_iface_name);
                debug(LOG_INFO, "Configuring interface: %s", interface_name);

                // Set device assignment
                char config_path[128];
                snprintf(config_path, sizeof(config_path), "wireless.%s.device", interface_name);
                if (set_uci_config(config_path, radio_name) != 0) {
                    success = 0;
                    snprintf(error_msg, sizeof(error_msg), "Failed to set device for interface %s", interface_name);
                    continue;
                }

                // Configure interface properties
                if (json_object_object_get_ex(j_interface, "mode", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.mode", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set mode for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "ssid", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.ssid", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set SSID for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "key", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.key", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set key for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "encryption", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.encryption", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set encryption for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "network", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.network", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set network for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "mesh_id", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.mesh_id", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set mesh_id for interface %s", interface_name);
                    }
                }



                if (json_object_object_get_ex(j_interface, "disabled", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.disabled", interface_name);
                    char value_str[16];
                    snprintf(value_str, sizeof(value_str), "%d", json_object_get_boolean(j_value) ? 1 : 0);
                    if (set_uci_config(config_path, value_str) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set disabled for interface %s", interface_name);
                    }
                }
            }
        }
    }



    if (success) {
        // Commit UCI changes
        if (commit_uci_changes() != 0) {
            success = 0;
            snprintf(error_msg, sizeof(error_msg), "Failed to commit configuration changes");
        }
    }

    if (success) {
        // Reload wifi to apply changes
        FILE *reload_fp = popen("wifi reload", "r");
        if (reload_fp == NULL) {
            debug(LOG_ERR, "Failed to run reload commands");
            json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Failed to reload services"));
        } else {
            pclose(reload_fp);
            
            // Construct success response
            json_object *j_resp_data = json_object_new_object();
            json_object_object_add(j_resp_data, "status", json_object_new_string("success"));
            json_object_object_add(j_resp_data, "message", json_object_new_string("Wi-Fi configuration updated successfully"));
            json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_response"));
            json_object_object_add(j_response, "data", j_resp_data);
        }
    } else {
        // Construct error response
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string(strlen(error_msg) > 0 ? error_msg : "Failed to update Wi-Fi configuration"));
    }

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending Wi-Fi configuration response");
    send_response(transport, response_str);

    // Cleanup
    json_object_put(j_response);
}

void handle_get_sys_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    
    debug(LOG_INFO, "System info request received");
    
    // Get system information
    struct sys_info sysinfo;
    get_sys_info(&sysinfo);
    
    // Build JSON response with system information
    json_object_object_add(j_data, "sys_uptime", json_object_new_int64(sysinfo.sys_uptime));
    json_object_object_add(j_data, "sys_memfree", json_object_new_int(sysinfo.sys_memfree));
    json_object_object_add(j_data, "sys_load", json_object_new_double(sysinfo.sys_load));
    json_object_object_add(j_data, "nf_conntrack_count", json_object_new_int64(sysinfo.nf_conntrack_count));
    json_object_object_add(j_data, "cpu_usage", json_object_new_double(sysinfo.cpu_usage));
    json_object_object_add(j_data, "wifidog_uptime", json_object_new_int64(sysinfo.wifidog_uptime));
    json_object_object_add(j_data, "cpu_temp", json_object_new_int(sysinfo.cpu_temp));
    
    // Construct response
    json_object_object_add(j_response, "type", json_object_new_string("get_sys_info_response"));
    json_object_object_add(j_response, "data", j_data);
    
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending system info response: %s", response_str);
    send_response(transport, response_str);
    
    // Cleanup
    json_object_put(j_response);
}
