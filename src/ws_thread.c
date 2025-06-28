
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <netinet/tcp.h>

#include "common.h"
#include "ws_thread.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "client_list.h"
#include "gateway.h"
#include "fw_iptables.h"
#include "fw_nft.h"
#include "wd_util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For calloc and free


/**
 * Maximum size of WebSocket output buffer in bytes
 */
#define MAX_OUTPUT (512*1024)
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_HEARTBEAT_INTERVAL 60

/**
 * Network byte order conversion for 64-bit integers
 * Handles both big and little endian architectures
 */
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

/**
 * Global WebSocket connection state
 */
static struct {
	struct event_base *base;      /* Main event loop base */
	struct evdns_base *dnsbase;   /* DNS resolver base */
	struct event *heartbeat_ev;   /* Heartbeat timer event */
	bool upgraded;                /* WebSocket upgrade completed flag */
} ws_state = {
	.base = NULL,
	.dnsbase = NULL, 
	.heartbeat_ev = NULL,
	.upgraded = false
};

/**
 * SSL/TLS connection state
 */
static struct {
	SSL_CTX *ctx;                /* SSL context */
	SSL *ssl;                    /* SSL connection */
} ssl_state = {
	.ctx = NULL,
	.ssl = NULL
};

enum WebSocketFrameType {
	ERROR_FRAME = 0xFF,
	INCOMPLETE_DATA = 0xFE,

	CLOSING_FRAME = 0x8,

	INCOMPLETE_FRAME = 0x81,

	TEXT_FRAME = 0x1,
	BINARY_FRAME = 0x2,

	PING_FRAME = 0x9,
	PONG_FRAME = 0xA
};

/**
 * WebSocket handshake constants
 * Fixed values used for testing/development
 * TODO: Generate random key and accept token for production
 */
#define WS_KEY_LEN 		24
#define WS_ACCEPT_LEN 	28
static char WS_KEY[WS_KEY_LEN+1];
static char WS_ACCEPT[WS_ACCEPT_LEN+1];

/* Forward declarations for callback functions */
static void ws_heartbeat_cb(evutil_socket_t fd, short events, void *arg);
static void wsevent_connection_cb(struct bufferevent *bev, short events, void *ctx);
static void handle_auth_response(json_object *j_auth);
static void handle_kickoff_response(json_object *j_auth);
static void handle_get_firmware_info_request(json_object *j_req, struct bufferevent *bev);
static void cleanup_connection(struct bufferevent *bev);
static void reconnect_websocket(void);
static void ws_send(struct evbuffer *buf, const char *msg, const size_t len, enum WebSocketFrameType frame_type);

/**
 * @brief Generates a secure WebSocket key for WebSocket handshake
 *
 * This function generates a WebSocket key according to RFC 6455 specifications:
 * 1. Creates 16 random bytes using OpenSSL's RAND_bytes
 * 2. Encodes these bytes using Base64 encoding
 * 
 * The resulting key is exactly 24 bytes long (not counting null terminator).
 *
 * @param key Buffer where the generated key will be stored
 * @param length Size of the provided buffer (must be at least 25 bytes to accommodate 
 *               24 Base64 encoded characters plus null terminator)
 *
 * @note The function will return without generating a key if:
 *       - Random bytes generation fails
 *       - The provided buffer is too small (< 25 bytes)
 */
static void
generate_sec_websocket_key(char *key, size_t length)
{
	// Generate 16 random bytes as required by WebSocket spec
	unsigned char rand_bytes[16];
	if (!RAND_bytes(rand_bytes, sizeof(rand_bytes))) {
		debug(LOG_ERR, "Failed to generate random bytes for WebSocket key");
		return;
	}

	// Base64 encode the random bytes
	// Base64 encoding of 16 bytes will produce exactly 24 bytes plus null terminator
	if (length < 25) {
		debug(LOG_ERR, "Buffer too small for WebSocket key");
		return;
	}

	EVP_EncodeBlock((unsigned char *)key, rand_bytes, sizeof(rand_bytes));
	
	// Ensure null termination
	key[24] = '\0';

	debug(LOG_DEBUG, "Generated WebSocket key: %s", key);
}

/**
 * @brief Handles a request for firmware information.
 *
 * This function is called by process_ws_msg() when a "get_firmware_info"
 * message is received. It executes the command "cat /etc/openwrt_release"
 * to retrieve firmware details, parses the key-value output, and sends
 * this information back to the client in a JSON response.
 *
 * The JSON response format is:
 * {
 *   "type": "firmware_info_response",
 *   "data": {
 *     "DISTRIB_ID": "ChaWrt",
 *     "DISTRIB_RELEASE": "24.10-SNAPSHOT",
 *     // ... other key-value pairs from /etc/openwrt_release
 *   }
 * }
 *
 * If the command execution fails, an error response is sent:
 * {
 *   "type": "firmware_info_error",
 *   "error": "Failed to execute command"
 * }
 *
 * @param j_req The incoming JSON request object. Currently unused for this
 *              specific request type but included for API consistency.
 * @param bev The bufferevent associated with the WebSocket connection, used
 *            for sending the response.
 */
static void handle_get_firmware_info_request(json_object *j_req, struct bufferevent *bev) {
    FILE *fp;
    char buffer[256];
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    // Execute command
    fp = popen("cat /etc/openwrt_release", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to run command /etc/openwrt_release");
        json_object_object_add(j_response, "type", json_object_new_string("firmware_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to execute command"));
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    // Read command output line by line
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        // Remove trailing newline
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
            json_object_object_add(j_data, key, json_object_new_string(value));
        }
    }
    pclose(fp);

    // Construct response
    json_object_object_add(j_response, "type", json_object_new_string("firmware_info_response"));
    json_object_object_add(j_response, "data", j_data); // j_data is already an object

    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);

    // Cleanup
    json_object_put(j_response); // This will also free j_data as it's part of j_response
}

/**
 * @brief Generates the Sec-WebSocket-Accept header value for WebSocket handshake
 *
 * This function implements the WebSocket handshake process by:
 * 1. Concatenating the client's Sec-WebSocket-Key with the WebSocket GUID
 * 2. Computing the SHA-1 hash of the concatenated string
 * 3. Base64 encoding the resulting hash
 *
 * @param key The Sec-WebSocket-Key value from the client's handshake request
 * @param accept Buffer to store the generated accept token
 * @param length Size of the accept buffer (must be at least 29 bytes)
 * 
 * @note The WebSocket GUID is defined as "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
 * @note The resulting accept token is exactly 28 bytes long plus null terminator
 */
static void
generate_sec_websocket_accept(const char *key, char *accept, size_t length)
{
	// Concatenate WebSocket key with WebSocket GUID
	char key_guid[64];
	snprintf(key_guid, sizeof(key_guid), "%s%s", key, WS_GUID);

	// Calculate SHA1 hash of concatenated key
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char *)key_guid, strlen(key_guid), sha1_hash);

	// Base64 encode the SHA1 hash
	// Base64 encoding of 20 bytes will produce exactly 28 bytes plus null terminator
	if (length < 29) {
		debug(LOG_ERR, "Buffer too small for WebSocket accept token");
		return;
	}

	EVP_EncodeBlock((unsigned char *)accept, sha1_hash, SHA_DIGEST_LENGTH);

	// Ensure null termination
	accept[28] = '\0';

	debug(LOG_DEBUG, "Generated WebSocket accept token: %s", accept);
}

/**
 * Handle client kickoff response from WebSocket server
 *
 * Processes client disconnection requests with format:
 * {
 *   "client_ip": "<ip_address>",
 *   "client_mac": "<mac_address>",
 *   "device_id": "<device_id>", 
 *   "gw_id": "<gateway_id>"
 * }
 *
 * Validates the request and removes the client by:
 * 1. Verifying all required fields are present
 * 2. Checking client exists in local database
 * 3. Validating device ID and gateway ID match
 * 4. Removing firewall rules and client entry
 *
 * @param j_auth JSON object containing the kickoff request
 */
static void
handle_kickoff_response(json_object *j_auth)
{
	// Extract and validate required fields
	json_object *client_ip = json_object_object_get(j_auth, "client_ip");
	json_object *client_mac = json_object_object_get(j_auth, "client_mac");
	json_object *device_id = json_object_object_get(j_auth, "device_id");
	json_object *gw_id = json_object_object_get(j_auth, "gw_id");

	if (!client_ip || !client_mac || !device_id || !gw_id) {
		debug(LOG_ERR, "Kickoff: Missing required fields in request");
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
		return;
	}

	// Validate device ID matches
	const char *local_device_id = get_device_id();
	if (!local_device_id || strcmp(local_device_id, device_id_str) != 0) {
		debug(LOG_ERR, "Kickoff: Device ID mismatch - expected %s", device_id_str);
		return;
	}

	// Validate gateway ID matches
	if (!client->gw_setting || strcmp(client->gw_setting->gw_id, gw_id_str) != 0) {
		debug(LOG_ERR, "Kickoff: Gateway mismatch for client %s - expected %s",
			  client_mac_str, gw_id_str);
		return;
	}

	// Remove client
	LOCK_CLIENT_LIST();
	fw_deny(client);
	client_list_remove(client);
	client_free_node(client);
	UNLOCK_CLIENT_LIST();

	debug(LOG_DEBUG, "Kicked off client %s (%s)", client_mac_str, client_ip_str);
}

/**
 * Handle authentication response from WebSocket server
 *
 * Processes client authentication responses with format:
 * {
 *   "token": "<auth_token>",
 *   "client_ip": "<ip_address>",
 *   "client_mac": "<mac_address>", 
 *   "client_name": "<name>",         // Optional
 *   "gw_id": "<gateway_id>",
 *   "once_auth": <boolean>
 * }
 *
 * Handles two cases:
 * 1. Once-auth: Updates gateway auth mode to 0 and reloads firewall
 * 2. Regular auth: Adds client to allowed list with firewall rules
 *
 * @param j_auth JSON object containing the auth response
 */
static void
handle_auth_response(json_object *j_auth)
{
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
		client->name = strdup(json_object_get_string(client_name));
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
 * Handle temporary pass response from WebSocket server
 *
 * Processes a temporary access request for a client device based on MAC address.
 * The request format is:
 * {
 *   "client_mac": "<MAC_ADDRESS>",
 *   "timeout": <SECONDS>        // Optional, defaults to 300s (5 min)
 * }
 *
 * Sets up temporary firewall access for the specified MAC address
 * that expires after the timeout period.
 *
 * @param j_tmp_pass JSON object containing the temporary pass request
 */
static void
handle_tmp_pass_response(json_object *j_tmp_pass)
{
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
 * Handle heartbeat response from WebSocket server
 *
 * Processes heartbeat response messages containing gateway status updates.
 * The response JSON format is:
 * {
 *   "type": "heartbeat",
 *   "gateway": [
 *     {
 *       "gw_id": "<gateway_id>",
 *       "auth_mode": <mode_number>
 *     },
 *     ...
 *   ]
 * }
 *
 * Updates local gateway settings and reloads firewall rules if any
 * authentication modes have changed.
 *
 * @param j_heartbeat JSON object containing the heartbeat response
 */
static void
handle_heartbeat_response(json_object *j_heartbeat)
{
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

/**
 * Start or restart the WebSocket heartbeat timer
 *
 * This function sets up a periodic timer to send heartbeat messages to the WebSocket
 * server every 60 seconds. It will:
 * - Clean up any existing heartbeat timer
 * - Create a new persistent timer event 
 * - Associate the timer with the WebSocket bufferevent
 *
 * The heartbeat helps:
 * - Keep the WebSocket connection alive
 * - Synchronize gateway states with the server
 * - Detect connection failures
 *
 * @param b_ws The WebSocket bufferevent to associate with the heartbeat
 */
static void
start_ws_heartbeat(struct bufferevent *b_ws)
{
	// Clean up existing timer if any
	if (ws_state.heartbeat_ev != NULL) {
		event_free(ws_state.heartbeat_ev);
		ws_state.heartbeat_ev = NULL;
	}

	struct timeval tv = {
		.tv_sec = WS_HEARTBEAT_INTERVAL,
		.tv_usec = 0
	};

	// Create persistent timer event
	ws_state.heartbeat_ev = event_new(ws_state.base, -1, EV_PERSIST, ws_heartbeat_cb, b_ws);
	if (ws_state.heartbeat_ev) {
		event_add(ws_state.heartbeat_ev, &tv);
	}
}

/**
 * @brief Processes incoming WebSocket messages.
 *
 * Parses and handles JSON messages received over WebSocket. This function acts as
 * a dispatcher, routing messages to specific handlers based on their "type" field.
 * Supported message types:
 * - `"heartbeat"`: Handles gateway status updates. (Responds with heartbeat)
 * - `"connect"`: Handles initial connection response. (Responds with heartbeat)
 * - `"auth"`: Handles client authentication responses.
 * - `"kickoff"`: Handles client disconnection requests.
 * - `"tmp_pass"`: Handles requests for temporary client access.
 * - `"get_firmware_info"`: Triggers a request for firmware information. The device
 *                          responds with a "firmware_info_response" message
 *                          containing details from /etc/openwrt_release.
 *
 * @param bev The bufferevent associated with the WebSocket connection,
 *            passed to message handlers for sending responses.
 * @param msg The raw JSON message string to process.
 */
static void
process_ws_msg(struct bufferevent *bev, const char *msg)
{
	debug(LOG_DEBUG, "Processing WebSocket message: %s", msg);

	// Parse JSON message
	json_object *jobj = json_tokener_parse(msg);
	if (!jobj) {
		debug(LOG_ERR, "Failed to parse JSON message");
		return;
	}

	// Extract message type
	json_object *type = json_object_object_get(jobj, "type");
	if (!type) {
		debug(LOG_ERR, "Missing message type in JSON");
		json_object_put(jobj);
		return;
	}

	// Route message to appropriate handler based on type
	const char *type_str = json_object_get_string(type);
	if (!strcmp(type_str, "heartbeat") || !strcmp(type_str, "connect")) {
		handle_heartbeat_response(jobj);
	} else if (!strcmp(type_str, "auth")) {
		handle_auth_response(jobj);
	} else if (!strcmp(type_str, "kickoff")) {
		handle_kickoff_response(jobj);
	} else if (!strcmp(type_str, "tmp_pass")) {
		handle_tmp_pass_response(jobj);
	} else if (!strcmp(type_str, "get_firmware_info")) {
		handle_get_firmware_info_request(jobj, bev);
	} else {
		debug(LOG_ERR, "Unknown message type: %s", type_str);
	}

	json_object_put(jobj);
}


/**
 * Send a WebSocket frame to the server
 *
 * Constructs and sends a WebSocket frame according to RFC 6455 with:
 * - FIN and opcode bits
 * - Payload length field (7/16/64 bits)
 * - Masking key and masked payload
 *
 * @param buf Output evbuffer to write the frame to
 * @param msg Message payload to send
 * @param len Length of the message payload
 */
static void 
ws_send(struct evbuffer *buf, const char *msg, const size_t len, enum WebSocketFrameType frame_type)
{
	// Frame header byte 1: FIN=1, RSV1-3=0, Opcode=0x1 (text)
	uint8_t header1 = 0x80; // 1000 0001
	header1 |= frame_type;

	// Frame header byte 2: MASK=1, with payload length
	uint8_t header2 = 0x80; // Set mask bit
	uint16_t len16;
	uint64_t len64;

	// Set payload length field
	if (len < 126) {
		header2 |= len;
	} else if (len < 65536) {
		header2 |= 126;
		len16 = htons(len);
	} else {
		header2 |= 127;
		len64 = htonll(len);
	}

	// Write frame headers
	evbuffer_add(buf, &header1, 1);
	evbuffer_add(buf, &header2, 1);

	// Write extended payload length if needed
	if (len >= 126 && len < 65536) {
		evbuffer_add(buf, &len16, sizeof(len16));
	} else if (len >= 65536) {
		evbuffer_add(buf, &len64, sizeof(len64));
	}

	// Add masking key and masked payload
	uint8_t mask_key[4];
    for (int i = 0; i < 4; i++) {
        mask_key[i] = rand() & 0xFF;
    }
	evbuffer_add(buf, mask_key, 4);

	// Mask and write payload
	uint8_t masked_byte;
	for (size_t i = 0; i < len; i++) {
		masked_byte = msg[i] ^ mask_key[i % 4];
		evbuffer_add(buf, &masked_byte, 1);
	}
}

/**
 * @brief Processes a received WebSocket frame.
 *
 * Parses and handles an incoming WebSocket frame according to RFC 6455.
 * This includes:
 * - Validating frame header and payload length fields.
 * - Handling extended payload lengths.
 * - Unmasking the payload if it is masked.
 * - Extracting the message from text frames and passing it to process_ws_msg().
 *
 * @param bev The bufferevent associated with the WebSocket connection,
 *            passed to process_ws_msg() for context.
 * @param data Pointer to the raw frame data buffer.
 * @param data_len Length of the data in the buffer.
 */
static void 
ws_receive(struct bufferevent *bev, unsigned char *data, const size_t data_len)
{
	if (data_len < 2) {
		return;
	}

	// Parse frame header
	const uint8_t opcode = data[0] & 0x0F;
	const bool masked = !!(data[1] & 0x80);
	uint64_t payload_len = data[1] & 0x7F;

	// Calculate total header length
	size_t header_len = 2 + (masked ? 4 : 0);

	// Handle extended payload lengths
	if (payload_len == 126) {
		header_len += 2;
		if (header_len > data_len) return;
		payload_len = ntohs(*(uint16_t*)(data + 2));
	} else if (payload_len == 127) {
		header_len += 8;
		if (header_len > data_len) return;
		payload_len = ntohll(*(uint64_t*)(data + 2));
	}

	// Validate total message length
	if (header_len + payload_len > data_len) {
		return;
	}

	// Unmask payload if needed
	if (masked) {
		unsigned char *mask_key = data + header_len - 4;
		for (uint64_t i = 0; i < payload_len; i++) {
			data[header_len + i] ^= mask_key[i % 4];
		}
	}

	// Process text frames
	if (opcode == TEXT_FRAME) {
		const char *msg = (const char *)(data + header_len);
		// Ensure null termination for safety, though payload_len should be accurate
		char *safe_msg = calloc(1, payload_len + 1);
		if (safe_msg) {
			memcpy(safe_msg, msg, payload_len);
			safe_msg[payload_len] = '\0';
			process_ws_msg(bev, safe_msg);
			free(safe_msg);
		} else {
			debug(LOG_ERR, "Failed to allocate memory for message buffer in ws_receive");
		}
	} else {
		debug(LOG_ERR, "Unsupported WebSocket opcode: %d", opcode);
	}
}

/**
 * Send WebSocket upgrade request to server
 *
 * Constructs and sends the initial HTTP upgrade request to establish
 * a WebSocket connection. The request includes:
 * - HTTP GET request with WebSocket path
 * - Required WebSocket headers (Upgrade, Connection, Key, Version)
 * - Host and Origin headers based on server configuration
 *
 * @param b_ws Bufferevent for the WebSocket connection
 */
static void 
ws_request(struct bufferevent* b_ws)
{
	struct evbuffer *out = bufferevent_get_output(b_ws);
	t_ws_server *ws_server = get_ws_server();
	
	debug(LOG_DEBUG, "Sending WebSocket upgrade request to path: %s", ws_server->path);
	
	// Required WebSocket headers
	evbuffer_add_printf(out, 
		"GET %s HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"User-Agent: apfree-wifidog\r\n"
		"Upgrade: websocket\r\n"
		"Connection: upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"\r\n",
		ws_server->path,
		ws_server->hostname, ws_server->port,
		WS_KEY
	);
}

/**
 * Send a message to the WebSocket server
 * 
 * Constructs and sends a JSON message containing:
 * - Message type (heartbeat/connect)
 * - Device ID
 * - Array of gateway configurations including:
 *   - Gateway ID, channel, IPv4/IPv6 addresses
 *   - Authentication mode and interface
 *
 * @param out The output evbuffer to write the message to
 * @param type The message type ("heartbeat" or "connect")
 */
static void
send_msg(struct evbuffer *out, const char *type)
{
	// Create root JSON object with type and device ID
	json_object *root = json_object_new_object();
	json_object_object_add(root, "type", json_object_new_string(type));
	json_object_object_add(root, "device_id", json_object_new_string(get_device_id()));

	// Create gateway array
	json_object *gw_array = json_object_new_array();
	t_gateway_setting *gw_settings = get_gateway_settings();

	// Add each gateway's configuration
	while(gw_settings) {
		json_object *gw = json_object_new_object();
		
		// Add required gateway fields
		json_object_object_add(gw, "gw_id", json_object_new_string(gw_settings->gw_id));
		json_object_object_add(gw, "gw_channel", json_object_new_string(gw_settings->gw_channel));
		json_object_object_add(gw, "gw_address_v4", json_object_new_string(gw_settings->gw_address_v4));
		json_object_object_add(gw, "auth_mode", json_object_new_int(gw_settings->auth_mode));
		json_object_object_add(gw, "gw_interface", json_object_new_string(gw_settings->gw_interface));

		// Add IPv6 address if available
		if (gw_settings->gw_address_v6) {
			json_object_object_add(gw, "gw_address_v6", 
				json_object_new_string(gw_settings->gw_address_v6));
		}

		json_object_array_add(gw_array, gw);
		gw_settings = gw_settings->next;
	}

	json_object_object_add(root, "gateway", gw_array);

	// Send formatted JSON message
	const char *json_str = json_object_to_json_string(root);
	debug(LOG_DEBUG, "Sending %s message: %s", type, json_str);
	
	
	ws_send(out, json_str, strlen(json_str), TEXT_FRAME);
	json_object_put(root);
}

/**
 * Periodic heartbeat callback
 *
 * Called every 60 seconds to send a heartbeat message to the server
 * to maintain the WebSocket connection and sync gateway states.
 *
 * @param fd Unused socket descriptor
 * @param event Unused event flags
 * @param arg Pointer to the WebSocket bufferevent
 */
static void
ws_heartbeat_cb(evutil_socket_t fd, short event, void *arg)
{
	struct bufferevent *b_ws = (struct bufferevent *)arg;
	struct evbuffer *out = bufferevent_get_output(b_ws);
	
	send_msg(out, "heartbeat");	
}

/**
 * WebSocket read callback handler
 *
 * Handles incoming WebSocket data including:
 * - Initial HTTP upgrade handshake verification 
 * - Processing of WebSocket frames after upgrade
 * - Sending initial connect message and starting heartbeat
 *
 * @param b_ws The WebSocket bufferevent
 * @param ctx User-provided context (unused)
 */
static void 
ws_read_cb(struct bufferevent *b_ws, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(b_ws);
	unsigned char data[1024] = {0};
	size_t total_len = 0;

	// Read all available data from input buffer
	size_t chunk_len;
	while ((chunk_len = evbuffer_get_length(input)) > 0) {
		if (total_len + chunk_len >= sizeof(data)) {
			debug(LOG_ERR, "Input buffer overflow");
			return;
		}
		evbuffer_remove(input, data + total_len, chunk_len);
		total_len += chunk_len;
	}

	// Handle HTTP upgrade handshake
	if (!ws_state.upgraded) {
		// Wait for complete HTTP response
		if (!strstr((const char*)data, "\r\n\r\n")) {
			debug(LOG_DEBUG, "Incomplete HTTP response");
			return;
		}

		// Verify upgrade response
		if (strncmp((const char*)data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0 
			|| !strstr((const char*)data, WS_ACCEPT)) {
			debug(LOG_ERR, "Invalid WebSocket upgrade response");
			return;
		}

		debug(LOG_DEBUG, "WebSocket upgrade successful");
		ws_state.upgraded = true;

		// Send initial connect message
		struct evbuffer *output = bufferevent_get_output(b_ws);
		send_msg(output, "connect");

		// Start heartbeat timer
		start_ws_heartbeat(b_ws);
		return;
	}

	// Process WebSocket frames after upgrade
	ws_receive(b_ws, data, total_len);
}

/**
 * Create and configure a new bufferevent for WebSocket connection
 *
 * This function creates a new bufferevent for either plain TCP or SSL/TLS
 * WebSocket connections based on server configuration. It:
 * - Creates bufferevent with appropriate SSL settings if needed
 * - Configures callbacks for reading and connection events
 * - Enables read/write operations
 *
 * @return struct bufferevent* Configured bufferevent ready for connection,
 *         or NULL on allocation failure
 */
static struct bufferevent *
create_ws_bufferevent(void)
{
	struct bufferevent *bev = NULL;
	t_ws_server *ws_server = get_ws_server();
	if (!ws_server) {
		debug(LOG_ERR, "No WebSocket server configuration available");
		return NULL;
	}

	// Set common bufferevent options
	int options = BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS;

	// Create appropriate bufferevent based on SSL setting
	if (ws_server->use_ssl) {
		if (!ssl_state.ssl) {
			debug(LOG_ERR, "SSL context not initialized");
			return NULL;
		}
		
		bev = bufferevent_openssl_socket_new(
			ws_state.base,
			-1,
			ssl_state.ssl,
			BUFFEREVENT_SSL_CONNECTING,
			options
		);
	} else {
		bev = bufferevent_socket_new(
			ws_state.base,
			-1, 
			options
		);
	}

	if (!bev) {
		debug(LOG_ERR, "Failed to create bufferevent");
		return NULL;
	}

	// Configure SSL settings if needed
	if (ws_server->use_ssl) {
		bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	}

	// Set callbacks and enable read/write
	bufferevent_setcb(bev, ws_read_cb, NULL, wsevent_connection_cb, NULL);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

	debug(LOG_DEBUG, "Created bufferevent for %s connection", 
		  ws_server->use_ssl ? "SSL" : "plain");

	return bev;
}

/**
 * WebSocket connection event callback
 *
 * Handles WebSocket connection events including:
 * - Successful connection and handshake initiation
 * - Connection errors and EOF 
 * - Automatic reconnection on failure
 *
 * @param b_ws The WebSocket bufferevent
 * @param events The triggered event flags
 * @param ctx User-provided context (unused)
 */
static void 
wsevent_connection_cb(struct bufferevent* b_ws, short events, void *ctx)
{
	if (events & BEV_EVENT_CONNECTED) {
		// Connection succeeded - initiate WebSocket handshake
		debug(LOG_DEBUG, "Connected to WebSocket server, initiating handshake");
		ws_request(b_ws);
		return;
	}

	// Handle connection failure cases
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		// Get specific error details
		int err = bufferevent_socket_get_dns_error(b_ws);
		if (err) {
			debug(LOG_ERR, "WebSocket DNS error: %s", evutil_gai_strerror(err));
		} else {
			debug(LOG_ERR, "WebSocket connection error: %s", evutil_socket_error_to_string(errno));
		}

		// Clean up existing connection state
		cleanup_connection(b_ws);

		// Calculate reconnect delay - longer for EOF
		int delay = (events & BEV_EVENT_EOF) ? 5 : 2;
		debug(LOG_DEBUG, "Waiting %d seconds before reconnect attempt", delay);
		sleep(delay);

		// Attempt reconnection
		reconnect_websocket();
		return;
	}

	debug(LOG_ERR, "Unexpected WebSocket event: 0x%x", events);
}

/**
 * @brief Static helper function used within the WebSocket thread context
 * 
 * This function is a private implementation detail of the WebSocket thread handling.
 * The actual purpose and behavior should be documented based on the function's
 * specific implementation.
 *
 * @note This is a static function and is not accessible outside of the ws_thread.c file
 */
static void
cleanup_connection(struct bufferevent *bev)
{
	// Stop heartbeat timer
	if (ws_state.heartbeat_ev) {
		event_free(ws_state.heartbeat_ev);
		ws_state.heartbeat_ev = NULL;
	}

	// Reset connection state
	ws_state.upgraded = false;

	// Free the bufferevent
	if (bev) {
		bufferevent_free(bev);
	}
}

/**
 * @brief Marks function as static, indicating private scope within the source file
 * 
 * This function is defined in ws_thread.c and is only accessible within that
 * translation unit. The 'static' keyword prevents external linkage.
 */
static void 
reconnect_websocket(void)
{
	struct bufferevent *bev = create_ws_bufferevent();
	if (!bev) {
		debug(LOG_ERR, "Failed to create new bufferevent for reconnection");
		return;
	}

	t_ws_server *server = get_ws_server();
	int ret = bufferevent_socket_connect_hostname(
		bev,
		ws_state.dnsbase,
		AF_INET, 
		server->hostname,
		server->port
	);

	if (ret < 0) {
		debug(LOG_ERR, "Reconnection failed: %s", evutil_socket_error_to_string(errno));
		bufferevent_free(bev);
	} else {
		debug(LOG_DEBUG, "Reconnection attempt initiated");
	}
}

/**
 * @brief Function prefix for a static function definition
 * @return Returns an integer value indicating the operation status
 * @note This is a static function and its scope is limited to the current file
 */
static int 
setup_ssl(const char *hostname)
{
	if (!RAND_poll()) {
		debug(LOG_ERR, "RAND_poll() failed");
		return -1;
	}

	ssl_state.ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_state.ctx) {
		debug(LOG_ERR, "SSL_CTX_new() failed");
		return -1;
	}

	ssl_state.ssl = SSL_new(ssl_state.ctx);
	if (!ssl_state.ssl) {
		debug(LOG_ERR, "SSL_new() failed");
		SSL_CTX_free(ssl_state.ctx);
		return -1;
	}

	if (!SSL_set_tlsext_host_name(ssl_state.ssl, hostname)) {
		debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
		SSL_free(ssl_state.ssl);
		SSL_CTX_free(ssl_state.ctx);
		return -1;
	}

	return 0;
}

/**
 * @brief Static helper function for WebSocket operations
 * @return Returns an integer status code:
 *         - Positive value on success
 *         - Zero or negative value on failure
 * 
 * @note This function is for internal use only within ws_thread.c
 */
static int 
setup_event_bases(void)
{
	ws_state.base = event_base_new();
	if (!ws_state.base) {
		debug(LOG_ERR, "Failed to create event base");
		return -1;
	}

	ws_state.dnsbase = evdns_base_new(ws_state.base, 1);
	if (!ws_state.dnsbase) {
		debug(LOG_ERR, "Failed to create DNS base");
		event_base_free(ws_state.base);
		return -1;
	}

	return 0;
}

/**
 * @brief Function prototype for a static function
 * @details This function is file-scoped (static) and returns an integer value
 * @return Returns an integer status code
 */
static int 
connect_ws_server(t_ws_server *ws_server)
{
	struct bufferevent *ws_bev = NULL;
	int max_retries = 5;
	int retry_count = 0;

	generate_sec_websocket_key(WS_KEY, sizeof(WS_KEY));
	generate_sec_websocket_accept(WS_KEY, WS_ACCEPT, sizeof(WS_ACCEPT));

	while (retry_count < max_retries) {
		ws_bev = create_ws_bufferevent();
		if (!ws_bev) {
			debug(LOG_ERR, "Failed to create bufferevent");
			sleep(1);
			retry_count++;
			continue;
		}

		int ret = bufferevent_socket_connect_hostname(
			ws_bev,
			ws_state.dnsbase,
			AF_INET,
			ws_server->hostname,
			ws_server->port
		);

		if (ret >= 0) {
			ws_state.upgraded = false;
			return 0;
		}

		debug(LOG_ERR, "Connection attempt %d failed: %s", 
			  retry_count + 1, strerror(errno));
		bufferevent_free(ws_bev);
		sleep(1);
		retry_count++;
	}

	return -1;
}

/**
 * @brief Starts the WebSocket server thread
 * 
 * This function initializes and starts a new thread dedicated to handling 
 * WebSocket connections. It sets up the necessary WebSocket server infrastructure
 * and begins listening for incoming client connections.
 *
 * @param arg Pointer to arguments passed to the thread (can be NULL)
 *
 * @return void
 *
 * @note This function runs in its own thread context
 */
void 
thread_websocket(void *arg)
{
	t_ws_server *ws_server = get_ws_server();
	if (!ws_server) {
		debug(LOG_ERR, "No WebSocket server configuration");
		return;
	}

	// Initialize SSL if needed
	if (ws_server->use_ssl) {
		if (setup_ssl(ws_server->hostname) < 0) {
			debug(LOG_ERR, "SSL setup failed");
			return;
		}
	}

	// Setup event and DNS bases
	if (setup_event_bases() < 0) {
		debug(LOG_ERR, "Event base setup failed");
		goto cleanup;
	}

	// Connect to WebSocket server
	if (connect_ws_server(ws_server) < 0) {
		debug(LOG_ERR, "Failed to connect to WebSocket server");
		goto cleanup;
	}

	debug(LOG_DEBUG, "WebSocket thread started");
	event_base_dispatch(ws_state.base);

cleanup:
	if (ws_state.base) event_base_free(ws_state.base);
	if (ws_state.dnsbase) evdns_base_free(ws_state.dnsbase, 0);
	if (ssl_state.ssl) SSL_free(ssl_state.ssl);
	if (ssl_state.ctx) SSL_CTX_free(ssl_state.ctx);
}
