
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For calloc and free

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
#include "safe.h"
#include "wdctlx_thread.h"
#include "ping_thread.h"
#include "api_handlers.h"
#include "wd_util.h"

/**
 * Global WebSocket connection state
 */
static struct {
	struct event_base *base;      /* Main event loop base */
	struct evdns_base *dnsbase;   /* DNS resolver base */
	struct event *heartbeat_ev;   /* Heartbeat timer event */
	struct event *control_ev;     /* Internal control timer event */
	bool upgraded;                /* WebSocket upgrade completed flag */
	struct bufferevent *current_bev; /* Current active bufferevent */
} ws_state = {
	.base = NULL,
	.dnsbase = NULL, 
	.heartbeat_ev = NULL,
	.control_ev = NULL,
	.upgraded = false,
	.current_bev = NULL
};

static _Atomic int ws_reconnect_requested = 0;

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

static char WS_KEY[WS_KEY_LEN+1];
static char WS_ACCEPT[WS_ACCEPT_LEN+1];

/* Forward declarations for callback functions */
static void ws_heartbeat_cb(evutil_socket_t fd, short events, void *arg);
static void wsevent_connection_cb(struct bufferevent *bev, short events, void *ctx);
static void ws_control_cb(evutil_socket_t fd, short events, void *arg);

static void cleanup_ws_connection(void);
static void reconnect_websocket(void);
static void scheduled_reconnect_cb(evutil_socket_t fd, short events, void *arg);

static void
start_ws_control_timer(void)
{
	if (!ws_state.base) {
		return;
	}

	if (ws_state.control_ev) {
		event_free(ws_state.control_ev);
		ws_state.control_ev = NULL;
	}

	struct timeval tv = {
		.tv_sec = 1,
		.tv_usec = 0
	};

	ws_state.control_ev = event_new(ws_state.base, -1, EV_PERSIST, ws_control_cb, NULL);
	if (ws_state.control_ev) {
		event_add(ws_state.control_ev, &tv);
	}
}


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

	// EVP_EncodeBlock always adds padding and null terminator
	// For 16 bytes input, it produces 24 bytes + null terminator = 25 bytes total
	int encoded_len = EVP_EncodeBlock((unsigned char *)key, rand_bytes, sizeof(rand_bytes));
	
	// Verify the encoding was successful and length is as expected
	if (encoded_len != 24) {
		debug(LOG_ERR, "Unexpected Base64 encoding length: %d (expected 24)", encoded_len);
		key[0] = '\0';  // Clear the buffer on error
		return;
	}
	
	// EVP_EncodeBlock automatically null-terminates, but ensure it's within bounds
	if (key[24] != '\0') {
		debug(LOG_WARNING, "Base64 encoding not properly null-terminated");
		key[24] = '\0';  // Force null termination
	}

	debug(LOG_DEBUG, "Generated WebSocket key: %s", key);
}

/**
 * @brief Callback function for scheduled reconnection attempts.
 *
 * This function is triggered by a timer event after a connection failure.
 * It calls reconnect_websocket() to attempt a new connection and then
 * frees the timer event structure itself.
 *
 * @param fd Unused socket descriptor.
 * @param events Unused event flags.
 * @param arg Pointer to the timer event structure that triggered this callback.
 */
static void scheduled_reconnect_cb(evutil_socket_t fd, short events, void *arg)
{
	struct event *timer_event_ptr = (struct event *)arg;

	debug(LOG_DEBUG, "Scheduled reconnect triggered via timer.");
	reconnect_websocket();

	// Use event_free() instead of free() for events created with event_new()
	if (timer_event_ptr) {
		event_free(timer_event_ptr);
	}
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
	// Validate input parameters
	if (!key || !accept || length < 29) {
		debug(LOG_ERR, "Invalid parameters for WebSocket accept generation");
		if (accept && length > 0) accept[0] = '\0';
		return;
	}

	// Concatenate WebSocket key with WebSocket GUID
	char key_guid[64];
	int ret = snprintf(key_guid, sizeof(key_guid), "%s%s", key, WS_GUID);
	
	// Check for truncation or error
	if (ret < 0 || ret >= sizeof(key_guid)) {
		debug(LOG_ERR, "WebSocket key concatenation failed or truncated: ret=%d", ret);
		accept[0] = '\0';
		return;
	}

	// Calculate SHA1 hash of concatenated key
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	SHA1((const unsigned char *)key_guid, strlen(key_guid), sha1_hash);

	// Base64 encode the SHA1 hash
	// Base64 encoding of 20 bytes will produce exactly 28 bytes plus null terminator
	if (length < 29) {
		debug(LOG_ERR, "Buffer too small for WebSocket accept token");
		return;
	}

	int encoded_len = EVP_EncodeBlock((unsigned char *)accept, sha1_hash, SHA_DIGEST_LENGTH);
	
	// Verify the encoding was successful and length is as expected
	if (encoded_len != 28) {
		debug(LOG_ERR, "Unexpected Base64 encoding length: %d (expected 28)", encoded_len);
		accept[0] = '\0';  // Clear the buffer on error
		return;
	}

	// EVP_EncodeBlock automatically null-terminates, but ensure it's within bounds
	if (accept[28] != '\0') {
		debug(LOG_WARNING, "Base64 encoding not properly null-terminated");
		accept[28] = '\0';  // Force null termination
	}

	debug(LOG_DEBUG, "Generated WebSocket accept token: %s", accept);
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
 * @brief Processes incoming WebSocket messages using unified API routing.
 *
 * Parses and handles JSON messages received over WebSocket. Uses the unified
 * API routing table to dispatch messages to appropriate handlers based on their
 * "type" field.
 * 
 * All message types are handled through api_dispatch_request() which uses the
 * same routing table as MQTT for consistency.
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

	// Create transport context for WebSocket
	api_transport_context_t *transport = create_websocket_transport_context(bev);
	if (!transport) {
		debug(LOG_ERR, "Failed to create WebSocket transport context");
		json_object_put(jobj);
		return;
	}

	// Get message type string
	const char *type_str = json_object_get_string(type);
	if (!type_str) {
		debug(LOG_ERR, "Invalid message type in JSON (null string)");
		destroy_transport_context(transport);
		json_object_put(jobj);
		return;
	}

	debug(LOG_DEBUG, "Processing WebSocket message type: %s", type_str);

	// Route to handler using unified API dispatch
	if (!api_dispatch_request(type_str, jobj, transport)) {
		debug(LOG_ERR, "Unknown WebSocket message type: %s", type_str);
	}

	// Clean up transport context and JSON
	destroy_transport_context(transport);
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
void 
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

	// Add masking key and masked payload - use secure random generator
	uint8_t mask_key[4];
	if (!RAND_bytes(mask_key, sizeof(mask_key))) {
		// Fallback to less secure but still better than rand()
		debug(LOG_WARNING, "OpenSSL RAND_bytes failed, using fallback");
		for (int i = 0; i < 4; i++) {
			mask_key[i] = rand() & 0xFF;
		}
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

	// Process frames based on opcode
	switch (opcode) {
	case TEXT_FRAME: {
		const char *msg = (const char *)(data + header_len);
		
		// Validate payload length to prevent integer overflow and excessive allocation
		if (payload_len > SIZE_MAX - 1 || payload_len > 1024 * 1024) {  // 1MB limit
			debug(LOG_ERR, "WebSocket payload too large: %llu bytes", (unsigned long long)payload_len);
			break;
		}
		
		// Ensure null termination for safety, though payload_len should be accurate
		char *safe_msg = calloc(1, (size_t)payload_len + 1);
		if (safe_msg) {
			memcpy(safe_msg, msg, (size_t)payload_len);
			safe_msg[payload_len] = '\0';
			process_ws_msg(bev, safe_msg);
			free(safe_msg);
		} else {
			debug(LOG_ERR, "Failed to allocate memory for message buffer in ws_receive");
		}
		break;
	}
	case BINARY_FRAME:
		// Handle binary data frames
		debug(LOG_DEBUG, "Received binary frame with %llu bytes", (unsigned long long)payload_len);
		// Binary frames are not currently supported in this implementation
		debug(LOG_WARNING, "Binary frames not supported, ignoring");
		break;
		
	case PING_FRAME: {
		// Respond to ping with pong frame containing same payload
		debug(LOG_DEBUG, "Received ping frame, sending pong response");
		struct evbuffer *out = bufferevent_get_output(bev);
		
		// Validate ping payload length to prevent excessive allocation
		if (payload_len > 125) {  // RFC 6455: control frames must not exceed 125 bytes
			debug(LOG_ERR, "Ping frame payload too large: %llu bytes (max 125)", (unsigned long long)payload_len);
			ws_send(out, "", 0, PONG_FRAME);
			break;
		}
		
		if (payload_len > 0) {
			// Echo back the ping payload in pong response
			char *ping_data = malloc((size_t)payload_len);
			if (ping_data) {
				memcpy(ping_data, data + header_len, (size_t)payload_len);
				ws_send(out, ping_data, (size_t)payload_len, PONG_FRAME);
				free(ping_data);
			} else {
				debug(LOG_ERR, "Failed to allocate memory for ping data");
				ws_send(out, "", 0, PONG_FRAME);
			}
		} else {
			ws_send(out, "", 0, PONG_FRAME);
		}
		break;
	}
	case PONG_FRAME:
		// Handle pong response (usually in response to our ping)
		debug(LOG_DEBUG, "Received pong frame with %llu bytes", (unsigned long long)payload_len);
		// Pong frames are typically used for keep-alive, no action needed
		break;
		
	case CLOSING_FRAME: {
		// Handle connection close frame
		debug(LOG_DEBUG, "Received close frame, initiating connection closure");
		
		// Extract close code and reason if present
		uint16_t close_code = 1000; // Normal closure
		const char *close_reason = "";
		
		if (payload_len >= 2) {
			close_code = ntohs(*(uint16_t*)(data + header_len));
			if (payload_len > 2) {
				close_reason = (const char*)(data + header_len + 2);
			}
		}
		
		debug(LOG_DEBUG, "Close code: %u, reason: %.100s", close_code, close_reason);
		
		// Send close frame acknowledgment
		struct evbuffer *out = bufferevent_get_output(bev);
		uint16_t close_response = htons(1000); // Normal closure
		ws_send(out, (const char*)&close_response, 2, CLOSING_FRAME);
		
		// Clean up connection
		cleanup_ws_connection();
		break;
	}
	case 0x0:
		// Continuation frame - handle fragmented messages
		debug(LOG_DEBUG, "Received continuation frame with %llu bytes", (unsigned long long)payload_len);
		// For now, continuation frames are not fully supported
		debug(LOG_WARNING, "Continuation frames not fully supported, ignoring");
		break;
		
	default:
		// Handle unknown/unsupported opcodes
		debug(LOG_ERR, "Unsupported WebSocket opcode: 0x%x", opcode);
		
		// Send close frame with unsupported data error code
		struct evbuffer *out = bufferevent_get_output(bev);
		uint16_t close_code = htons(1003); // Unsupported data
		ws_send(out, (const char*)&close_code, 2, CLOSING_FRAME);
		break;
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
 * - Device info object (if available) containing:
 *   - ap_device_id: Access Point Device ID
 *   - ap_mac_address: Access Point MAC Address
 *   - ap_longitude: Access Point GPS longitude coordinate
 *   - ap_latitude: Access Point GPS latitude coordinate
 *   - location_id: Location identifier
 * - Array of gateway configurations including:
 *   - Gateway ID, channel, IPv4/IPv6 addresses
 *   - Authentication mode and interface
 * - System info object (for heartbeat messages only) containing:
 *   - sys_uptime: System uptime in seconds
 *   - sys_memfree: Free memory in KB
 *   - sys_load: System load average
 *   - nf_conntrack_count: Netfilter connection tracking count
 *   - cpu_usage: CPU usage percentage
 *   - cpu_temp: CPU temperature in Celsius (-1 if unable to read)
 *   - wifidog_uptime: Wifidog process uptime in seconds
 *   - online_clients: Number of online clients
 *   - offline_clients: Number of offline clients
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

	// Add device info as an object if available
	t_device_info *device_info = get_device_info();
	if (device_info) {
		json_object *device_info_obj = json_object_new_object();
		
		if (device_info->ap_device_id) {
			json_object_object_add(device_info_obj, "ap_device_id", json_object_new_string(device_info->ap_device_id));
		}
		if (device_info->ap_mac_address) {
			json_object_object_add(device_info_obj, "ap_mac_address", json_object_new_string(device_info->ap_mac_address));
		}
		if (device_info->ap_longitude) {
			json_object_object_add(device_info_obj, "ap_longitude", json_object_new_string(device_info->ap_longitude));
		}
		if (device_info->ap_latitude) {
			json_object_object_add(device_info_obj, "ap_latitude", json_object_new_string(device_info->ap_latitude));
		}
		if (device_info->location_id) {
			json_object_object_add(device_info_obj, "location_id", json_object_new_string(device_info->location_id));
		}
		
		json_object_object_add(root, "device_info", device_info_obj);
	}

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

	// Add system information for heartbeat messages
	if (strcmp(type, "heartbeat") == 0) {
		struct sys_info info;
		memset(&info, 0, sizeof(info));
		get_sys_info(&info);
		
		// Create system info object
		json_object *sys_info_obj = json_object_new_object();
		
		// Add system uptime
		json_object_object_add(sys_info_obj, "sys_uptime", json_object_new_int64(info.sys_uptime));
		
		// Add system memory free (in KB)
		json_object_object_add(sys_info_obj, "sys_memfree", json_object_new_int64(info.sys_memfree));
		
		// Add system load average
		json_object_object_add(sys_info_obj, "sys_load", json_object_new_double(info.sys_load));
		
		// Add netfilter connection tracking count
		json_object_object_add(sys_info_obj, "nf_conntrack_count", json_object_new_int64(info.nf_conntrack_count));
		
		// Add CPU usage percentage
		json_object_object_add(sys_info_obj, "cpu_usage", json_object_new_double(info.cpu_usage));
		
		// Add CPU temperature (in Celsius, -1 if unable to read)
		json_object_object_add(sys_info_obj, "cpu_temp", json_object_new_int(info.cpu_temp));
		
		// Add wifidog uptime (calculated in ping_thread.c logic)
		extern time_t started_time;
		long wifidog_uptime = time(NULL) - started_time;
		if (wifidog_uptime > (long)info.sys_uptime) {
			wifidog_uptime = 0;  // Reset if inconsistent
		}
		json_object_object_add(sys_info_obj, "wifidog_uptime", json_object_new_int64(wifidog_uptime));
		
		// Add online and offline client counts
		extern int g_online_clients;
		json_object_object_add(sys_info_obj, "online_clients", json_object_new_int(g_online_clients));
		json_object_object_add(sys_info_obj, "offline_clients", json_object_new_int(offline_client_ageout()));
		
		// Add system info to root object
		json_object_object_add(root, "sys_info", sys_info_obj);
	}

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

static void
ws_control_cb(evutil_socket_t fd, short events, void *arg)
{
	(void)fd;
	(void)events;
	(void)arg;

	if (!ws_reconnect_requested) {
		return;
	}

	ws_reconnect_requested = 0;
	debug(LOG_INFO, "WebSocket reconnect requested by hotplugin event");
	cleanup_ws_connection();
	reconnect_websocket();
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

		// Mark auth server as online when WebSocket connection is established
		mark_auth_online();

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
	if (!ws_state.base) {
		debug(LOG_ERR, "create_ws_bufferevent: ws_state.base is NULL, cannot create bufferevent.");
		return NULL;
	}
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
		if (!ssl_state.ctx) {
			debug(LOG_ERR, "create_ws_bufferevent: ssl_state.ctx is NULL, cannot create SSL object for bufferevent.");
			return NULL;
		}
		// Create a new SSL object for this specific connection
		SSL *ssl = SSL_new(ssl_state.ctx);
		if (!ssl) {
			debug(LOG_ERR, "SSL_new() failed in create_ws_bufferevent");
			return NULL;
		}

		// Set SNI and verify it succeeds
		if (!SSL_set_tlsext_host_name(ssl, ws_server->hostname)) {
			debug(LOG_ERR, "SSL_set_tlsext_host_name failed in create_ws_bufferevent for hostname %s", ws_server->hostname);
			SSL_free(ssl);
			return NULL;
		}
		
		// Create SSL bufferevent
		bev = bufferevent_openssl_socket_new(
			ws_state.base,
			-1,
			ssl, // Pass the newly created and configured SSL object
			BUFFEREVENT_SSL_CONNECTING,
			options
		);
		
		// Check if bufferevent creation failed
		if (!bev) {
			debug(LOG_ERR, "bufferevent_openssl_socket_new() failed");
			SSL_free(ssl); // Clean up the SSL object if bufferevent creation failed
			return NULL;
		}
		
		// SSL object 'ssl' is now managed by the bufferevent,
		// and will be automatically freed when bufferevent_free() is called
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
		// Mark auth server as offline when WebSocket connection fails
		mark_auth_offline();
		
		// Get specific error details
		int err = bufferevent_socket_get_dns_error(b_ws);
		if (err) {
			debug(LOG_ERR, "WebSocket DNS error: %s", evutil_gai_strerror(err));
		} else {
			debug(LOG_ERR, "WebSocket connection error: %s", evutil_socket_error_to_string(errno));
		}

		// Only clean up heartbeat timer and reset state, don't free the bufferevent 
		// from within its own callback as that can cause segfaults
		if (ws_state.heartbeat_ev) {
			event_del(ws_state.heartbeat_ev);
			event_free(ws_state.heartbeat_ev);
			ws_state.heartbeat_ev = NULL;
		}
		ws_state.upgraded = false;

		// Calculate reconnect delay - longer for EOF
		int delay = (events & BEV_EVENT_EOF) ? 5 : 2;
		debug(LOG_DEBUG, "Attempting to schedule reconnection in %d seconds.", delay);

		if (ws_state.base) {
			struct timeval delay_tv;
			delay_tv.tv_sec = delay;
			delay_tv.tv_usec = 0;

			// Create timer event with callback that will handle its own cleanup
			struct event *reconnect_timer_ev_heap = event_new(ws_state.base, -1, 0, scheduled_reconnect_cb, NULL);
			if (reconnect_timer_ev_heap) {
				// Update the callback argument to point to the event itself so it can free itself
				event_assign(reconnect_timer_ev_heap, ws_state.base, -1, 0, scheduled_reconnect_cb, (void *)reconnect_timer_ev_heap);
				if (event_add(reconnect_timer_ev_heap, &delay_tv) == 0) {
					debug(LOG_DEBUG, "Successfully scheduled reconnection in %d seconds.", delay);
				} else {
					debug(LOG_ERR, "Failed to add reconnect timer event to pending list.");
					event_free(reconnect_timer_ev_heap);
				}
			} else {
				debug(LOG_ERR, "Failed to allocate memory for reconnect timer event.");
			}
		} else {
			debug(LOG_ERR, "ws_state.base is NULL. Cannot schedule reconnection.");
			// If ws_state.base is NULL, the thread is likely shutting down, so no reschedule.
		}
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
cleanup_ws_connection(void)
{
	// Mark auth server as offline when cleaning up WebSocket connection
	if (ws_state.upgraded) {
		mark_auth_offline();
	}

	// Stop heartbeat timer
	if (ws_state.heartbeat_ev) {
		event_del(ws_state.heartbeat_ev);
		event_free(ws_state.heartbeat_ev);
		ws_state.heartbeat_ev = NULL;
	}

	if (ws_state.control_ev) {
		event_del(ws_state.control_ev);
		event_free(ws_state.control_ev);
		ws_state.control_ev = NULL;
	}

	// Reset connection state
	ws_state.upgraded = false;

	// Free the bufferevent - this will automatically free any associated SSL object
	if (ws_state.current_bev) {
		bufferevent_free(ws_state.current_bev); // This will close the socket fd and free SSL
		ws_state.current_bev = NULL;
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
	// First, clean up any existing connection properly
	if (ws_state.current_bev) {
		// Disable callbacks to prevent them from firing during cleanup
		bufferevent_setcb(ws_state.current_bev, NULL, NULL, NULL, NULL);
		bufferevent_disable(ws_state.current_bev, EV_READ | EV_WRITE);
		
		// For SSL bufferevents, let bufferevent_free() handle SSL cleanup
		// Don't manually free SSL objects as it can cause double-free issues
		bufferevent_free(ws_state.current_bev);
		ws_state.current_bev = NULL;
	}

	struct bufferevent *bev = create_ws_bufferevent();
	if (!bev) {
		debug(LOG_ERR, "Failed to create new bufferevent for reconnection");
		return;
	}

	t_ws_server *server = get_ws_server();
	if (!server) {
		debug(LOG_ERR, "reconnect_websocket: WebSocket server configuration (server) is NULL. Aborting.");
		bufferevent_free(bev);
		return;
	}

	if (!ws_state.dnsbase) {
		debug(LOG_ERR, "reconnect_websocket: ws_state.dnsbase is NULL. Aborting reconnection attempt.");
		bufferevent_free(bev);
		return;
	}
	if (!server->hostname) {
		debug(LOG_ERR, "reconnect_websocket: WebSocket server hostname is NULL. Aborting.");
		bufferevent_free(bev);
		return;
	}

	// Set the new bufferevent before attempting connection
	ws_state.current_bev = bev;
	
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
		ws_state.current_bev = NULL;
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
setup_ssl(const char *hostname) // hostname parameter is no longer strictly needed here but can be kept for now
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

	// The SSL object (ssl_state.ssl) will be created per connection in create_ws_bufferevent.
	// The SSL_set_tlsext_host_name() will also be called there.

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
			ws_state.current_bev = ws_bev;
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

	start_ws_control_timer();

	// Connect to WebSocket server
	if (connect_ws_server(ws_server) < 0) {
		debug(LOG_ERR, "Failed to connect to WebSocket server");
		if (ws_state.base) {
			event_base_loopbreak(ws_state.base);
		}
		goto cleanup;
	}

	debug(LOG_DEBUG, "WebSocket thread started");
	event_base_dispatch(ws_state.base);

cleanup:
	cleanup_ws_connection(); /* Frees current_bev, its SSL, and heartbeat */
	if (ws_state.base) {
		event_base_free(ws_state.base);
		ws_state.base = NULL;
	}
	if (ws_state.dnsbase) {
		evdns_base_free(ws_state.dnsbase, 0);
		ws_state.dnsbase = NULL;
	}
	// ssl_state.ssl is no longer a global SSL object pointer;
	// individual SSL objects are freed in cleanup_ws_connection.
	if (ssl_state.ctx) {
		SSL_CTX_free(ssl_state.ctx);
		ssl_state.ctx = NULL;
	}
}

void
ws_request_reconnect(void)
{
	ws_reconnect_requested = 1;
}

