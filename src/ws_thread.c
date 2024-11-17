
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

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

#define MAX_OUTPUT (512*1024)
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static struct event_base *ws_base;
static struct evdns_base *ws_dnsbase;
static struct event *ws_heartbeat_ev;
static char *fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
static char *fixed_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
static bool upgraded = false;

static SSL_CTX *ssl_ctx = NULL;
static SSL *ssl = NULL;

static void ws_heartbeat_cb(evutil_socket_t , short , void *);
static void wsevent_connection_cb(struct bufferevent* , short , void *);

static void
handle_kickoff_response(json_object *j_auth)
{
	json_object *client_ip = json_object_object_get(j_auth, "client_ip");
	json_object *client_mac = json_object_object_get(j_auth, "client_mac");
	json_object *device_id = json_object_object_get(j_auth, "device_id");
	json_object *gw_id = json_object_object_get(j_auth, "gw_id");
	if(client_ip == NULL || client_mac == NULL || device_id == NULL || gw_id == NULL){
		debug(LOG_ERR, "kickoff: parse json data failed\n");
		return;
	}

	const char *client_ip_str = json_object_get_string(client_ip);
	const char *client_mac_str = json_object_get_string(client_mac);
	const char *device_id_str = json_object_get_string(device_id);
	const char *gw_id_str = json_object_get_string(gw_id);
	t_client *client = client_list_find(client_ip_str, client_mac_str);
	if (client == NULL) {
		debug(LOG_ERR, "kickoff: client %s %s not found\n", client_ip_str, client_mac_str);
		return;
	}
	
	if (get_device_id() == NULL || strcmp(get_device_id(), device_id_str) != 0) {
		debug(LOG_ERR, "kickoff: device_id %s not match\n", device_id_str);
		return;
	}

	if (client->gw_setting == NULL || strcmp(client->gw_setting->gw_id, gw_id_str) != 0) {
		debug(LOG_ERR, "kickoff: client %s %s gw_id %s not match\n", client_ip_str, client_mac_str, gw_id_str);
		return;
	}

	LOCK_CLIENT_LIST();
	fw_deny(client);
	client_list_remove(client);
	client_free_node(client);
	UNLOCK_CLIENT_LIST();
}

static void
handle_auth_response(json_object *j_auth)
{
	json_object *token = json_object_object_get(j_auth, "token");
	json_object *client_ip = json_object_object_get(j_auth, "client_ip");
	json_object *client_mac = json_object_object_get(j_auth, "client_mac");
	json_object *client_name = json_object_object_get(j_auth, "client_name");
	json_object *gw_id = json_object_object_get(j_auth, "gw_id");
	json_object *once_auth = json_object_object_get(j_auth, "once_auth");
	if(token == NULL || client_ip == NULL || client_mac == NULL || gw_id == NULL || once_auth == NULL){
		debug(LOG_ERR, "auth: parse json data failed\n");
		return;
	}

	const char *gw_id_str = json_object_get_string(gw_id);
	const bool once_auth_bool = json_object_get_boolean(once_auth);
	if (once_auth_bool) {
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (gw_setting == NULL) {
			debug(LOG_ERR, "auth: gateway %s not found\n", gw_id_str);
			return;
		}
		gw_setting->auth_mode = 0;
		debug(LOG_DEBUG, 
			"auth: once_auth is true, update gw_setting's auth_mode [%d] and refresh gw rule\n", gw_setting->auth_mode);
		nft_reload_gw();
		return;
	}

	const char *token_str = json_object_get_string(token);
	const char *client_ip_str = json_object_get_string(client_ip);
	const char *client_mac_str = json_object_get_string(client_mac);
	if (client_list_find(client_ip_str, client_mac_str) == NULL)  {
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (gw_setting == NULL) {
			debug(LOG_ERR, "auth: gateway %s not found\n", gw_id_str);
			return;
		}
		LOCK_CLIENT_LIST();
		t_client *client = client_list_add(client_ip_str, client_mac_str, token_str, gw_setting);
		fw_allow(client, FW_MARK_KNOWN);
		if (client_name != NULL) {
			client->name = strdup(json_object_get_string(client_name));
		}
		client->first_login = time(NULL);
		client->is_online = 1;
		UNLOCK_CLIENT_LIST();
		{
			LOCK_OFFLINE_CLIENT_LIST();
			t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
			if(o_client)
				offline_client_list_delete(o_client);
			UNLOCK_OFFLINE_CLIENT_LIST();
		}
		debug(LOG_DEBUG, "fw_allow client: token %s, client_ip %s, client_mac %s gw_setting is %lu\n", 
			token_str, client_ip_str, client_mac_str, client->gw_setting);
	} else {
		debug(LOG_DEBUG, "client already exists: token %s, client_ip %s, client_mac %s\n", token_str, client_ip_str, client_mac_str);
	}
}

static void
handle_tmp_pass_response(json_object *j_tmp_pass)
{
	json_object *client_mac = json_object_object_get(j_tmp_pass, "client_mac");
	json_object *timeout = json_object_object_get(j_tmp_pass, "timeout");
	if(client_mac == NULL){
		debug(LOG_ERR, "temp_pass: parse json data failed\n");
		return;
	}

	const char *client_mac_str = json_object_get_string(client_mac);
	uint32_t timeout_value = 5*60;
	if (timeout != NULL) {
		timeout_value = json_object_get_int(timeout);
	}
	fw_set_mac_temporary(client_mac_str, timeout_value);
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
		nft_reload_gw();
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
	if (ws_heartbeat_ev != NULL) {
		event_free(ws_heartbeat_ev);
		ws_heartbeat_ev = NULL;
	}

	// Set 60 second interval
	struct timeval tv = {
		.tv_sec = 60,
		.tv_usec = 0
	};

	// Create persistent timer event
	ws_heartbeat_ev = event_new(ws_base, -1, EV_PERSIST, ws_heartbeat_cb, b_ws);
	if (ws_heartbeat_ev) {
		event_add(ws_heartbeat_ev, &tv);
	}
}

/**
 * Process incoming WebSocket messages
 *
 * Parses and handles JSON messages received over WebSocket. Supported message types:
 * - heartbeat: Gateway status updates
 * - connect: Initial connection response
 * - auth: Client authentication response
 * - kickoff: Client disconnection request
 * - tmp_pass: Temporary client access grant
 *
 * @param msg The JSON message string to process
 */
static void
process_ws_msg(const char *msg)
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
ws_send(struct evbuffer *buf, const char *msg, const size_t len)
{
	// Frame header byte 1: FIN=1, RSV1-3=0, Opcode=0x1 (text)
	uint8_t header1 = 0x81; // 1000 0001

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
	uint8_t mask_key[4] = {1, 2, 3, 4};
	evbuffer_add(buf, mask_key, 4);

	// Mask and write payload
	uint8_t masked_byte;
	for (size_t i = 0; i < len; i++) {
		masked_byte = msg[i] ^ mask_key[i % 4];
		evbuffer_add(buf, &masked_byte, 1);
	}
}

/**
 * Process received WebSocket frame
 *
 * Parses and handles an incoming WebSocket frame according to RFC 6455:
 * - Validates frame header and length fields
 * - Handles message fragmentation
 * - Unmasks payload if masked
 * - Processes text frame payloads
 *
 * @param data Raw frame data buffer
 * @param data_len Length of data buffer
 */
static void 
ws_receive(unsigned char *data, const size_t data_len)
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
	if (opcode == 0x01) {
		const char *msg = (const char *)(data + header_len);
		process_ws_msg(msg);
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

	// Build HTTP request headers
	const char *scheme = ws_server->use_ssl ? "https" : "http";
	
	// Required WebSocket headers
	evbuffer_add_printf(out, 
		"GET %s HTTP/1.1\r\n"
		"Host: %s:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Origin: %s://%s:%d\r\n"
		"\r\n",
		ws_server->path,
		ws_server->hostname, ws_server->port,
		fixed_key,
		scheme, ws_server->hostname, ws_server->port
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
	
	ws_send(out, json_str, strlen(json_str));
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
	if (!upgraded) {
		// Wait for complete HTTP response
		if (!strstr((const char*)data, "\r\n\r\n")) {
			debug(LOG_DEBUG, "Incomplete HTTP response");
			return;
		}

		// Verify upgrade response
		if (strncmp((const char*)data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0 
			|| !strstr((const char*)data, fixed_accept)) {
			debug(LOG_ERR, "Invalid WebSocket upgrade response");
			return;
		}

		debug(LOG_DEBUG, "WebSocket upgrade successful");
		upgraded = true;

		// Send initial connect message
		struct evbuffer *output = bufferevent_get_output(b_ws);
		send_msg(output, "connect");

		// Start heartbeat timer
		start_ws_heartbeat(b_ws);
		return;
	}

	// Process WebSocket frames after upgrade
	ws_receive(data, total_len);
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
	t_ws_server *ws_server = get_ws_server();
	struct bufferevent *bev = NULL;

	// Create bufferevent with SSL if needed
	if (ws_server->use_ssl) {
		bev = bufferevent_openssl_socket_new(
			ws_base,
			-1,
			ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
		);
	} else {
		bev = bufferevent_socket_new(
			ws_base,
			-1,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
		);
	}

	if (!bev) {
		return NULL;
	}

	// Configure bufferevent settings
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
	bufferevent_setcb(bev, ws_read_cb, NULL, wsevent_connection_cb, NULL);
	bufferevent_enable(bev, EV_READ | EV_WRITE);

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
	// Handle successful connection
	if (events & BEV_EVENT_CONNECTED) {
		debug(LOG_DEBUG, "Connected to WebSocket server, initiating handshake");
		ws_request(b_ws);
		return;
	}

	// Handle connection errors and EOF
	if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
		debug(LOG_ERR, "WebSocket connection error: %s", strerror(errno));

		// Stop heartbeat timer
		if (ws_heartbeat_ev) {
			event_free(ws_heartbeat_ev);
			ws_heartbeat_ev = NULL;
		}

		// Add delay before reconnect attempt
		// Longer delay on EOF (reset by peer)
		sleep((events & BEV_EVENT_EOF) ? 5 : 2);

		// Clean up existing connection
		if (b_ws) {
			bufferevent_free(b_ws);
		}

		// Attempt reconnection
		b_ws = create_ws_bufferevent();
		upgraded = false;

		int ret = bufferevent_socket_connect_hostname(b_ws, ws_dnsbase, AF_INET,
													get_ws_server()->hostname,
													get_ws_server()->port);
		if (ret < 0) {
			debug(LOG_ERR, "Reconnection failed: %s", strerror(errno));
			bufferevent_free(b_ws);
		}
		return;
	}

	// Handle other unexpected events
	debug(LOG_ERR, "Unexpected WebSocket event: %s", strerror(errno));
}

/**
 * Initialize and start the WebSocket client thread
 * 
 * This function:
 * - Sets up SSL/TLS context and connection
 * - Creates libevent bases for events and DNS
 * - Establishes WebSocket connection to server
 * - Runs the event loop
 *
 * @param arg Unused argument (required by thread API)
 */
void
start_ws_thread(void *arg) 
{
	t_ws_server *ws_server = get_ws_server();

	// Initialize SSL
	if (!RAND_poll()) {
		termination_handler(0);
	}

	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		termination_handler(0);
	}

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		termination_handler(0);
	}

	// Set SSL SNI hostname
	if (!SSL_set_tlsext_host_name(ssl, ws_server->hostname)) {
		debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
		termination_handler(0);
	}

	// Setup event bases
	ws_base = event_base_new();
	if (ws_base == NULL) {
		debug(LOG_ERR, "Failed to create event base");
		termination_handler(0);
	}

	ws_dnsbase = evdns_base_new(ws_base, 1);
	if (ws_dnsbase == NULL) {
		debug(LOG_ERR, "Failed to create DNS base");
		termination_handler(0);
	}

	// Connect to WebSocket server with retry
	struct bufferevent *ws_bev = NULL;
	while (1) {
		ws_bev = create_ws_bufferevent();
		int ret = bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET,
													ws_server->hostname, 
													ws_server->port);
		upgraded = false;
		
		if (ret < 0) {
			debug(LOG_ERR, "Connection failed: %s", strerror(errno));
			bufferevent_free(ws_bev);
			sleep(1);
		} else {
			break;
		}
	}

	debug(LOG_DEBUG, "WebSocket thread started");
	event_base_dispatch(ws_base);

	// Cleanup
	if (ws_base) event_base_free(ws_base);
	if (ws_dnsbase) evdns_base_free(ws_dnsbase, 0);
	if (ws_bev) bufferevent_free(ws_bev);
	if (ssl) SSL_free(ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
}

/**
 * Stop the WebSocket client thread
 * 
 * Forces the event loop to exit, triggering cleanup
 */
void
stop_ws_thread()
{
	event_base_loopexit(ws_base, NULL);
}
