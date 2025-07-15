
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
#include "safe.h"
#include "wdctlx_thread.h"
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
	struct bufferevent *current_bev; /* Current active bufferevent */
} ws_state = {
	.base = NULL,
	.dnsbase = NULL, 
	.heartbeat_ev = NULL,
	.upgraded = false,
	.current_bev = NULL
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
static void handle_auth_request(json_object *j_auth);
static void handle_kickoff_request(json_object *j_auth, struct bufferevent *bev);
static void handle_get_firmware_info_request(json_object *j_req, struct bufferevent *bev);
static void handle_firmware_upgrade_request(json_object *j_req, struct bufferevent *bev);
static void handle_update_device_info_request(json_object *j_req, struct bufferevent *bev);
static void handle_sync_trusted_domain_request(json_object *j_req, struct bufferevent *bev);
static void handle_get_trusted_domains_request(json_object *j_req, struct bufferevent *bev);
static void handle_get_trusted_wildcard_domains_request(json_object *j_req, struct bufferevent *bev);
static void handle_sync_trusted_wildcard_domains_request(json_object *j_req, struct bufferevent *bev);
static void handle_reboot_device_request(json_object *j_req, struct bufferevent *bev);
static void handle_get_wifi_info_request(json_object *j_req, struct bufferevent *bev);
static void handle_set_wifi_info_request(json_object *j_req, struct bufferevent *bev);
static void cleanup_ws_connection(void);
static void reconnect_websocket(void);
static void scheduled_reconnect_cb(evutil_socket_t fd, short events, void *arg);
static void ws_send(struct evbuffer *buf, const char *msg, const size_t len, enum WebSocketFrameType frame_type);

/* Helper structure for Wi-Fi interface information */
struct wifi_interface_info {
    char interface_name[64];
    char device[16];
    char mode[16];
};

/* Helper function for setting Wi-Fi configuration */
static int set_radio_wifi_config(json_object *j_radio, const char *target_device,
                                 struct wifi_interface_info *interfaces, int interface_count);

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
 * @brief Handles a request for firmware upgrade.
 *
 * This function is called by process_ws_msg() when a "firmware_upgrade"
 * message is received. It processes firmware upgrade requests and provides
 * appropriate JSON responses based on the operation outcome.
 *
 * Request format:
 * {
 *   "type": "firmware_upgrade",
 *   "url": "<firmware_url>",      // Required: URL to firmware image
 *   "force": <boolean>            // Optional: Force upgrade without checks (default: false)
 * }
 *
 * Success response (sent before reboot):
 * {
 *   "type": "firmware_upgrade_response",
 *   "status": "success",
 *   "message": "Firmware upgrade initiated successfully"
 * }
 *
 * Error responses:
 * {
 *   "type": "firmware_upgrade_error",
 *   "error": "Missing or invalid 'url' field"
 * }
 * {
 *   "type": "firmware_upgrade_error", 
 *   "error": "Failed to execute sysupgrade command"
 * }
 *
 * @param j_req The incoming JSON request object containing upgrade parameters
 * @param bev The bufferevent associated with the WebSocket connection for responses
 */
static void handle_firmware_upgrade_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_url, *j_force;
    
    // Validate required URL field
    if (!json_object_object_get_ex(j_req, "url", &j_url) || !json_object_is_type(j_url, json_type_string)) {
        debug(LOG_ERR, "Firmware upgrade request missing or invalid 'url' field");
        json_object_object_add(j_response, "type", json_object_new_string("firmware_upgrade_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing or invalid 'url' field"));
        
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    const char *url_str = json_object_get_string(j_url);
    
    // Get optional force parameter
    bool force_upgrade = false;
    if (json_object_object_get_ex(j_req, "force", &j_force) && json_object_is_type(j_force, json_type_boolean)) {
        force_upgrade = json_object_get_boolean(j_force);
    }
    
    debug(LOG_INFO, "Firmware upgrade request received - URL: %s, Force: %s", 
          url_str, force_upgrade ? "true" : "false");

    // Construct sysupgrade command with appropriate flags
    char command[512];
    if (force_upgrade) {
        snprintf(command, sizeof(command), "sysupgrade -F %s", url_str);
    } else {
        snprintf(command, sizeof(command), "sysupgrade %s", url_str);
    }

    debug(LOG_INFO, "Executing firmware upgrade command: %s", command);

    // Execute the upgrade command
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute sysupgrade command: %s", command);
        
        // Send error response
        json_object_object_add(j_response, "type", json_object_new_string("firmware_upgrade_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to execute sysupgrade command"));
        
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    // Command executed successfully - send success response before potential reboot
    json_object_object_add(j_response, "type", json_object_new_string("firmware_upgrade_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Firmware upgrade initiated successfully"));
    
    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
    json_object_put(j_response);
    
    // Close the pipe - system will likely reboot during or after this
    pclose(fp);
    debug(LOG_INFO, "Firmware upgrade command executed successfully - system may reboot");
}

static void
handle_update_device_info_request(json_object *j_req, struct bufferevent *bev)
{
	json_object *j_response = json_object_new_object();
	json_object *j_device_info;

	if (!json_object_object_get_ex(j_req, "device_info", &j_device_info)) {
		debug(LOG_ERR, "Update device info request missing 'device_info' field");
		json_object_object_add(j_response, "type", json_object_new_string("update_device_info_error"));
		json_object_object_add(j_response, "error", json_object_new_string("Missing 'device_info' field"));
		const char *response_str = json_object_to_json_string(j_response);
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
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

	if (json_object_object_get_ex(j_device_info, "ap_device_id", &j_ap_device_id)) {
		const char *ap_device_id = json_object_get_string(j_ap_device_id);
		if (device_info->ap_device_id) free(device_info->ap_device_id);
		device_info->ap_device_id = safe_strdup(ap_device_id);
		uci_set_value("wifidogx", "common", "ap_device_id", ap_device_id);
	}
	if (json_object_object_get_ex(j_device_info, "ap_mac_address", &j_ap_mac_address)) {
		const char *ap_mac_address = json_object_get_string(j_ap_mac_address);
		if (device_info->ap_mac_address) free(device_info->ap_mac_address);
		device_info->ap_mac_address = safe_strdup(ap_mac_address);
		uci_set_value("wifidogx", "common", "ap_mac_address", ap_mac_address);
	}
	if (json_object_object_get_ex(j_device_info, "ap_longitude", &j_ap_longitude)) {
		const char *ap_longitude = json_object_get_string(j_ap_longitude);
		if (device_info->ap_longitude) free(device_info->ap_longitude);
		device_info->ap_longitude = safe_strdup(ap_longitude);
		uci_set_value("wifidogx", "common", "ap_longitude", ap_longitude);
	}
	if (json_object_object_get_ex(j_device_info, "ap_latitude", &j_ap_latitude)) {
		const char *ap_latitude = json_object_get_string(j_ap_latitude);
		if (device_info->ap_latitude) free(device_info->ap_latitude);
		device_info->ap_latitude = safe_strdup(ap_latitude);
		uci_set_value("wifidogx", "common", "ap_latitude", ap_latitude);
	}
	if (json_object_object_get_ex(j_device_info, "location_id", &j_location_id)) {
		const char *location_id = json_object_get_string(j_location_id);
		if (device_info->location_id) free(device_info->location_id);
		device_info->location_id = safe_strdup(location_id);
		uci_set_value("wifidogx", "common", "location_id", location_id);
	}

	json_object_object_add(j_response, "type", json_object_new_string("update_device_info_response"));
	json_object_object_add(j_response, "status", json_object_new_string("success"));
	json_object_object_add(j_response, "message", json_object_new_string("Device info updated successfully"));
	const char *response_str = json_object_to_json_string(j_response);
	ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
	json_object_put(j_response);
}

/**
 * @brief Handles request to synchronize trusted domains list.
 *
 * This function processes a WebSocket request to update the complete list of trusted domains.
 * It clears all existing trusted domains and replaces them with the new list provided.
 * Trusted domains allow network traffic to pass through without authentication.
 *
 * Request format:
 * {
 *   "type": "sync_trusted_domain",
 *   "domains": [
 *     "example.com",
 *     "trusted-site.org",
 *     "api.service.com"
 *   ]
 * }
 *
 * Success response:
 * {
 *   "type": "sync_trusted_domain_response",
 *   "status": "success", 
 *   "message": "Trusted domains synchronized successfully"
 * }
 *
 * The function performs the following operations:
 * 1. Clears all existing trusted domains from memory and UCI config
 * 2. Iterates through the provided domains array
 * 3. Adds each valid domain to the trusted domains list
 * 4. Updates UCI configuration for persistence
 * 5. Sends success response back to the client
 *
 * @param j_req The incoming JSON request object containing the domains array
 * @param bev The bufferevent associated with the WebSocket connection for sending response
 *
 * @note This operation completely replaces the existing trusted domains list
 * @note Domain validation is minimal - any string value in the array is accepted
 * @note Changes are immediately effective and persist across system reboots via UCI
 */
static void handle_sync_trusted_domain_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    // Clear existing trusted domains
    clear_trusted_domains();

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
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
    json_object_put(j_response);
}

/**
 * @brief Handles request to retrieve current trusted domains list.
 *
 * This function processes a WebSocket request to get the complete list of currently
 * configured trusted domains. Trusted domains are exact domain matches that allow
 * network traffic to pass through without user authentication.
 *
 * Request format:
 * {
 *   "type": "get_trusted_domains"
 * }
 *
 * Response format:
 * {
 *   "type": "get_trusted_domains_response",
 *   "domains": [
 *     "example.com",
 *     "api.service.com",
 *     "cdn.provider.net"
 *   ]
 * }
 *
 * The function:
 * 1. Creates a new JSON response object
 * 2. Iterates through the linked list of trusted domains
 * 3. Adds each domain name to the response array
 * 4. Sends the complete list back to the client
 *
 * @param j_req The incoming JSON request object (content not used for this request type)
 * @param bev The bufferevent associated with the WebSocket connection for sending response
 *
 * @note Returns an empty array if no trusted domains are configured
 * @note Domain order in response may not match configuration order
 */
static void handle_get_trusted_domains_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
    json_object_put(j_response);
}

/**
 * @brief Handles request to retrieve current trusted wildcard domains list.
 *
 * This function processes a WebSocket request to get the complete list of currently
 * configured trusted wildcard domains. Wildcard domains use pattern matching to allow
 * traffic to multiple subdomains (e.g., "*.example.com" matches "api.example.com", 
 * "cdn.example.com", etc.).
 *
 * Request format:
 * {
 *   "type": "get_trusted_wildcard_domains"
 * }
 *
 * Response format:
 * {
 *   "type": "get_trusted_wildcard_domains_response",
 *   "domains": [
 *     "*.googleapis.com",
 *     "*.cloudflare.com", 
 *     "*.github.io"
 *   ]
 * }
 *
 * The function:
 * 1. Creates a new JSON response object and domains array
 * 2. Retrieves the linked list of trusted wildcard domains
 * 3. Iterates through each wildcard domain entry
 * 4. Adds each domain pattern to the response array
 * 5. Sends the complete list back to the client
 *
 * @param j_req The incoming JSON request object (content not used for this request type)  
 * @param bev The bufferevent associated with the WebSocket connection for sending response
 *
 * @note Returns an empty array if no wildcard domains are configured
 * @note Wildcard patterns typically use "*." prefix for subdomain matching
 * @note Domain order in response may not match configuration order
 */
static void handle_get_trusted_wildcard_domains_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_pan_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
    json_object_put(j_response);
}

/**
 * @brief Handles request to synchronize trusted wildcard domains list.
 *
 * This function processes a WebSocket request to update the complete list of trusted
 * wildcard domains. It clears all existing wildcard domains and replaces them with
 * the new list provided. Wildcard domains allow pattern-based domain matching,
 * typically using "*." prefix to match all subdomains.
 *
 * Request format:
 * {
 *   "type": "sync_trusted_wildcard_domains",
 *   "domains": [
 *     "*.googleapis.com",
 *     "*.cloudflare.com",
 *     "*.github.io",
 *     "*.example.org"
 *   ]
 * }
 *
 * Success response:
 * {
 *   "type": "sync_trusted_wildcard_domains_response",
 *   "status": "success",
 *   "message": "Trusted wildcard domains synchronized successfully"
 * }
 *
 * The function performs the following operations:
 * 1. Clears all existing trusted wildcard domains from memory and UCI config
 * 2. Validates the incoming request contains a domains array
 * 3. Iterates through each domain pattern in the array
 * 4. Adds each valid wildcard domain to the trusted list
 * 5. Updates UCI configuration for system persistence
 * 6. Sends success response back to the client
 *
 * Examples of wildcard domain patterns:
 * - "*.example.com" - matches api.example.com, cdn.example.com, etc.
 * - "*.github.io" - matches username.github.io, project.github.io, etc.
 * - "*.googleapis.com" - matches maps.googleapis.com, fonts.googleapis.com, etc.
 *
 * @param j_req The incoming JSON request object containing the wildcard domains array
 * @param bev The bufferevent associated with the WebSocket connection for sending response
 *
 * @note This operation completely replaces the existing wildcard domains list
 * @note Pattern validation is minimal - any string value in the array is accepted
 * @note Changes take effect immediately and persist across system reboots via UCI
 * @note Wildcard matching depends on the underlying domain resolution implementation
 */
static void handle_sync_trusted_wildcard_domains_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    // Clear existing trusted domains
    clear_trusted_pan_domains();

    if (json_object_object_get_ex(j_req, "domains", &j_domains) && json_object_is_type(j_domains, json_type_array)) {
        int array_len = json_object_array_length(j_domains);
        for (int i = 0; i < array_len; i++) {
            json_object *j_domain = json_object_array_get_idx(j_domains, i);
            if (json_object_is_type(j_domain, json_type_string)) {
                const char *domain_str = json_object_get_string(j_domain);
                add_trusted_pan_domains(domain_str);
                uci_add_list_value("wifidogx", "common", "trusted_wildcard_domains", domain_str);
            }
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted wildcard domains synchronized successfully"));
    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
    json_object_put(j_response);
}

/**
 * @brief Handles a request to reboot the device.
 *
 * This function is called by process_ws_msg() when a "reboot_device"
 * message is received. It executes the system reboot command to restart
 * the device. This is typically used for remote device management,
 * firmware updates, or configuration changes that require a restart.
 *
 * Request format:
 * {
 *   "type": "reboot_device"
 * }
 *
 * Success behavior:
 * - Device immediately begins reboot process
 * - No response is sent back as the device shuts down
 * - WebSocket connection is terminated by system shutdown
 *
 * Error response (if reboot command fails):
 * {
 *   "type": "reboot_device_error",
 *   "error": "Failed to execute reboot command"
 * }
 *
 * Security considerations:
 * - This is a privileged operation that should only be allowed for
 *   authenticated and authorized management connections
 * - The reboot command requires root privileges to execute
 * - All running processes and network connections will be terminated
 *
 * Implementation details:
 * - Uses system("reboot") to trigger immediate device restart
 * - On success, the device will shut down within seconds
 * - All unsaved data and active connections will be lost
 * - Boot process follows normal system startup sequence
 *
 * @param j_req The incoming JSON request object. The request content is not
 *              used for this operation as no parameters are required, but
 *              the parameter is included for API consistency across handlers.
 * @param bev The bufferevent associated with the WebSocket connection, used
 *            for sending error responses if the reboot command fails.
 *
 * @note This function will cause the device to restart immediately on success
 * @note Use with caution as it will interrupt all ongoing operations
 * @note The WebSocket connection will be forcibly closed during reboot
 */
static void handle_reboot_device_request(json_object *j_req, struct bufferevent *bev) {
    debug(LOG_INFO, "Reboot device request received");

	// Execute the reboot command
	if (system("reboot") != 0) {
		debug(LOG_ERR, "Failed to execute reboot command");
		// Optionally, send an error response back to the client
		json_object *j_response = json_object_new_object();
		json_object_object_add(j_response, "type", json_object_new_string("reboot_device_error"));
		json_object_object_add(j_response, "error", json_object_new_string("Failed to execute reboot command"));
		const char *response_str = json_object_to_json_string(j_response);
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
		json_object_put(j_response);
		return;
	}

	// No response sent back as the device will reboot immediately
	debug(LOG_INFO, "Device is rebooting now");
}

/**
 * @brief Handles a request to get Wi-Fi information.
 *
 * This function is called by process_ws_msg() when a "get_wifi_info"
 * message is received. It executes the command "uci show wireless"
 * to retrieve Wi-Fi details, parses the output, and sends
 * this information back to the client in a JSON response.
 *
 * The function extracts 2.4G and 5G radio information including:
 * - SSID and Key from AP interfaces (mode='ap')
 * - Mesh ID and Mesh Key from mesh interfaces (mode='mesh')
 * - Supports any interface names, not just default_radio0/1
 *
 * The JSON response format is:
 * {
 *   "type": "get_wifi_info_response",
 *   "data": {
 *     "radio0": {
 *       "ssid": "OpenWrt_2G",
 *       "key": "password123",
 *       "mesh_id": "mesh_network_2g",
 *       "mesh_key": "mesh_password123"
 *     },
 *     "radio1": {
 *       "ssid": "OpenWrt_5G", 
 *       "key": "password123",
 *       "mesh_id": "mesh_network_5g",
 *       "mesh_key": "mesh_password123"
 *     }
 *   }
 * }
 *
 * If the command execution fails, an error response is sent:
 * {
 *   "type": "get_wifi_info_error",
 *   "error": "Failed to execute command"
 * }
 *
 * @param j_req The incoming JSON request object. Currently unused for this
 *              specific request type but included for API consistency.
 * @param bev The bufferevent associated with the WebSocket connection, used
 *            for sending the response.
 */
static void handle_get_wifi_info_request(json_object *j_req, struct bufferevent *bev) {
    FILE *fp;
    char buffer[512];
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    json_object *j_radio0 = json_object_new_object();
    json_object *j_radio1 = json_object_new_object();

    // Temporary storage for interface information
    struct {
        char *device;
        char *mode;
        char *ssid;
        char *key;
        char *mesh_id;
    } interfaces[32];
    int interface_count = 0;

    // Execute command
    fp = popen("uci show wireless", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to run command uci show wireless");
        json_object_object_add(j_response, "type", json_object_new_string("get_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to execute command"));
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    // Initialize interface storage
    memset(interfaces, 0, sizeof(interfaces));

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

            // Parse interface information
            // Format: wireless.<interface_name>.<option>
            if (strstr(key, "wireless.") == key) {
                char *key_copy = strdup(key);
                char *parts[4];
                int part_count = 0;
                
                char *token = strtok(key_copy, ".");
                while (token && part_count < 4) {
                    parts[part_count++] = token;
                    token = strtok(NULL, ".");
                }

                if (part_count >= 3) {
                    char *interface_name = parts[1];
                    char *option = parts[2];

                    // Find or create interface entry
                    int idx = -1;
                    for (int i = 0; i < interface_count; i++) {
                        if (interfaces[i].device && strcmp(interfaces[i].device, interface_name) == 0) {
                            idx = i;
                            break;
                        }
                    }
                    if (idx == -1 && interface_count < 32) {
                        idx = interface_count++;
                        interfaces[idx].device = strdup(interface_name);
                    }

                    if (idx >= 0) {
                        if (strcmp(option, "device") == 0) {
                            // Skip device lines, we care about wifi-iface sections
                        } else if (strcmp(option, "mode") == 0) {
                            if (interfaces[idx].mode) free(interfaces[idx].mode);
                            interfaces[idx].mode = (strlen(value) > 0) ? strdup(value) : NULL;
                        } else if (strcmp(option, "ssid") == 0) {
                            if (interfaces[idx].ssid) free(interfaces[idx].ssid);
                            interfaces[idx].ssid = (strlen(value) > 0) ? strdup(value) : NULL;
                        } else if (strcmp(option, "key") == 0) {
                            if (interfaces[idx].key) free(interfaces[idx].key);
                            interfaces[idx].key = (strlen(value) > 0) ? strdup(value) : NULL;
                        } else if (strcmp(option, "mesh_id") == 0) {
                            if (interfaces[idx].mesh_id) free(interfaces[idx].mesh_id);
                            interfaces[idx].mesh_id = (strlen(value) > 0) ? strdup(value) : NULL;
                        }
                    }
                }
                free(key_copy);
            }
        }
    }
    pclose(fp);

    // Process interfaces and categorize by radio
    for (int i = 0; i < interface_count; i++) {
        if (!interfaces[i].device || !interfaces[i].mode) continue;

        // Determine which radio this interface belongs to
        json_object *target_radio = NULL;
        
        // Check device assignment through a separate uci call
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "uci get wireless.%s.device 2>/dev/null", interfaces[i].device);
        FILE *device_fp = popen(cmd, "r");
        if (device_fp) {
            char device_buffer[64];
            if (fgets(device_buffer, sizeof(device_buffer), device_fp)) {
                device_buffer[strcspn(device_buffer, "\n")] = 0;
                if (strcmp(device_buffer, "radio0") == 0) {
                    target_radio = j_radio0;
                } else if (strcmp(device_buffer, "radio1") == 0) {
                    target_radio = j_radio1;
                }
            }
            pclose(device_fp);
        }

        if (!target_radio) continue;

        // Add interface data based on mode
        if (strcmp(interfaces[i].mode, "ap") == 0) {
            // AP interface - add SSID and key
            if (interfaces[i].ssid) {
                json_object_object_add(target_radio, "ssid", json_object_new_string(interfaces[i].ssid));
            }
            if (interfaces[i].key) {
                json_object_object_add(target_radio, "key", json_object_new_string(interfaces[i].key));
            }
        } else if (strcmp(interfaces[i].mode, "mesh") == 0) {
            // Mesh interface - add mesh_id and mesh_key
            if (interfaces[i].mesh_id) {
                json_object_object_add(target_radio, "mesh_id", json_object_new_string(interfaces[i].mesh_id));
            }
            if (interfaces[i].key) {
                json_object_object_add(target_radio, "mesh_key", json_object_new_string(interfaces[i].key));
            }
        }
    }

    // Cleanup interface storage
    for (int i = 0; i < interface_count; i++) {
        if (interfaces[i].device) free(interfaces[i].device);
        if (interfaces[i].mode) free(interfaces[i].mode);
        if (interfaces[i].ssid) free(interfaces[i].ssid);
        if (interfaces[i].key) free(interfaces[i].key);
        if (interfaces[i].mesh_id) free(interfaces[i].mesh_id);
    }

    // Add radio objects to data
    json_object_object_add(j_data, "radio0", j_radio0);
    json_object_object_add(j_data, "radio1", j_radio1);

    // Construct response
    json_object_object_add(j_response, "type", json_object_new_string("get_wifi_info_response"));
    json_object_object_add(j_response, "data", j_data);

    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);

    // Cleanup
    json_object_put(j_response);
}

/**
 * @brief Handles a request to set Wi-Fi information.
 *
 * This function is called by process_ws_msg() when a "set_wifi_info"
 * message is received. It executes the command "uci set"
 * to set Wi-Fi details, and sends
 * this information back to the client in a JSON response.
 *
 * The JSON request format is:
 * {
 *   "type": "set_wifi_info",
 *   "data": {
 *     "default_radio0": {
 *       "ssid": "new_ssid",
 *       "mesh_id": "new_mesh_id"
 *     }
 *   }
 * }
 *
 * The JSON response format is:
 * {
 *   "type": "set_wifi_info_response",
 *   "data": {
 *     "status": "success",
 *     "message": "Wi-Fi info updated successfully"
 *   }
 * }
 *
 * If the command execution fails, an error response is sent:
 * {
 *   "type": "set_wifi_info_error",
 *   "error": "Failed to execute command"
 * }
 *
 * @param j_req The incoming JSON request object.
 * @param bev The bufferevent associated with the WebSocket connection, used
 *            for sending the response.
 */
/**
 * @brief Helper function to set Wi-Fi configuration for a specific radio device.
 * 
 * This function searches for interfaces belonging to the specified radio device
 * and updates their configuration based on the interface mode (AP or mesh).
 * 
 * @param j_radio JSON object containing radio configuration (ssid, key, mesh_id, mesh_key)
 * @param target_device Target radio device name (e.g., "radio0", "radio1")
 * @param interfaces Array of interface information structures
 * @param interface_count Number of interfaces in the array
 * @return 0 on success, -1 on failure
 */
static int set_radio_wifi_config(json_object *j_radio, const char *target_device,
                                 struct wifi_interface_info *interfaces, int interface_count) {
    if (!j_radio || !target_device || !interfaces) {
        return 0; // No error if no config provided
    }
    
    json_object *j_ssid, *j_key, *j_mesh_id, *j_mesh_key;
    const char *ssid = NULL, *key = NULL, *mesh_id = NULL, *mesh_key = NULL;
    int success = 1;
    
    // Extract values from JSON
    if (json_object_object_get_ex(j_radio, "ssid", &j_ssid)) {
        ssid = json_object_get_string(j_ssid);
        // Skip empty strings
        if (ssid && strlen(ssid) == 0) {
            ssid = NULL;
        }
    }
    if (json_object_object_get_ex(j_radio, "key", &j_key)) {
        key = json_object_get_string(j_key);
        // Skip empty strings
        if (key && strlen(key) == 0) {
            key = NULL;
        }
    }
    if (json_object_object_get_ex(j_radio, "mesh_id", &j_mesh_id)) {
        mesh_id = json_object_get_string(j_mesh_id);
        // Skip empty strings
        if (mesh_id && strlen(mesh_id) == 0) {
            mesh_id = NULL;
        }
    }
    if (json_object_object_get_ex(j_radio, "mesh_key", &j_mesh_key)) {
        mesh_key = json_object_get_string(j_mesh_key);
        // Skip empty strings
        if (mesh_key && strlen(mesh_key) == 0) {
            mesh_key = NULL;
        }
    }
    
    // Find interfaces for this device and update them
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interfaces[i].device, target_device) == 0) {
            if (strcmp(interfaces[i].mode, "ap") == 0) {
                // Update AP interface
                if (ssid) {
                    debug(LOG_INFO, "Setting SSID for AP interface %s: %s", interfaces[i].interface_name, ssid);
                    if (uci_set_value("wireless", interfaces[i].interface_name, "ssid", ssid) != 0) {
                        debug(LOG_ERR, "Failed to set SSID for %s", interfaces[i].interface_name);
                        success = 0;
                    }
                } else {
                    debug(LOG_DEBUG, "Skipping empty SSID for AP interface %s", interfaces[i].interface_name);
                }
                if (key) {
                    debug(LOG_INFO, "Setting key for AP interface %s", interfaces[i].interface_name);
                    if (uci_set_value("wireless", interfaces[i].interface_name, "key", key) != 0) {
                        debug(LOG_ERR, "Failed to set key for %s", interfaces[i].interface_name);
                        success = 0;
                    }
                } else {
                    debug(LOG_DEBUG, "Skipping empty key for AP interface %s", interfaces[i].interface_name);
                }
            } else if (strcmp(interfaces[i].mode, "mesh") == 0) {
                // Update mesh interface
                if (mesh_id) {
                    debug(LOG_INFO, "Setting mesh_id for mesh interface %s: %s", interfaces[i].interface_name, mesh_id);
                    if (uci_set_value("wireless", interfaces[i].interface_name, "mesh_id", mesh_id) != 0) {
                        debug(LOG_ERR, "Failed to set mesh_id for %s", interfaces[i].interface_name);
                        success = 0;
                    }
                } else {
                    debug(LOG_DEBUG, "Skipping empty mesh_id for mesh interface %s", interfaces[i].interface_name);
                }
                if (mesh_key) {
                    debug(LOG_INFO, "Setting mesh key for mesh interface %s", interfaces[i].interface_name);
                    if (uci_set_value("wireless", interfaces[i].interface_name, "key", mesh_key) != 0) {
                        debug(LOG_ERR, "Failed to set mesh key for %s", interfaces[i].interface_name);
                        success = 0;
                    }
                } else {
                    debug(LOG_DEBUG, "Skipping empty mesh_key for mesh interface %s", interfaces[i].interface_name);
                }
            }
        }
    }
    
    return success ? 0 : -1;
}

/**
 * @brief Handles a request to set Wi-Fi information.
 *
 * This function is called by process_ws_msg() when a "set_wifi_info"
 * message is received. It accepts Wi-Fi configuration data for both
 * 2.4G and 5G radios, updates the UCI wireless configuration,
 * and restarts the Wi-Fi to apply changes.
 *
 * Expected JSON request format:
 * {
 *   "type": "set_wifi_info",
 *   "data": {
 *     "radio0": {
 *       "ssid": "New_2G_SSID",
 *       "key": "new_password123",
 *       "mesh_id": "new_mesh_2g",
 *       "mesh_key": "new_mesh_password123"
 *     },
 *     "radio1": {
 *       "ssid": "New_5G_SSID",
 *       "key": "new_password123",
 *       "mesh_id": "new_mesh_5g",
 *       "mesh_key": "new_mesh_password123"
 *     }
 *   }
 * }
 *
 * The function will:
 * 1. Find the appropriate AP interfaces for each radio
 * 2. Find the appropriate mesh interfaces for each radio  
 * 3. Update SSID/key for AP interfaces
 * 4. Update mesh_id/mesh_key for mesh interfaces
 * 5. Commit UCI changes and restart Wi-Fi
 *
 * Success response:
 * {
 *   "type": "set_wifi_info_response",
 *   "data": {
 *     "status": "success",
 *     "message": "Wi-Fi configuration updated successfully"
 *   }
 * }
 *
 * Error response:
 * {
 *   "type": "set_wifi_info_error",
 *   "error": "Error description"
 * }
 *
 * @param j_req The incoming JSON request object containing Wi-Fi config data.
 * @param bev The bufferevent associated with the WebSocket connection, used
 *            for sending the response.
 */
static void handle_set_wifi_info_request(json_object *j_req, struct bufferevent *bev) {
    json_object *j_response = json_object_new_object();
    json_object *j_data;

    if (!json_object_object_get_ex(j_req, "data", &j_data)) {
        debug(LOG_ERR, "Set wifi info request missing 'data' field");
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'data' field"));
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    // Structure to hold interface information
    struct wifi_interface_info interfaces[32];
    int interface_count = 0;

    // First, discover existing interfaces and their assignments
    FILE *fp = popen("uci show wireless | grep -E '\\.(device|mode)='", "r");
    if (!fp) {
        debug(LOG_ERR, "Failed to query wireless interfaces");
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to query wireless interfaces"));
        const char *response_str = json_object_to_json_string(j_response);
        ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
        json_object_put(j_response);
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
        
        char *key = strtok(buffer, "=");
        char *value_with_quotes = strtok(NULL, "=");
        
        if (key && value_with_quotes) {
            char *value = value_with_quotes;
            if (value[0] == '\'' && value[strlen(value) - 1] == '\'') {
                value = value + 1;
                value[strlen(value) - 1] = '\0';
            }
            
            // Parse wireless.<interface>.<property>
            if (strstr(key, "wireless.") == key) {
                char *key_copy = strdup(key);
                char *parts[4];
                int part_count = 0;
                
                char *token = strtok(key_copy, ".");
                while (token && part_count < 4) {
                    parts[part_count++] = token;
                    token = strtok(NULL, ".");
                }
                
                if (part_count >= 3) {
                    char *interface_name = parts[1];
                    char *property = parts[2];
                    
                    // Find or create interface entry
                    int idx = -1;
                    for (int i = 0; i < interface_count; i++) {
                        if (strcmp(interfaces[i].interface_name, interface_name) == 0) {
                            idx = i;
                            break;
                        }
                    }
                    if (idx == -1 && interface_count < 32) {
                        idx = interface_count++;
                        strncpy(interfaces[idx].interface_name, interface_name, sizeof(interfaces[idx].interface_name) - 1);
                        interfaces[idx].interface_name[sizeof(interfaces[idx].interface_name) - 1] = '\0';
                    }
                    
                    if (idx >= 0) {
                        if (strcmp(property, "device") == 0) {
                            strncpy(interfaces[idx].device, value, sizeof(interfaces[idx].device) - 1);
                            interfaces[idx].device[sizeof(interfaces[idx].device) - 1] = '\0';
                        } else if (strcmp(property, "mode") == 0) {
                            strncpy(interfaces[idx].mode, value, sizeof(interfaces[idx].mode) - 1);
                            interfaces[idx].mode[sizeof(interfaces[idx].mode) - 1] = '\0';
                        }
                    }
                }
                free(key_copy);
            }
        }
    }
    pclose(fp);

    // Get radio configuration objects
    json_object *j_radio0 = NULL, *j_radio1 = NULL;
    json_object_object_get_ex(j_data, "radio0", &j_radio0);
    json_object_object_get_ex(j_data, "radio1", &j_radio1);

    // Set configuration for each radio
    int success = 1;
    if (set_radio_wifi_config(j_radio0, "radio0", interfaces, interface_count) != 0) {
        success = 0;
    }
    if (set_radio_wifi_config(j_radio1, "radio1", interfaces, interface_count) != 0) {
        success = 0;
    }

    if (success) {
        // Reload wifi to apply changes
        FILE *reload_fp = popen("wifi reload", "r");
        if (reload_fp == NULL) {
            debug(LOG_ERR, "Failed to run command wifi reload");
            json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Failed to execute wifi reload"));
            const char *response_str = json_object_to_json_string(j_response);
            ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
            json_object_put(j_response);
            return;
        }
        pclose(reload_fp);

        // Construct success response
        json_object *j_resp_data = json_object_new_object();
        json_object_object_add(j_resp_data, "status", json_object_new_string("success"));
        json_object_object_add(j_resp_data, "message", json_object_new_string("Wi-Fi info updated successfully"));
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_response"));
        json_object_object_add(j_response, "data", j_resp_data);
    } else {
        // Construct error response
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to update one or more Wi-Fi settings"));
    }

    const char *response_str = json_object_to_json_string(j_response);
    ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);

    // Cleanup
    json_object_put(j_response);
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
 * Handle client kickoff request from WebSocket server
 *
 * Processes client disconnection requests with format:
 * {
 *   "client_ip": "<ip_address>",
 *   "client_mac": "<mac_address>",
 *   "device_id": "<device_id>", 
 *   "gw_id": "<gateway_id>"
 * }
 *
 * Success response:
 * {
 *   "type": "kickoff_response",
 *   "status": "success",
 *   "client_ip": "<ip_address>",
 *   "client_mac": "<mac_address>",
 *   "message": "Client kicked off successfully"
 * }
 *
 * Error responses:
 * {
 *   "type": "kickoff_error",
 *   "error": "Missing required fields in request"
 * }
 * {
 *   "type": "kickoff_error",
 *   "error": "Client not found",
 *   "client_ip": "<ip_address>",
 *   "client_mac": "<mac_address>"
 * }
 *
 * Validates the request and removes the client by:
 * 1. Verifying all required fields are present
 * 2. Checking client exists in local database
 * 3. Validating device ID and gateway ID match
 * 4. Removing firewall rules and client entry
 * 5. Sending appropriate response back to server
 *
 * @param j_auth JSON object containing the kickoff request
 * @param bev The bufferevent associated with the WebSocket connection for responses
 */
static void
handle_kickoff_request(json_object *j_auth, struct bufferevent *bev)
{
	json_object *j_response = json_object_new_object();
	
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
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
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
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
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
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
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
		ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
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
	ws_send(bufferevent_get_output(bev), response_str, strlen(response_str), TEXT_FRAME);
	json_object_put(j_response);
}

/**
 * Handle authentication request from WebSocket server
 *
 * Processes client authentication requests with format:
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
 * @param j_auth JSON object containing the auth request
 */
static void
handle_auth_request(json_object *j_auth)
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
 * - "heartbeat": Handles gateway status updates. (Responds with heartbeat)
 * - "connect": Handles initial connection response. (Responds with heartbeat)
 * - "auth": Handles client authentication requests.
 * - "kickoff": Handles client disconnection requests. Responds with "kickoff_response"
 *              for success or "kickoff_error" for validation failures.
 * - "tmp_pass": Handles requests for temporary client access.
 * - "get_firmware_info": Triggers a request for firmware information. The device
 *                        responds with a "firmware_info_response" message
 *                        containing details from /etc/openwrt_release.
 * - "firmware_upgrade": Handles firmware upgrade requests. Executes sysupgrade
 *                       command with the provided URL and responds with success
 *                       or error status before potential system reboot.
 * - "update_device_info": Handles device information update requests. Updates
 *                         local device configuration and UCI settings.
 * - "sync_trusted_domain": Handles trusted domains synchronization. Completely
 *                          replaces the current trusted domains list with the
 *                          provided list. Responds with "sync_trusted_domain_response".
 * - "get_trusted_domains": Retrieves the current list of trusted domains.
 *                          Responds with "get_trusted_domains_response" containing
 *                          an array of exact-match domain names.
 * - "sync_trusted_wildcard_domains": Handles wildcard domains synchronization.
 *                                    Replaces current wildcard domains list with
 *                                    the provided patterns (e.g., "*.example.com").
 *                                    Responds with "sync_trusted_wildcard_domains_response".
 * - "get_trusted_wildcard_domains": Retrieves the current list of wildcard domains.
 *                                   Responds with "get_trusted_wildcard_domains_response"
 *                                   containing an array of wildcard patterns.
 * - "reboot_device": Handles device reboot requests. Executes system reboot command
 *                    to restart the device immediately. No response is sent on success
 *                    as the device shuts down. Responds with "reboot_device_error" 
 *                    if the reboot command fails to execute.
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
		handle_auth_request(jobj);
	} else if (!strcmp(type_str, "kickoff")) {
		handle_kickoff_request(jobj, bev);
	} else if (!strcmp(type_str, "tmp_pass")) {
		handle_tmp_pass_response(jobj);
	} else if (!strcmp(type_str, "get_firmware_info")) {
		handle_get_firmware_info_request(jobj, bev);
	} else if (!strcmp(type_str, "firmware_upgrade")) {
		handle_firmware_upgrade_request(jobj, bev);
	} else if (!strcmp(type_str, "update_device_info")) {
		handle_update_device_info_request(jobj, bev);
	} else if (!strcmp(type_str, "sync_trusted_domain")) {
		handle_sync_trusted_domain_request(jobj, bev);
	} else if (!strcmp(type_str, "get_trusted_domains")) {
		handle_get_trusted_domains_request(jobj, bev);
	} else if (!strcmp(type_str, "sync_trusted_wildcard_domains")) {
		handle_sync_trusted_wildcard_domains_request(jobj, bev);
	} else if (!strcmp(type_str, "get_trusted_wildcard_domains")) {
		handle_get_trusted_wildcard_domains_request(jobj, bev);
	} else if (!strcmp(type_str, "reboot_device")) {
		handle_reboot_device_request(jobj, bev);
	} else if (!strcmp(type_str, "get_wifi_info")) {
		handle_get_wifi_info_request(jobj, bev);
	} else if (!strcmp(type_str, "set_wifi_info")) {
		handle_set_wifi_info_request(jobj, bev);
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

	// Process frames based on opcode
	switch (opcode) {
	case TEXT_FRAME: {
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
		if (payload_len > 0) {
			// Echo back the ping payload in pong response
			char *ping_data = malloc(payload_len);
			if (ping_data) {
				memcpy(ping_data, data + header_len, payload_len);
				ws_send(out, ping_data, payload_len, PONG_FRAME);
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
	// Stop heartbeat timer
	if (ws_state.heartbeat_ev) {
		event_del(ws_state.heartbeat_ev);
		event_free(ws_state.heartbeat_ev);
		ws_state.heartbeat_ev = NULL;
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
