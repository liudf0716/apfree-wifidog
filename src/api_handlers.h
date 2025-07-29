// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _API_HANDLERS_H_
#define _API_HANDLERS_H_

#include <event2/bufferevent.h>
#include <json-c/json.h>

// Forward declarations
typedef struct api_transport_context api_transport_context_t;

/**
 * @brief Function pointer type for sending responses
 * 
 * This abstraction allows API handlers to be transport-agnostic.
 * Different transport protocols (WebSocket, MQTT, HTTP) can provide
 * their own implementation of this function.
 * 
 * @param ctx Transport-specific context (e.g., bufferevent for WebSocket)
 * @param message The message string to send
 * @param length Length of the message
 * @return 0 on success, -1 on error
 */
typedef int (*api_send_response_func_t)(void *ctx, const char *message, size_t length);

/**
 * @brief Transport context structure for API handlers
 * 
 * This structure provides a transport-agnostic interface for API handlers.
 * It contains the transport-specific context and the send function.
 */
struct api_transport_context {
    void *transport_ctx;                    // Transport-specific context (e.g., bufferevent*)
    api_send_response_func_t send_response; // Function to send responses
    char *protocol_name;                    // Protocol name for debugging ("websocket", "mqtt", etc.)
};

struct wifi_interface_info {
    char interface_name[64];    // Interface section name (e.g., wifinet2, default_radio1)
    char device[16];           // Radio device (radio0, radio1)
    char mode[16];             // Interface mode (ap, mesh, sta)
    char ssid[64];             // SSID for AP mode
    char key[128];             // Password/key
    char encryption[32];       // Encryption type (psk2, sae, none)
    char network[32];          // Network interface (lan, lan2, lan3)
    char mesh_id[64];          // Mesh ID for mesh mode
    int disabled;              // Interface disabled (0/1)
};

/**
 * @brief WiFi device (radio) information structure
 */
struct wifi_device_info {
    char device_name[16];      // Device name (radio0, radio1)
    char type[16];             // Device type (mac80211)
    char path[128];            // Device path
    char band[8];              // Band (2g, 5g)
    int channel;               // Channel number
    char htmode[16];           // HT mode (HT20, HE80, etc.)
    int cell_density;          // Cell density
};

// Authentication and client management handlers
void handle_auth_request(json_object *j_auth);
void handle_kickoff_request(json_object *j_req, api_transport_context_t *transport);
void handle_get_client_info_request(json_object *j_req, api_transport_context_t *transport);

// Device management handlers
void handle_update_device_info_request(json_object *j_req, api_transport_context_t *transport);
void handle_reboot_device_request(json_object *j_req, api_transport_context_t *transport);

// Firmware management handlers
void handle_get_firmware_info_request(json_object *j_req, api_transport_context_t *transport);
void handle_firmware_upgrade_request(json_object *j_req, api_transport_context_t *transport);

// Network configuration handlers
void handle_get_wifi_info_request(json_object *j_req, api_transport_context_t *transport);
void handle_set_wifi_info_request(json_object *j_req, api_transport_context_t *transport);

// Domain management handlers
void handle_sync_trusted_domain_request(json_object *j_req, api_transport_context_t *transport);
void handle_get_trusted_domains_request(json_object *j_req, api_transport_context_t *transport);
void handle_sync_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport);
void handle_get_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport);

// System information handlers
void handle_get_sys_info_request(json_object *j_req, api_transport_context_t *transport);

// Connection management handlers (these don't need transport context)
void handle_heartbeat_request(json_object *j_heartbeat);
void handle_tmp_pass_request(json_object *j_tmp_pass);

// Utility functions for transport abstraction
api_transport_context_t* create_websocket_transport_context(struct bufferevent *bev);
void destroy_transport_context(api_transport_context_t *transport);

#endif /* _API_HANDLERS_H_ */