// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE
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
#include "version.h"
#include "commandline.h"
#include "mqtt_thread.h"
#include "safe.h"
#include "wdctlx_thread.h"
#include "ping_thread.h"
#include "client_library/shell_executor.h"
#include <uci.h>

// Forward declaration of ws_send function (will be implemented in ws_thread.c)
extern void ws_send(struct evbuffer *buf, const char *msg, const size_t len, int frame_type);

// WebSocket frame types
#define TEXT_FRAME 0x1



// MQTT context structure to hold mosquitto instance and req_id
typedef struct {
    void *mosq;              // struct mosquitto *
    unsigned int req_id;
} mqtt_context_t;

/**
 * @brief Unified API routing table
 * 
 * This table maps operation/message type names to their handler functions.
 * Used by both MQTT and WebSocket protocols.
 * 
 * Note: Some operations have aliases (e.g., "connect" and "heartbeat" both map to the same handler)
 */
static const api_route_entry_t api_routes[] = {
	// System info & status
	{"heartbeat",                   handle_get_sys_info_request},
	{"connect",                     handle_get_sys_info_request},
	{"bootstrap",                   handle_get_sys_info_request},
    {"get_sys_info",                handle_get_sys_info_request},
    {"get_status",                  handle_get_aw_status_request},
	
	// Authentication & client management
	{"auth",                        handle_auth_request},
	{"kickoff",                     handle_kickoff_request},
	{"tmp_pass",                    handle_tmp_pass_request},
	{"get_client_info",             handle_get_client_info_request},
	{"get_clients",                 handle_get_clients_request},
    {"shell",                       handle_shell_request},
	
	// Firmware management
	{"get_firmware_info",           handle_get_firmware_info_request},
	{"firmware_upgrade",            handle_firmware_upgrade_request},
	{"ota",                         handle_firmware_upgrade_request},
	
	// Device configuration
    {"update_device_info",          handle_update_device_info_request},
    {"get_device_info",             handle_get_device_info_request},
	{"set_auth_serv",               handle_set_auth_server_request},
    {"get_auth_serv",               handle_get_auth_server_request},
    {"reboot_device",               handle_reboot_device_request},
	
	// WiFi management
	{"get_wifi_info",               handle_get_wifi_info_request},
    {"set_wifi_info",               handle_set_wifi_info_request},
    {"scan_wifi",                   handle_scan_wifi_request},
    {"set_wifi_relay",              handle_set_wifi_relay_request},
    {"delete_wifi_relay",           handle_delete_wifi_relay_request},
    {"unset_wifi_relay",            handle_delete_wifi_relay_request},

    // Flow control / BPF management (aw-bpfctl wrapper)
    {"bpf_add",                     handle_bpf_add_request},
    {"bpf_del",                     handle_bpf_del_request},
    {"bpf_flush",                   handle_bpf_flush_request},
    {"bpf_json",                    handle_bpf_json_request},
    {"bpf_update",                  handle_bpf_update_request},
    {"bpf_update_all",              handle_bpf_update_all_request},
	
    // Trusted domains
    // Note: Use `sync_trusted_domain` as the canonical operation name.
    {"sync_trusted_domain",         handle_sync_trusted_domain_request},
	{"get_trusted_domains",         handle_get_trusted_domains_request},
	{"sync_trusted_wildcard_domains", handle_sync_trusted_wildcard_domains_request},
    {"get_trusted_wildcard_domains",  handle_get_trusted_wildcard_domains_request},
    // Trusted MACs (added)
    {"sync_trusted_mac",            handle_sync_trusted_mac_request},
    {"get_trusted_mac",             handle_get_trusted_mac_request},
	
	// End marker
	{NULL, NULL}
};

/**
 * @brief Get the global API routing table
 */
const api_route_entry_t* 
api_get_routes(void) 
{
	return api_routes;
}

/**
 * @brief Dispatch API request to appropriate handler
 */
bool 
api_dispatch_request(const char *op_name, json_object *json_req, api_transport_context_t *transport)
{
	if (!op_name || !json_req) {
		debug(LOG_ERR, "Invalid parameters for API dispatch");
		return false;
	}

	// Route to handler using lookup table
	for (const api_route_entry_t *route = api_routes; route->name != NULL; route++) {
		if (strcmp(op_name, route->name) == 0) {
			if (route->handler) {
                route->handler(json_req, transport);
                return true;
			}
			return true;
		}
	}

	return false;
}

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
 * @brief MQTT-specific send response implementation
 * 
 * @param ctx Transport context (should be mqtt_context_t*)
 * @param message Message to send
 * @param length Length of message
 * @return 0 on success, -1 on error
 */
static int mqtt_send_response(void *ctx, const char *message, size_t length) {
    mqtt_context_t *mqtt_ctx = (mqtt_context_t *)ctx;
    if (!mqtt_ctx || !mqtt_ctx->mosq || !message) {
        debug(LOG_ERR, "mqtt_send_response: Invalid context or message");
        return -1;
    }
    
    char *topic = NULL;
    char *res_data = NULL;
    
    // Get device ID (external function)
    extern const char* get_device_id(void);
    
    // Format topic and response
    if (asprintf(&topic, "wifidogx/v1/%s/s2c/response", get_device_id()) < 0) {
        debug(LOG_ERR, "mqtt_send_response: Failed to allocate topic");
        return -1;
    }
    
    if (asprintf(&res_data, "{\"req_id\":%u,\"response\":\"200\",\"data\":%s}", 
                 mqtt_ctx->req_id, message) < 0) {
        debug(LOG_ERR, "mqtt_send_response: Failed to allocate response data");
        free(topic);
        return -1;
    }
    
    debug(LOG_INFO, "mqtt_send_response: Publishing to topic: %s, req_id: %u", topic, mqtt_ctx->req_id);
    
    // Publish via mosquitto library
    int ret = mosquitto_publish(mqtt_ctx->mosq, NULL, topic, 
                               strlen(res_data), res_data, 0, false);
    
    debug(LOG_INFO, "mqtt_send_response: mosquitto_publish returned: %d", ret);
    
    free(topic);
    free(res_data);
    
    return ret == 0 ? 0 : -1;
}

/**
 * @brief Create a MQTT transport context
 * 
 * @param mosq The mosquitto instance
 * @param req_id Request ID for correlation
 * @return Allocated transport context, or NULL on error
 */
api_transport_context_t* create_mqtt_transport_context(void *mosq, unsigned int req_id) {
    if (!mosq) {
        return NULL;
    }
    
    mqtt_context_t *mqtt_ctx = malloc(sizeof(mqtt_context_t));
    if (!mqtt_ctx) {
        return NULL;
    }
    
    mqtt_ctx->mosq = mosq;
    mqtt_ctx->req_id = req_id;
    
    api_transport_context_t *transport = malloc(sizeof(api_transport_context_t));
    if (!transport) {
        free(mqtt_ctx);
        return NULL;
    }
    
    transport->transport_ctx = mqtt_ctx;
    transport->send_response = mqtt_send_response;
    transport->protocol_name = "mqtt";
    
    return transport;
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
        // For MQTT, we need to free the mqtt_context_t structure
        if (transport->protocol_name && strcmp(transport->protocol_name, "mqtt") == 0) {
            free(transport->transport_ctx);
        }
        // Note: For WebSocket, transport_ctx (bufferevent) is managed by the caller
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

/*
 * Auto-generate simple field descriptions for responses.
 * If a handler has already provided a dedicated `field_descriptions`
 * entry, this function will do nothing. Otherwise it will add a
 * top-level `field_descriptions` object describing keys under `data`.
 */
static void add_auto_field_descriptions(json_object *j_response)
{
    if (!j_response) return;

    json_object *existing = NULL;
    if (json_object_object_get_ex(j_response, "field_descriptions", &existing)) {
        return; /* already provided */
    }

    json_object *j_data = NULL;
    if (!json_object_object_get_ex(j_response, "data", &j_data) || !json_object_is_type(j_data, json_type_object)) {
        /* nothing to describe */
        return;
    }

    json_object *j_fd = json_object_new_object();
    json_object_object_foreach(j_data, key, val) {
        const char *type_name = "unknown";
        switch(json_object_get_type(val)) {
            case json_type_boolean: type_name = "boolean"; break;
            case json_type_double:  type_name = "double";  break;
            case json_type_int:     type_name = "integer"; break;
            case json_type_string:  type_name = "string";  break;
            case json_type_array:   type_name = "array";   break;
            case json_type_object:  type_name = "object";  break;
            default: type_name = "unknown"; break;
        }

        char buf[128];
        snprintf(buf, sizeof(buf), "Auto-generated: key '%s' of type %s", key, type_name);
        json_object_object_add(j_fd, key, json_object_new_string(buf));
    }

    json_object_object_add(j_response, "field_descriptions", j_fd);
}

/* Send a json_object response after adding field descriptions (if missing). */
static void send_json_response(api_transport_context_t *transport, json_object *j_response)
{
    if (!j_response) return;
    add_auto_field_descriptions(j_response);

    const char *response_str = json_object_to_json_string(j_response);
    if (response_str) {
        send_response(transport, response_str);
    }

    json_object_put(j_response);
}

/**
 * @brief Return apfree-wifidog runtime status (distinct from sys info)
 *
 * Provides a small status object: service name, uptime (seconds), and
 * number of known clients. This reads only runtime memory and /proc/uptime.
 */
void handle_get_aw_status_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    /* AW human-readable uptime */
    char *aw_uptime = get_aw_uptime();

    /* System and wifidog stats */
    struct sys_info info;
    memset(&info, 0, sizeof(info));
    get_sys_info(&info);

    /* selected auth section from UCI (if present) */
    char selected_section[128] = {0};
    if (uci_get_value("wifidogx", "wifidog", "selected_auth_server", selected_section, sizeof(selected_section)) != 0) {
        selected_section[0] = '\0';
    }

    /* Copy runtime auth-server values and config flags under lock */
    char *hostname_copy = NULL;
    char *path_copy = NULL;
    int port_copy = 0;
    s_config *config = config_get_config();

    LOCK_CONFIG();
    if (config && config->auth_servers) {
        if (config->auth_servers->authserv_hostname) {
            hostname_copy = safe_strdup(config->auth_servers->authserv_hostname);
        }
        port_copy = config->auth_servers->authserv_http_port;
        if (config->auth_servers->authserv_path) {
            path_copy = safe_strdup(config->auth_servers->authserv_path);
        }
    }

    /* collect gateway settings and mqtt server under same lock */
    t_gateway_setting *gw_settings = NULL;
    t_mqtt_server *mqtt_server = NULL;
    if (config) {
        gw_settings = config->gateway_settings;
        mqtt_server = config->mqtt_server;
    }
    int gw_port = config ? config->gw_port : DEFAULT_GATEWAYPORT;
    int gw_https_port = config ? config->gw_https_port : DEFAULT_GATEWAY_HTTPS_PORT;
    int check_interval = config ? config->checkinterval : DEFAULT_CHECKINTERVAL;
    int client_timeout = config ? config->clienttimeout : DEFAULT_CLIENTTIMEOUT;
    int fw4_enabled = config ? config->fw4_enable : 0;
    int anti_nat = config ? config->enable_anti_nat : 0;
    int del_conntrack = config ? config->enable_del_conntrack : 0;
    
    UNLOCK_CONFIG();

    /* Top-level fields */
    json_object_object_add(j_data, "service", json_object_new_string("apfree-wifidog"));
    json_object_object_add(j_data, "version", json_object_new_string(VERSION));
    if (aw_uptime) {
        json_object_object_add(j_data, "uptime", json_object_new_string(aw_uptime));
    }
    json_object_object_add(j_data, "uptime_seconds", json_object_new_int64(info.wifidog_uptime));

    /* Has been restarted */
    extern pid_t restart_orig_pid;
    json_object_object_add(j_data, "has_been_restarted", json_object_new_string(restart_orig_pid ? "yes" : "no"));
    json_object_object_add(j_data, "restart_orig_pid", json_object_new_int((int)restart_orig_pid));

    /* Auth / portal / mode fields */
    const char *auth_mode_str = is_local_auth_mode() ? "Local" : (is_bypass_mode() ? "Bypass" : "Cloud");
    json_object_object_add(j_data, "auth_server_mode", json_object_new_string(auth_mode_str));
    json_object_object_add(j_data, "portal_auth", json_object_new_string(is_portal_auth_disabled() ? "Disabled" : "Enabled"));
    json_object_object_add(j_data, "bypass_mode", json_object_new_string(is_bypass_mode() ? "Yes" : "No"));

    /* Ports and intervals */
    json_object_object_add(j_data, "gateway_port", json_object_new_int(gw_port));
    json_object_object_add(j_data, "https_port", json_object_new_int(gw_https_port));
    json_object_object_add(j_data, "check_interval", json_object_new_int(check_interval));
    json_object_object_add(j_data, "client_timeout", json_object_new_int(client_timeout));

    /* Connectivity */
    json_object_object_add(j_data, "internet_connectivity", json_object_new_string(is_online() ? "yes" : "no"));
    json_object_object_add(j_data, "auth_server_reachable", json_object_new_string(is_auth_online() ? "yes" : "no"));

    if (selected_section[0]) {
        json_object_object_add(j_data, "selected_auth_server", json_object_new_string(selected_section));
    }

    /* Auth server runtime details */
    json_object *j_auth = json_object_new_object();
    if (hostname_copy) {
        json_object_object_add(j_auth, "hostname", json_object_new_string(hostname_copy));
    }
    json_object_object_add(j_auth, "port", json_object_new_int(port_copy));
    if (path_copy) {
        json_object_object_add(j_auth, "path", json_object_new_string(path_copy));
    }
    json_object_object_add(j_data, "auth_server", j_auth);

    /* Gateway settings array */
    if (gw_settings) {
        json_object *j_gws = json_object_new_array();
        t_gateway_setting *g = gw_settings;
        while (g) {
            json_object *j_gw = json_object_new_object();
            json_object_object_add(j_gw, "interface", json_object_new_string(g->gw_interface ? g->gw_interface : "N/A"));
            json_object_object_add(j_gw, "gateway_id", json_object_new_string(g->gw_id ? g->gw_id : "N/A"));
            json_object_object_add(j_gw, "ipv4", json_object_new_string(g->gw_address_v4 ? g->gw_address_v4 : "N/A"));
            json_object_object_add(j_gw, "ipv6", json_object_new_string(g->gw_address_v6 ? g->gw_address_v6 : "N/A"));
            json_object_object_add(j_gw, "channel", json_object_new_string(g->gw_channel ? g->gw_channel : "N/A"));
            json_object_array_add(j_gws, j_gw);
            g = g->next;
        }
        json_object_object_add(j_data, "gateway_settings", j_gws);
    }

    /* System resources */
    json_object *j_sys = json_object_new_object();
    json_object_object_add(j_sys, "system_uptime_seconds", json_object_new_int64(info.sys_uptime));
    json_object_object_add(j_sys, "free_memory_kb", json_object_new_int(info.sys_memfree));
    json_object_object_add(j_sys, "load_average", json_object_new_double(info.sys_load));
    json_object_object_add(j_sys, "cpu_usage_percent", json_object_new_double(info.cpu_usage));
    if (info.cpu_temp > 0) {
        json_object_object_add(j_sys, "cpu_temperature_c", json_object_new_int(info.cpu_temp));
    }
    json_object_object_add(j_sys, "netfilter_conntrack", json_object_new_int64(info.nf_conntrack_count));
    json_object_object_add(j_data, "system_resources", j_sys);

    /* Firewall status */
    json_object *j_fw = json_object_new_object();
    json_object_object_add(j_fw, "fw4_enabled", json_object_new_boolean(fw4_enabled));
    json_object_object_add(j_fw, "anti_nat_enabled", json_object_new_boolean(anti_nat));
    json_object_object_add(j_fw, "del_conntrack", json_object_new_boolean(del_conntrack));
    json_object_object_add(j_data, "firewall_status", j_fw);

    /* MQTT server info */
    if (mqtt_server) {
        json_object *j_mqtt = json_object_new_object();
        json_object_object_add(j_mqtt, "host", json_object_new_string(mqtt_server->hostname ? mqtt_server->hostname : "N/A"));
        json_object_object_add(j_mqtt, "port", json_object_new_int(mqtt_server->port));
        json_object_object_add(j_mqtt, "username", json_object_new_string(mqtt_server->username ? mqtt_server->username : "N/A"));
        /* MQTT connection status */
        json_object_object_add(j_mqtt, "connected", json_object_new_boolean(mqtt_is_connected()));
        json_object_object_add(j_data, "mqtt_server", j_mqtt);
    }

    /* Portal/authentication runtime status convenience */
    json_object_object_add(j_data, "portal_auth_enabled", json_object_new_boolean(!is_portal_auth_disabled()));

    /* Descriptions for AI/clients: explain each field returned in the JSON */
    json_object *j_field_desc = json_object_new_object();
    json_object_object_add(j_field_desc, "service", json_object_new_string("Service name (string) - identifies this software component"));
    json_object_object_add(j_field_desc, "version", json_object_new_string("Version (string) - software version string"));
    json_object_object_add(j_field_desc, "uptime", json_object_new_string("Human-readable uptime (string), e.g. '1D 2H 3M 4S'"));
    json_object_object_add(j_field_desc, "uptime_seconds", json_object_new_string("Uptime in seconds (int64) since service start"));
    json_object_object_add(j_field_desc, "has_been_restarted", json_object_new_string("Indicates whether process was restarted during this run ('yes'/'no')"));
    json_object_object_add(j_field_desc, "restart_orig_pid", json_object_new_string("Original parent PID if restarted (int)"));
    json_object_object_add(j_field_desc, "auth_server_mode", json_object_new_string("Auth mode (string) - 'Local', 'Cloud' or 'Bypass'"));
    json_object_object_add(j_field_desc, "portal_auth", json_object_new_string("Portal authentication status (string) - 'Enabled' or 'Disabled'"));
    json_object_object_add(j_field_desc, "bypass_mode", json_object_new_string("Bypass mode flag (string) - 'Yes' or 'No'"));
    json_object_object_add(j_field_desc, "gateway_port", json_object_new_string("Gateway HTTP port (int) used by captive portal"));
    json_object_object_add(j_field_desc, "https_port", json_object_new_string("Gateway HTTPS port (int) used by captive portal"));
    json_object_object_add(j_field_desc, "check_interval", json_object_new_string("Connectivity check interval (int, seconds)"));
    json_object_object_add(j_field_desc, "client_timeout", json_object_new_string("Client session timeout (int, seconds)") );
    json_object_object_add(j_field_desc, "internet_connectivity", json_object_new_string("Hint whether Internet connectivity appears available ('yes'/'no')"));
    json_object_object_add(j_field_desc, "auth_server_reachable", json_object_new_string("Hint whether the configured auth server is reachable ('yes'/'no')"));
    json_object_object_add(j_field_desc, "selected_auth_server", json_object_new_string("UCI section name of the selected auth server (string), if configured"));

    /* auth_server subfields */
    json_object *j_auth_desc = json_object_new_object();
    json_object_object_add(j_auth_desc, "hostname", json_object_new_string("Auth server hostname (string) from runtime config"));
    json_object_object_add(j_auth_desc, "port", json_object_new_string("Auth server HTTP port (int) from runtime config"));
    json_object_object_add(j_auth_desc, "path", json_object_new_string("Auth server path (string) used for authentication requests"));
    json_object_object_add(j_field_desc, "auth_server", j_auth_desc);

    /* gateway_settings description */
    json_object_object_add(j_field_desc, "gateway_settings", json_object_new_string("Array of gateway objects. Each object: interface (string), gateway_id (string), ipv4 (string), ipv6 (string), channel (string)"));

    /* system_resources subfields */
    json_object *j_sys_desc = json_object_new_object();
    json_object_object_add(j_sys_desc, "system_uptime_seconds", json_object_new_string("System uptime in seconds (int64)"));
    json_object_object_add(j_sys_desc, "free_memory_kb", json_object_new_string("Free memory in KB (int)"));
    json_object_object_add(j_sys_desc, "load_average", json_object_new_string("System load average (double)"));
    json_object_object_add(j_sys_desc, "cpu_usage_percent", json_object_new_string("Estimated CPU usage percent (double)"));
    json_object_object_add(j_sys_desc, "cpu_temperature_c", json_object_new_string("CPU temperature in Celsius (int) if available"));
    json_object_object_add(j_sys_desc, "netfilter_conntrack", json_object_new_string("Number of conntrack entries (int64)"));
    json_object_object_add(j_field_desc, "system_resources", j_sys_desc);

    /* firewall_status subfields */
    json_object *j_fw_desc = json_object_new_object();
    json_object_object_add(j_fw_desc, "fw4_enabled", json_object_new_string("IPv4 firewall enabled boolean"));
    json_object_object_add(j_fw_desc, "anti_nat_enabled", json_object_new_string("Anti-NAT rules enabled boolean"));
    json_object_object_add(j_fw_desc, "del_conntrack", json_object_new_string("Whether conntrack entries are removed on client disconnect (boolean)"));
    json_object_object_add(j_field_desc, "firewall_status", j_fw_desc);

    /* mqtt_server subfields */
    json_object *j_mqtt_desc = json_object_new_object();
    json_object_object_add(j_mqtt_desc, "host", json_object_new_string("MQTT broker hostname (string) from runtime config"));
    json_object_object_add(j_mqtt_desc, "port", json_object_new_string("MQTT broker port (int)"));
    json_object_object_add(j_mqtt_desc, "username", json_object_new_string("MQTT username (string) if configured"));
    json_object_object_add(j_mqtt_desc, "connected", json_object_new_string("Current MQTT connection state (boolean) - true if client connected to broker"));
    json_object_object_add(j_field_desc, "mqtt_server", j_mqtt_desc);

    json_object_object_add(j_field_desc, "portal_auth_enabled", json_object_new_string("Boolean (true/false) duplicate convenience indicating portal auth is enabled"));

    json_object_object_add(j_data, "field_descriptions", j_field_desc);

    json_object_object_add(j_response, "type", json_object_new_string("get_status_response"));
    json_object_object_add(j_response, "data", j_data);

    send_json_response(transport, j_response);

    free(aw_uptime);
    free(hostname_copy);
    free(path_copy);
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

    if (uci_set_config_path_staged(config_path, value) != 0) {
        debug(LOG_ERR, "Failed to set UCI option: %s", config_path);
        return -1;
    }

    return 0;
}

/**
 * @brief Helper function to commit UCI changes
 */
static int commit_uci_changes(void) {
    if (uci_commit_package_by_name("wireless") != 0) {
        debug(LOG_ERR, "Failed to commit UCI changes for wireless");
        return -1;
    }
    
    return 0;
}

/* Helper: run shell command and capture stdout into allocated string. */
static int run_command_capture(const char *cmd, char **out_str, int *exit_status)
{
    if (!cmd) return -1;
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        debug(LOG_ERR, "run_command_capture: popen failed for '%s'", cmd);
        return -1;
    }

    char *buf = NULL;
    size_t buf_len = 0;
    char tmp[512];
    while (fgets(tmp, sizeof(tmp), fp)) {
        size_t tlen = strlen(tmp);
        char *newb = realloc(buf, buf_len + tlen + 1);
        if (!newb) {
            free(buf);
            pclose(fp);
            debug(LOG_ERR, "run_command_capture: memory allocation failed");
            return -1;
        }
        buf = newb;
        memcpy(buf + buf_len, tmp, tlen);
        buf_len += tlen;
        buf[buf_len] = '\0';
    }

    int rc = pclose(fp);
    if (exit_status) *exit_status = rc;
    if (out_str) {
        if (buf) {
            *out_str = buf;
        } else {
            *out_str = strdup("");
        }
    } else {
        free(buf);
    }

    return 0;
}

/* Validate requested aw-bpfctl table name */
static int is_valid_bpf_table(const char *table)
{
    if (!table) return 0;
    if (strcmp(table, "ipv4") == 0) return 1;
    if (strcmp(table, "ipv6") == 0) return 1;
    if (strcmp(table, "mac") == 0) return 1;
    return 0;
}

/* Validate IPv4 address using inet_pton */
static int is_valid_ipv4_address(const char *addr)
{
    if (!addr) return 0;
    struct in_addr in;
    return inet_pton(AF_INET, addr, &in) == 1;
}

/* Validate IPv6 address using inet_pton */
static int is_valid_ipv6_address(const char *addr)
{
    if (!addr) return 0;
    struct in6_addr in6;
    return inet_pton(AF_INET6, addr, &in6) == 1;
}

/* Validate MAC address formats: aa:bb:cc:dd:ee:ff or aabbccddeeff */
static int is_valid_mac_address(const char *mac)
{
    if (!mac) return 0;
    size_t len = strlen(mac);
    if (len == 17) { // expect separators
        int vals[6];
        if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        if (sscanf(mac, "%x-%x-%x-%x-%x-%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        return 0;
    } else if (len == 12) { // no separators
        for (size_t i = 0; i < 12; i++) {
            if (!isxdigit((unsigned char)mac[i])) return 0;
        }
        return 1;
    }
    return 0;
}


/* Validate bitrates (bps). Accept 1 .. 10_000_000_000 (10 Gbps) */
static int is_valid_bitrate_long(long long v)
{
    if (v <= 0) return 0;
    if (v > 10000000000LL) return 0; /* cap at 10 Gbps */
    return 1;
}

/* Admin-token authorization removed per request: BPF handlers no longer require admin token */

/* Generic wrapper handlers for aw-bpfctl commands. Each handler expects JSON
 * input with fields documented below and returns a JSON response containing
 * `status` and `output` (command stdout/stderr concatenated where available).
 */

void handle_bpf_add_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");

    json_object *j_response = json_object_new_object();

    if (!j_table || !j_addr) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' or 'address' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    /* validate address format depending on table */
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC address"));
            send_json_response(transport, j_response);
            return;
        }
    }

    char cmd[512];
    int ret = snprintf(cmd, sizeof(cmd), "aw-bpfctl %s add %s", table, addr);
    if (ret <= 0 || ret >= (int)sizeof(cmd)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Command buffer overflow"));
        send_json_response(transport, j_response);
        return;
    }

    char *out = NULL;
    int status = 0;
    int rc = run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_add_response"));
    json_object_object_add(j_response, "status", json_object_new_string((rc == 0) ? "success" : "error"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));

    send_json_response(transport, j_response);
    free(out);
}

/* bpf_list removed: functionality covered by bpf_json which returns structured JSON */

void handle_bpf_del_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_addr) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' or 'address' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC address"));
            send_json_response(transport, j_response);
            return;
        }
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s del %s", table, addr);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_del_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_flush_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = json_object_new_object();

    if (!j_table) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s flush", table);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_json_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = json_object_new_object();

    if (!j_table) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_json_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_json_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s json", table);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_json_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));

    if (out && strlen(out) > 0) {
        /* Try to parse AW BPF JSON output into structured JSON */
        json_object *parsed = json_tokener_parse(out);
        if (parsed) {
            json_object_object_add(j_response, "data", parsed);
        } else {
            json_object_object_add(j_response, "output", json_object_new_string(out));
        }
    } else {
        json_object_object_add(j_response, "output", json_object_new_string(""));
    }

    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_update_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_target = json_object_object_get(j_req, "target");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_target || !j_down || !j_up) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required parameters: 'table','target','downrate','uprate'"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *target = json_object_get_string(j_target);

    /* validate target depending on table */
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 target"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 target"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC target"));
            send_json_response(transport, j_response);
            return;
        }
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update %s downrate %lld uprate %lld", table, target, down, up);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_update_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_update_all_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_down || !j_up) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required parameters: 'table','downrate','uprate'"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update_all downrate %lld uprate %lld", table, down, up);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_heartbeat_request(json_object *j_heartbeat, api_transport_context_t *transport)
{
	// Mark auth server as online when receiving heartbeat response
	mark_auth_online();
	
	// Extract gateway array from response
	json_object *gw_array = json_object_object_get(j_heartbeat, "gateway");
	if (!gw_array || !json_object_is_type(gw_array, json_type_array)) {
		debug(LOG_ERR, "Heartbeat: Invalid or missing gateway array");
		send_response(transport, "{\"error\":\"Invalid or missing gateway array\"}");
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
	
	// Send success response for heartbeat
	send_response(transport, "{\"status\":\"heartbeat_received\"}");
}

void handle_tmp_pass_request(json_object *j_tmp_pass, api_transport_context_t *transport)
{
	// Check if portal auth is disabled
	if (is_portal_auth_disabled()) {
		debug(LOG_WARNING, "Portal authentication is disabled, ignoring tmp_pass request from server");
		send_response(transport, "{\"error\":\"Portal authentication is disabled\"}");
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

void handle_shell_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_response = json_object_new_object();
    json_object *jo_req_id = NULL;
    json_object *jo_command = NULL;
    json_object *jo_timeout = NULL;
    const char *command = NULL;
    int timeout = shell_executor_get_timeout();
    shell_exec_result_t result;

    if (!j_req || !transport) {
        if (j_response) {
            json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
            json_object_object_add(j_response, "code", json_object_new_int(-1));
            json_object_object_add(j_response, "msg", json_object_new_string("Invalid request"));
            json_object_object_add(j_response, "output", json_object_new_string(""));
            send_json_response(transport, j_response);
        }
        return;
    }

    jo_req_id = json_object_object_get(j_req, "req_id");
    if (jo_req_id) {
        const char *req_id_str = json_object_get_string(jo_req_id);
        json_object_object_add(j_response, "req_id", json_object_new_string(req_id_str ? req_id_str : ""));
    }

    jo_command = json_object_object_get(j_req, "command");
    if (!jo_command || !json_object_is_type(jo_command, json_type_string)) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-2));
        json_object_object_add(j_response, "msg", json_object_new_string("Missing command"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    command = json_object_get_string(jo_command);
    if (!command || strlen(command) == 0) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-2));
        json_object_object_add(j_response, "msg", json_object_new_string("Empty command"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    jo_timeout = json_object_object_get(j_req, "timeout");
    if (jo_timeout) {
        timeout = json_object_get_int(jo_timeout);
        if (timeout <= 0 || timeout > shell_executor_get_timeout()) {
            timeout = shell_executor_get_timeout();
        }
    }

    if (strlen(command) > (size_t)shell_executor_get_max_command_length()) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-3));
        json_object_object_add(j_response, "msg", json_object_new_string("Command too long"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    memset(&result, 0, sizeof(result));
    int exec_ret = shell_executor_execute(command, timeout, &result);

    json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
    if (exec_ret != 0) {
        json_object_object_add(j_response, "code", json_object_new_int(exec_ret));
        json_object_object_add(j_response, "msg", json_object_new_string("Execution failed"));
        json_object_object_add(j_response, "output", json_object_new_string(result.output));
    } else {
        json_object_object_add(j_response, "code", json_object_new_int(result.exit_code));
        json_object_object_add(j_response, "msg", json_object_new_string("OK"));
        json_object_object_add(j_response, "output", json_object_new_string(result.output));
    }

    send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
        return;
    }
    
    const char *mac_str = json_object_get_string(j_mac);
    if (!mac_str || strlen(mac_str) == 0) {
        debug(LOG_ERR, "Invalid MAC address in get_client_info request");
        
        json_object *j_type = json_object_new_string("get_client_info_error");
        json_object *j_error = json_object_new_string("Invalid MAC address");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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
    /* Detailed field descriptions for clients (hand-written for AI/clients) */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "id", json_object_new_string("Client internal id (int64)"));
    json_object_object_add(j_fd, "ip", json_object_new_string("IPv4 address of client (string)"));
    json_object_object_add(j_fd, "ip6", json_object_new_string("IPv6 address of client (string) if present"));
    json_object_object_add(j_fd, "mac", json_object_new_string("Client MAC address (string)"));
    json_object_object_add(j_fd, "token", json_object_new_string("Authentication token assigned to client (string)"));
    json_object_object_add(j_fd, "fw_connection_state", json_object_new_string("Firewall/connection state (int) - internal enum"));
    json_object_object_add(j_fd, "name", json_object_new_string("Optional client name (string)"));
    json_object_object_add(j_fd, "is_online", json_object_new_string("Is client currently online (boolean as int: 0/1)"));
    json_object_object_add(j_fd, "wired", json_object_new_string("Is client wired (boolean as int: 0/1)"));
    json_object_object_add(j_fd, "first_login", json_object_new_string("Epoch timestamp of first login (int64)"));
    /* counters subobject */
    json_object *j_cnt_desc = json_object_new_object();
    json_object_object_add(j_cnt_desc, "incoming_bytes", json_object_new_string("IPv4 incoming bytes (int64)"));
    json_object_object_add(j_cnt_desc, "incoming_packets", json_object_new_string("IPv4 incoming packets (int64)"));
    json_object_object_add(j_cnt_desc, "outgoing_bytes", json_object_new_string("IPv4 outgoing bytes (int64)"));
    json_object_object_add(j_cnt_desc, "outgoing_packets", json_object_new_string("IPv4 outgoing packets (int64)"));
    json_object_object_add(j_cnt_desc, "incoming_rate", json_object_new_string("IPv4 incoming rate (int, bytes/sec)"));
    json_object_object_add(j_cnt_desc, "outgoing_rate", json_object_new_string("IPv4 outgoing rate (int, bytes/sec)"));
    json_object_object_add(j_cnt_desc, "last_updated", json_object_new_string("Epoch timestamp when counters were last updated (int64)"));
    json_object_object_add(j_fd, "counters", j_cnt_desc);
    /* counters6 subobject */
    json_object *j_cnt6_desc = json_object_new_object();
    json_object_object_add(j_cnt6_desc, "incoming_bytes", json_object_new_string("IPv6 incoming bytes (int64)"));
    json_object_object_add(j_cnt6_desc, "incoming_packets", json_object_new_string("IPv6 incoming packets (int64)"));
    json_object_object_add(j_cnt6_desc, "outgoing_bytes", json_object_new_string("IPv6 outgoing bytes (int64)"));
    json_object_object_add(j_cnt6_desc, "outgoing_packets", json_object_new_string("IPv6 outgoing packets (int64)"));
    json_object_object_add(j_cnt6_desc, "incoming_rate", json_object_new_string("IPv6 incoming rate (int, bytes/sec)"));
    json_object_object_add(j_cnt6_desc, "outgoing_rate", json_object_new_string("IPv6 outgoing rate (int, bytes/sec)"));
    json_object_object_add(j_cnt6_desc, "last_updated", json_object_new_string("Epoch timestamp when counters6 were last updated (int64)"));
    json_object_object_add(j_fd, "counters6", j_cnt6_desc);
    json_object_object_add(j_data, "field_descriptions", j_fd);

    // Send response
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending client info response: %s", response_str);
    send_json_response(transport, j_response);
    
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
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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
    
    send_json_response(transport, j_response);
}

/**
 * @brief Handle get clients list request
 * 
 * Returns a list of all connected clients with their information.
 * 
 * @param j_req JSON request object (no parameters required)
 * @param transport Transport context for sending response
 */
void handle_get_clients_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    
    debug(LOG_INFO, "Get clients list request received");
    
    // Update client counters before retrieving information
    debug(LOG_DEBUG, "Updating client counters before retrieving clients list");
    if (fw_counters_update() == -1) {
        debug(LOG_WARNING, "Failed to update client counters, proceeding with cached data");
    }
    
    // Create clients array
    json_object *j_clients_array = json_object_new_array();
    
    // Get all clients
    LOCK_CLIENT_LIST();
    t_client *client = client_get_first_client();
    
    while (client) {
        // Create client object
        json_object *j_client = json_object_new_object();
        
        // Add client basic information
        json_object_object_add(j_client, "id", json_object_new_int64(client->id));
        
        if (client->ip) {
            json_object_object_add(j_client, "ip", json_object_new_string(client->ip));
        }
        
        if (client->ip6) {
            json_object_object_add(j_client, "ip6", json_object_new_string(client->ip6));
        }
        
        if (client->mac) {
            json_object_object_add(j_client, "mac", json_object_new_string(client->mac));
        }
        
        if (client->token) {
            json_object_object_add(j_client, "token", json_object_new_string(client->token));
        }
        
        json_object_object_add(j_client, "fw_connection_state", json_object_new_int(client->fw_connection_state));
        
        if (client->name) {
            json_object_object_add(j_client, "name", json_object_new_string(client->name));
        }
        
        json_object_object_add(j_client, "is_online", json_object_new_int(client->is_online));
        json_object_object_add(j_client, "wired", json_object_new_int(client->wired));
        json_object_object_add(j_client, "first_login", json_object_new_int64(client->first_login));
        
        // Add IPv4 counters
        json_object *j_counters = json_object_new_object();
        json_object_object_add(j_counters, "incoming_bytes", json_object_new_int64(client->counters.incoming_bytes));
        json_object_object_add(j_counters, "incoming_packets", json_object_new_int64(client->counters.incoming_packets));
        json_object_object_add(j_counters, "outgoing_bytes", json_object_new_int64(client->counters.outgoing_bytes));
        json_object_object_add(j_counters, "outgoing_packets", json_object_new_int64(client->counters.outgoing_packets));
        json_object_object_add(j_counters, "incoming_rate", json_object_new_int(client->counters.incoming_rate));
        json_object_object_add(j_counters, "outgoing_rate", json_object_new_int(client->counters.outgoing_rate));
        json_object_object_add(j_counters, "last_updated", json_object_new_int64(client->counters.last_updated));
        json_object_object_add(j_client, "counters", j_counters);
        
        // Add IPv6 counters
        json_object *j_counters6 = json_object_new_object();
        json_object_object_add(j_counters6, "incoming_bytes", json_object_new_int64(client->counters6.incoming_bytes));
        json_object_object_add(j_counters6, "incoming_packets", json_object_new_int64(client->counters6.incoming_packets));
        json_object_object_add(j_counters6, "outgoing_bytes", json_object_new_int64(client->counters6.outgoing_bytes));
        json_object_object_add(j_counters6, "outgoing_packets", json_object_new_int64(client->counters6.outgoing_packets));
        json_object_object_add(j_counters6, "incoming_rate", json_object_new_int(client->counters6.incoming_rate));
        json_object_object_add(j_counters6, "outgoing_rate", json_object_new_int(client->counters6.outgoing_rate));
        json_object_object_add(j_counters6, "last_updated", json_object_new_int64(client->counters6.last_updated));
        json_object_object_add(j_client, "counters6", j_counters6);
        
        // Add client to array
        json_object_array_add(j_clients_array, j_client);
        
        // Move to next client
        client = client->next;
    }
    
    UNLOCK_CLIENT_LIST();
    
    // Build success response
    json_object *j_type = json_object_new_string("get_clients_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "clients", j_clients_array);
    /* Describe the clients array and client object fields for AI/clients */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "clients", json_object_new_string("Array of client objects. Each object contains id, ip, ip6, mac, token, counters, counters6, etc."));
    json_object *j_client_desc = json_object_new_object();
    json_object_object_add(j_client_desc, "id", json_object_new_string("Client internal id (int64)"));
    json_object_object_add(j_client_desc, "ip", json_object_new_string("IPv4 address (string)"));
    json_object_object_add(j_client_desc, "ip6", json_object_new_string("IPv6 address (string) if present"));
    json_object_object_add(j_client_desc, "mac", json_object_new_string("MAC address (string)"));
    json_object_object_add(j_client_desc, "token", json_object_new_string("Auth token (string)"));
    json_object_object_add(j_client_desc, "fw_connection_state", json_object_new_string("Firewall/connection state (int)"));
    json_object_object_add(j_client_desc, "name", json_object_new_string("Optional human name for client (string)"));
    json_object_object_add(j_client_desc, "is_online", json_object_new_string("Online flag (0/1)"));
    json_object_object_add(j_client_desc, "wired", json_object_new_string("Wired flag (0/1)"));
    json_object_object_add(j_client_desc, "first_login", json_object_new_string("Epoch timestamp of first login (int64)"));
    json_object_object_add(j_fd, "client_object", j_client_desc);
    json_object_object_add(j_response, "field_descriptions", j_fd);

    // Send response
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending clients list response: %s", response_str);
    send_json_response(transport, j_response);
    
    
    debug(LOG_INFO, "Clients list sent successfully");
}

/**
 * @brief Handle set auth server configuration request
 * 
 * Updates the authentication server configuration (hostname, port, path).
 * 
 * @param j_req JSON request object with hostname, port, path fields
 * @param transport Transport context for sending response
 */
void handle_set_auth_server_request(json_object *j_req, api_transport_context_t *transport) {
    if (!j_req || !transport) {
        debug(LOG_ERR, "Invalid parameters for set_auth_server");
        return;
    }

    s_config *config = config_get_config();
    if (!config || !config->auth_servers) {
        debug(LOG_ERR, "Config or auth_servers is NULL");
        send_response(transport, "{\"error\":\"Internal configuration error\"}");
        return;
    }

    char *hostname = config->auth_servers->authserv_hostname;
    char *path = config->auth_servers->authserv_path;
    const char *tmp_host_name = NULL;
    const char *tmp_http_port = NULL;
    const char *tmp_path = NULL;

    // Parse JSON parameters
    json_object *jo_host_name = json_object_object_get(j_req, "hostname");
    json_object *jo_http_port = json_object_object_get(j_req, "port");
    json_object *jo_path = json_object_object_get(j_req, "path");

    const char *json_host = NULL;
    const char *json_port = NULL;
    const char *json_path = NULL;

    if (jo_host_name != NULL) {
        json_host = json_object_get_string(jo_host_name);
    }
    if (jo_http_port != NULL) {
        json_port = json_object_get_string(jo_http_port);
    }
    if (jo_path != NULL) {
        json_path = json_object_get_string(jo_path);
    }

    /* Update runtime config first (memory is authoritative) */
    LOCK_CONFIG();
    if (json_host != NULL && hostname && strcmp(hostname, json_host) != 0) {
        free(hostname);
        config->auth_servers->authserv_hostname = safe_strdup(json_host);
        tmp_host_name = config->auth_servers->authserv_hostname;
    }

    if (json_path != NULL && path && strcmp(path, json_path) != 0) {
        free(path);
        config->auth_servers->authserv_path = safe_strdup(json_path);
        tmp_path = config->auth_servers->authserv_path;
    }

    if (json_port != NULL) {
        config->auth_servers->authserv_http_port = atoi(json_port);
        /* store string form for persisting */
        tmp_http_port = json_port;
    }
    UNLOCK_CONFIG();

    debug(LOG_DEBUG, "Set auth server - hostname: %s, port: %s, path: %s",
          tmp_host_name ? tmp_host_name : "(unchanged)",
          tmp_http_port ? tmp_http_port : "(unchanged)",
          tmp_path ? tmp_path : "(unchanged)");

    /* runtime already updated above; persistence handled against the
     * selected auth 'config auth' section further below. Removed duplicate
     * writes to the 'wifidog' section to avoid overwriting unrelated state.
     */

    /* Persist changes to the config file: write into the selected auth 'config auth' section */
    char selected_section[128] = {0};
    if (uci_get_value("wifidogx", "wifidog", "selected_auth_server", selected_section, sizeof(selected_section)) == 0 && selected_section[0] != '\0') {
        if (tmp_host_name != NULL) {
            uci_set_value("wifidogx", selected_section, "auth_server_hostname", tmp_host_name);
        }
        if (tmp_path != NULL) {
            uci_set_value("wifidogx", selected_section, "auth_server_path", tmp_path);
        }
        if (tmp_http_port != NULL) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%d", config->auth_servers->authserv_http_port);
            uci_set_value("wifidogx", selected_section, "auth_server_port", portbuf);
        }
    } else {
        debug(LOG_WARNING, "No selected_auth_server found in UCI; skipping persistence to auth section");
    }

    // Send success response
    json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("success"));
    json_object_object_add(response, "message", json_object_new_string("Auth server configuration updated"));

    send_json_response(transport, response);
}

/**
 * @brief Handles a request to get the configured authentication server.
 *
 * Returns the current auth server hostname, port and path from runtime config.
 */
void handle_get_auth_server_request(json_object *j_req, api_transport_context_t *transport) {
    /* Return auth server configuration from runtime memory only.
     * Do not read from UCI or config files here. Protect access with
     * LOCK_CONFIG()/UNLOCK_CONFIG() to avoid races when other threads
     * may be updating the runtime config.
     */
    json_object *j_response = json_object_new_object();

    s_config *config = config_get_config();
    if (!config || !config->auth_servers) {
        debug(LOG_ERR, "Get auth server: Config or auth_servers is NULL");
        json_object_object_add(j_response, "type", json_object_new_string("get_auth_serv_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Internal configuration error"));
        send_json_response(transport, j_response);
        return;
    }

    /* Copy runtime values under lock into local buffers/vars so we only
     * read memory and then build the response from those copies. */
    char *hostname_copy = NULL;
    char *path_copy = NULL;
    int port_copy = 0;

    LOCK_CONFIG();
    if (config->auth_servers->authserv_hostname) {
        hostname_copy = safe_strdup(config->auth_servers->authserv_hostname);
    }
    port_copy = config->auth_servers->authserv_http_port;
    if (config->auth_servers->authserv_path) {
        path_copy = safe_strdup(config->auth_servers->authserv_path);
    }
    UNLOCK_CONFIG();

    json_object *j_data = json_object_new_object();
    if (hostname_copy) {
        json_object_object_add(j_data, "hostname", json_object_new_string(hostname_copy));
    }
    json_object_object_add(j_data, "port", json_object_new_int(port_copy));
    if (path_copy) {
        json_object_object_add(j_data, "path", json_object_new_string(path_copy));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_auth_serv_response"));
    json_object_object_add(j_response, "data", j_data);
    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "hostname", json_object_new_string("Auth server hostname (string) from runtime config"));
    json_object_object_add(j_fd, "port", json_object_new_string("Auth server HTTP port (int) from runtime config"));
    json_object_object_add(j_fd, "path", json_object_new_string("Auth server path (string) from runtime config"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);

    free(hostname_copy);
    free(path_copy);
}

/**
 * @brief Handle authentication request from WebSocket server
 *
 * Processes client authentication requests, adding clients to the allowed list
 * or enabling once-auth mode based on the request parameters.
 *
 * @param j_auth The JSON authentication request object
 */
void handle_auth_request(json_object *j_auth, api_transport_context_t *transport) {
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring auth request from server");
        send_response(transport, "{\"error\":\"Portal authentication is disabled\"}");
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
        // Send success response for once-auth
        char response_msg[128];
        snprintf(response_msg, sizeof(response_msg), 
                 "{\"status\":\"once_auth_enabled\",\"gw_id\":\"%s\"}", 
                 gw_id_str);
        send_response(transport, response_msg);
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
        // Send response indicating client already authenticated
        char response_msg[256];
        snprintf(response_msg, sizeof(response_msg), 
                 "{\"status\":\"already_authenticated\",\"client_ip\":\"%s\",\"client_mac\":\"%s\"}", 
                 client_ip_str, client_mac_str);
        send_response(transport, response_msg);
        return;
    }

    // Add new client with firewall rules
    LOCK_CLIENT_LIST();
    t_client *client = client_list_add(client_ip_str, client_mac_str, token_str, gw_setting);
    client->auth_type = AUTH_TYPE_AUTH_SERVER;
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

    // Send success response
    char response_msg[256];
    snprintf(response_msg, sizeof(response_msg), 
             "{\"status\":\"auth_success\",\"client_ip\":\"%s\",\"client_mac\":\"%s\"}", 
             client_ip_str, client_mac_str);
    send_response(transport, response_msg);
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
        
        send_json_response(transport, j_response);
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
    /* Describe firmware info: keys are release variables (strings) */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "data", json_object_new_string("Map of firmware/release keys to string values (e.g. DISTRIB_RELEASE, DISTRIB_ID). Keys vary by device image."));
    json_object_object_add(j_data, "field_descriptions", j_fd);

    // Send response
    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending firmware info response: %s", response_str);
    send_json_response(transport, j_response);

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
        
        send_json_response(transport, j_response);
        return;
    }
    
    const char *url_str = json_object_get_string(j_url);
    if (!url_str || strlen(url_str) == 0) {
        debug(LOG_ERR, "Invalid URL in firmware upgrade request");
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Missing or invalid 'url' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        send_json_response(transport, j_response);
        return;
    }
    
    // Validate URL format (basic check for HTTP/HTTPS)
    if (strncmp(url_str, "http://", 7) != 0 && strncmp(url_str, "https://", 8) != 0) {
        debug(LOG_ERR, "Invalid URL protocol in firmware upgrade request: %s", url_str);
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Invalid URL protocol, only HTTP/HTTPS allowed");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        send_json_response(transport, j_response);
        return;
    }
    
    // Validate URL length
    if (strlen(url_str) > 1024) {
        debug(LOG_ERR, "URL too long in firmware upgrade request");
        
        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("URL too long");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        
        send_json_response(transport, j_response);
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
    
    send_json_response(transport, j_response);
    
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
        
        send_json_response(transport, j_response);
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
        
        send_json_response(transport, j_response);
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

    send_json_response(transport, j_response);

    debug(LOG_INFO, "Device info updated successfully");
}

/**
 * @brief Handles a request to get stored device information (ap_longitude, ap_latitude, etc.)
 *
 * This returns the contents of the device_info structure saved in firmware (if present).
 */
void handle_get_device_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    debug(LOG_INFO, "Get device info request received");

    t_device_info *device_info = get_device_info();
    if (!device_info) {
        json_object *j_type = json_object_new_string("get_device_info_error");
        json_object *j_error = json_object_new_string("Device info not set");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_data = json_object_new_object();

    if (device_info->ap_device_id) {
        json_object_object_add(j_data, "ap_device_id", json_object_new_string(device_info->ap_device_id));
    }
    if (device_info->ap_mac_address) {
        json_object_object_add(j_data, "ap_mac_address", json_object_new_string(device_info->ap_mac_address));
    }
    if (device_info->ap_longitude) {
        json_object_object_add(j_data, "ap_longitude", json_object_new_string(device_info->ap_longitude));
    }
    if (device_info->ap_latitude) {
        json_object_object_add(j_data, "ap_latitude", json_object_new_string(device_info->ap_latitude));
    }
    if (device_info->location_id) {
        json_object_object_add(j_data, "location_id", json_object_new_string(device_info->location_id));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_device_info_response"));
    json_object_object_add(j_response, "data", j_data);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending device info response: %s", response_str);
    send_json_response(transport, j_response);

    debug(LOG_INFO, "Device info sent successfully");
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

    struct uci_context *w_ctx = NULL;
    struct uci_package *w_pkg = NULL;
    if (uci_open_package("wireless", &w_ctx, &w_pkg) != 0) {
        debug(LOG_ERR, "Failed to open UCI package: wireless");

        json_object *j_type = json_object_new_string("get_wifi_info_error");
        json_object *j_error = json_object_new_string("Failed to read wireless config");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    struct uci_element *e = NULL;
    uci_foreach_element(&w_pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->e.name || !sec->type) continue;

        if (strcmp(sec->type, "wifi-device") == 0) {
            int idx = -1;
            for (int i = 0; i < device_count; i++) {
                if (strcmp(devices[i].device_name, sec->e.name) == 0) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1 && device_count < 8) {
                idx = device_count++;
                strncpy(devices[idx].device_name, sec->e.name, sizeof(devices[idx].device_name) - 1);
                devices[idx].device_name[sizeof(devices[idx].device_name) - 1] = '\0';
            }
            if (idx < 0) continue;

            const char *type = uci_lookup_option_string(w_ctx, sec, "type");
            const char *path = uci_lookup_option_string(w_ctx, sec, "path");
            const char *band = uci_lookup_option_string(w_ctx, sec, "band");
            const char *channel = uci_lookup_option_string(w_ctx, sec, "channel");
            const char *htmode = uci_lookup_option_string(w_ctx, sec, "htmode");
            const char *cell_density = uci_lookup_option_string(w_ctx, sec, "cell_density");

            if (type) {
                strncpy(devices[idx].type, type, sizeof(devices[idx].type) - 1);
                devices[idx].type[sizeof(devices[idx].type) - 1] = '\0';
            }
            if (path) {
                strncpy(devices[idx].path, path, sizeof(devices[idx].path) - 1);
                devices[idx].path[sizeof(devices[idx].path) - 1] = '\0';
            }
            if (band) {
                strncpy(devices[idx].band, band, sizeof(devices[idx].band) - 1);
                devices[idx].band[sizeof(devices[idx].band) - 1] = '\0';
            }
            if (channel) {
                devices[idx].channel = atoi(channel);
            }
            if (htmode) {
                strncpy(devices[idx].htmode, htmode, sizeof(devices[idx].htmode) - 1);
                devices[idx].htmode[sizeof(devices[idx].htmode) - 1] = '\0';
            }
            if (cell_density) {
                devices[idx].cell_density = atoi(cell_density);
            }
            continue;
        }

        if (strcmp(sec->type, "wifi-iface") == 0) {
            int idx = -1;
            for (int i = 0; i < interface_count; i++) {
                if (strcmp(interfaces[i].interface_name, sec->e.name) == 0) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1 && interface_count < 32) {
                idx = interface_count++;
                strncpy(interfaces[idx].interface_name, sec->e.name, sizeof(interfaces[idx].interface_name) - 1);
                interfaces[idx].interface_name[sizeof(interfaces[idx].interface_name) - 1] = '\0';
            }
            if (idx < 0) continue;

            const char *device = uci_lookup_option_string(w_ctx, sec, "device");
            const char *mode = uci_lookup_option_string(w_ctx, sec, "mode");
            const char *ssid = uci_lookup_option_string(w_ctx, sec, "ssid");
            const char *key = uci_lookup_option_string(w_ctx, sec, "key");
            const char *encryption = uci_lookup_option_string(w_ctx, sec, "encryption");
            const char *network = uci_lookup_option_string(w_ctx, sec, "network");
            const char *mesh_id = uci_lookup_option_string(w_ctx, sec, "mesh_id");
            const char *disabled = uci_lookup_option_string(w_ctx, sec, "disabled");

            if (device) {
                strncpy(interfaces[idx].device, device, sizeof(interfaces[idx].device) - 1);
                interfaces[idx].device[sizeof(interfaces[idx].device) - 1] = '\0';
            }
            if (mode) {
                strncpy(interfaces[idx].mode, mode, sizeof(interfaces[idx].mode) - 1);
                interfaces[idx].mode[sizeof(interfaces[idx].mode) - 1] = '\0';
            }
            if (ssid) {
                strncpy(interfaces[idx].ssid, ssid, sizeof(interfaces[idx].ssid) - 1);
                interfaces[idx].ssid[sizeof(interfaces[idx].ssid) - 1] = '\0';
            }
            if (key) {
                strncpy(interfaces[idx].key, key, sizeof(interfaces[idx].key) - 1);
                interfaces[idx].key[sizeof(interfaces[idx].key) - 1] = '\0';
            }
            if (encryption) {
                strncpy(interfaces[idx].encryption, encryption, sizeof(interfaces[idx].encryption) - 1);
                interfaces[idx].encryption[sizeof(interfaces[idx].encryption) - 1] = '\0';
            }
            if (network) {
                strncpy(interfaces[idx].network, network, sizeof(interfaces[idx].network) - 1);
                interfaces[idx].network[sizeof(interfaces[idx].network) - 1] = '\0';
            }
            if (mesh_id) {
                strncpy(interfaces[idx].mesh_id, mesh_id, sizeof(interfaces[idx].mesh_id) - 1);
                interfaces[idx].mesh_id[sizeof(interfaces[idx].mesh_id) - 1] = '\0';
            }
            if (disabled) {
                interfaces[idx].disabled = atoi(disabled);
            }
        }
    }

    uci_close_package(w_ctx, w_pkg);

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
    
    struct uci_context *n_ctx = NULL;
    struct uci_package *n_pkg = NULL;
    if (uci_open_package("network", &n_ctx, &n_pkg) == 0) {
        struct uci_element *ne = NULL;
        uci_foreach_element(&n_pkg->sections, ne) {
            struct uci_section *sec = uci_to_section(ne);
            if (!sec || !sec->e.name) continue;

            const char *interface_name = sec->e.name;
            if (strcmp(interface_name, "loopback") == 0 || strcmp(interface_name, "globals") == 0) {
                continue;
            }

            const char *proto = uci_lookup_option_string(n_ctx, sec, "proto");
            if (!proto || strcmp(proto, "static") != 0) {
                continue;
            }

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
        uci_close_package(n_ctx, n_pkg);
    }
    json_object_object_add(j_data, "available_networks", j_networks);

    // Build success response
    json_object *j_type = json_object_new_string("get_wifi_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);
    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();

    /* radio_device describes the structure for each radio key (e.g., radio0, radio1) */
    json_object *j_radio_desc = json_object_new_object();
    json_object_object_add(j_radio_desc, "type", json_object_new_string("Radio device driver/type string (e.g., mac80211)"));
    json_object_object_add(j_radio_desc, "path", json_object_new_string("Kernel/platform path for the radio device (string)"));
    json_object_object_add(j_radio_desc, "band", json_object_new_string("Radio band (string) e.g., 2g, 5g"));
    json_object_object_add(j_radio_desc, "channel", json_object_new_string("Operating channel (int)"));
    json_object_object_add(j_radio_desc, "htmode", json_object_new_string("HT mode (string), e.g., HT20, HE80"));
    json_object_object_add(j_radio_desc, "cell_density", json_object_new_string("Cell density (int)"));

    /* Interface object description */
    json_object *j_iface_desc = json_object_new_object();
    json_object_object_add(j_iface_desc, "interface_name", json_object_new_string("Logical interface name (string)"));
    json_object_object_add(j_iface_desc, "mode", json_object_new_string("Interface mode (string) e.g., ap, sta"));
    json_object_object_add(j_iface_desc, "network", json_object_new_string("Associated network name (string)"));
    json_object_object_add(j_iface_desc, "encryption", json_object_new_string("Encryption type (string) e.g., psk2"));
    json_object_object_add(j_iface_desc, "disabled", json_object_new_string("Disabled flag (boolean)"));
    json_object_object_add(j_iface_desc, "ssid", json_object_new_string("SSID string (if configured)"));
    json_object_object_add(j_iface_desc, "key", json_object_new_string("Pre-shared key/passphrase (if present)"));
    json_object_object_add(j_iface_desc, "mesh_id", json_object_new_string("Mesh identifier string (if present)"));

    json_object_object_add(j_radio_desc, "interfaces", j_iface_desc);

    json_object_object_add(j_fd, "radio_device", j_radio_desc);
    json_object_object_add(j_fd, "available_networks", json_object_new_string("Array of available static network interface names (array of strings)"));

    json_object_object_add(j_response, "field_descriptions", j_fd);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending complete Wi-Fi info response: %s", response_str);
    send_json_response(transport, j_response);
    
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

    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "domains", json_object_new_string("Array of trusted domain strings (exact hostnames)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
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
    send_json_response(transport, j_response);
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

    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "domains", json_object_new_string("Array of trusted wildcard domain strings (may include leading '*.' patterns)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
}

void handle_get_trusted_mac_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_macs = json_object_new_array();

    char *macs = mqtt_get_serialize_maclist(TRUSTED_MAC);
    if (macs && strlen(macs) > 0) {
        char *saveptr = NULL;
        char *token = strtok_r(macs, ",", &saveptr);
        while (token) {
            trim_newline(token);
            json_object_array_add(j_macs, json_object_new_string(token));
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    if (macs) free(macs);

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_mac_response"));
    json_object_object_add(j_response, "macs", j_macs);

    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "macs", json_object_new_string("Array of trusted MAC address strings (format aa:bb:cc:dd:ee:ff)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
}

void handle_sync_trusted_mac_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    // Clear existing trusted maclist in memory and firewall
    clear_trusted_maclist();

    // Clear existing trusted macs from UCI configuration (persisted option: trustd_macs)
    uci_del_list_option("wifidogx", "common", "trustd_macs");

    // Accept either "macs" array or "values" array for compatibility
    json_object *j_macs = NULL;
    if (json_object_object_get_ex(j_req, "macs", &j_macs) && json_object_is_type(j_macs, json_type_array)) {
        int len = json_object_array_length(j_macs);
        // Build comma-separated string for add_trusted_maclist
        size_t buf_len = len * 18 + 16; // estimate
        char *buf = calloc(1, buf_len);
        if (buf) {
            char *p = buf;
            for (int i = 0; i < len; i++) {
                json_object *j_mac = json_object_array_get_idx(j_macs, i);
                if (!json_object_is_type(j_mac, json_type_string)) continue;
                const char *mac = json_object_get_string(j_mac);
                if (!mac) continue;
                // Persist each MAC into UCI list option 'trustd_macs'
                uci_add_list_value("wifidogx", "common", "trustd_macs", mac);
                if (p != buf) { *p++ = ','; }
                strncpy(p, mac, buf_len - (p - buf) - 1);
                p += strlen(p);
            }
            if (strlen(buf) > 0) add_trusted_maclist(buf);
            free(buf);
        }
    } else if (json_object_object_get_ex(j_req, "values", &j_macs) && json_object_is_type(j_macs, json_type_array)) {
        int len = json_object_array_length(j_macs);
        size_t buf_len = len * 18 + 16;
        char *buf = calloc(1, buf_len);
        if (buf) {
            char *p = buf;
            for (int i = 0; i < len; i++) {
                json_object *j_mac = json_object_array_get_idx(j_macs, i);
                if (!json_object_is_type(j_mac, json_type_string)) continue;
                const char *mac = json_object_get_string(j_mac);
                if (!mac) continue;
                // Persist each MAC into UCI list option 'trustd_macs'
                uci_add_list_value("wifidogx", "common", "trustd_macs", mac);
                if (p != buf) { *p++ = ','; }
                strncpy(p, mac, buf_len - (p - buf) - 1);
                p += strlen(p);
            }
            if (strlen(buf) > 0) add_trusted_maclist(buf);
            free(buf);
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_mac_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted MACs synchronized successfully"));
    send_json_response(transport, j_response);
}

/* forward declare helper used below */
static char *select_radio_by_band(const char *band_pref);

/**
 * @brief Scan for nearby Wi-Fi networks, filtered by band
 *
 * Request JSON parameters (optional):
 * - "band": "2g" or "5g" (default "2g")
 *
 * Response: { "type":"scan_wifi_response", "networks": [ { ssid, bssid, frequency_ghz, signal_dbm, encryption } ] }
 */
void handle_scan_wifi_request(json_object *j_req, api_transport_context_t *transport) {
    const char *band = "2g";
    json_object *j_band = json_object_object_get(j_req, "band");
    if (j_band && json_object_is_type(j_band, json_type_string)) {
        const char *b = json_object_get_string(j_band);
        if (b && (strcmp(b, "5g") == 0 || strcmp(b, "2g") == 0)) band = b;
    }

    json_object *j_response = json_object_new_object();
    json_object *j_networks = json_object_new_array();

    /* Use ubus to perform scan and return JSON results.
     * Select radio dynamically via select_radio_by_band(); fall back to
     * legacy names when not available.
     */
    char *device = select_radio_by_band(band);
    if (!device) {
        /* Fallback should map 5g->radio1 and 2g->radio0 on common OpenWrt layouts. */
        device = strdup(strcmp(band, "5g") == 0 ? "radio1" : "radio0");
    }
    if (!device) {
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to select scan device"));
        send_json_response(transport, j_response);
        return;
    }
    debug(LOG_INFO, "scan_wifi: requested band=%s, selected device=%s", band, device ? device : "(null)");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ubus call iwinfo scan '{\"device\":\"%s\"}' 2>/dev/null", device);

    FILE *sfp = popen(cmd, "r");
    if (!sfp) {
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to invoke ubus iwinfo scan"));
        if (device) free(device);
        send_json_response(transport, j_response);
        return;
    }

    // Read entire output into buffer
    size_t out_len = 0;
    size_t buf_size = 4096;
    char *out = malloc(buf_size);
    if (!out) {
        pclose(sfp);
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Memory allocation failed"));
        send_json_response(transport, j_response);
        return;
    }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), sfp) != NULL) {
        size_t chunk_len = strlen(chunk);
        if (out_len + chunk_len + 1 > buf_size) {
            buf_size = (out_len + chunk_len + 1) * 2;
            char *n = realloc(out, buf_size);
            if (!n) break;
            out = n;
        }
        memcpy(out + out_len, chunk, chunk_len);
        out_len += chunk_len;
        out[out_len] = '\0';
    }
    pclose(sfp);

    if (out_len == 0) {
        free(out);
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_response"));
        json_object_object_add(j_response, "networks", j_networks);
        json_object *j_fd_empty = json_object_new_object();
        json_object_object_add(j_fd_empty, "networks", json_object_new_string("Array of network objects found by scan"));
        json_object_object_add(j_response, "field_descriptions", j_fd_empty);
        send_json_response(transport, j_response);
        return;
    }

    // Parse JSON output from ubus
    json_object *j_scan = NULL;
    j_scan = json_tokener_parse(out);
    free(out);
    if (!j_scan) {
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to parse ubus iwinfo JSON output"));
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_results = NULL;
    if (json_object_object_get_ex(j_scan, "results", &j_results) && json_object_is_type(j_results, json_type_array)) {
        size_t n = json_object_array_length(j_results);
        for (size_t i = 0; i < n; i++) {
            json_object *entry = json_object_array_get_idx(j_results, i);
            if (!entry || !json_object_is_type(entry, json_type_object)) continue;

            json_object *j_net = json_object_new_object();
            json_object *tmp = NULL;

            if (json_object_object_get_ex(entry, "ssid", &tmp) && json_object_is_type(tmp, json_type_string))
                json_object_object_add(j_net, "ssid", json_object_new_string(json_object_get_string(tmp)));

            if (json_object_object_get_ex(entry, "bssid", &tmp) && json_object_is_type(tmp, json_type_string))
                json_object_object_add(j_net, "bssid", json_object_new_string(json_object_get_string(tmp)));

            if (json_object_object_get_ex(entry, "band", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "band", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "channel", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "channel", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "mhz", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "mhz", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "signal", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "signal_dbm", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "quality", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "quality", json_object_new_int(json_object_get_int(tmp)));

            // encryption object
            json_object *j_enc = NULL;
            if (json_object_object_get_ex(entry, "encryption", &j_enc) && json_object_is_type(j_enc, json_type_object)) {
                json_object *j_enc_out = json_object_new_object();
                json_object *jen = NULL;
                if (json_object_object_get_ex(j_enc, "enabled", &jen) && json_object_is_type(jen, json_type_boolean))
                    json_object_object_add(j_enc_out, "enabled", json_object_new_boolean(json_object_get_boolean(jen)));

                // wpa array
                if (json_object_object_get_ex(j_enc, "wpa", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "wpa", json_object_get(jen));
                }

                if (json_object_object_get_ex(j_enc, "authentication", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "authentication", json_object_get(jen));
                }

                if (json_object_object_get_ex(j_enc, "ciphers", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "ciphers", json_object_get(jen));
                }

                json_object_object_add(j_net, "encryption", j_enc_out);
            }

            json_object_array_add(j_networks, j_net);
        }
    }

    json_object_put(j_scan);

    json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_response"));
    json_object_object_add(j_response, "networks", j_networks);
    /* Describe fields */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "networks", json_object_new_string("Array of network objects found by scan"));
    json_object_object_add(j_response, "field_descriptions", j_fd);
    send_json_response(transport, j_response);
    if (device) free(device);
}

/*
 * Production-ready implementation to configure a Wi-Fi client (STA) that
 * attaches to `wwan` (upstream via DHCP). This function performs the
 * following, safely and deterministically:
 * - ensures a `wwan` interface exists in /etc/config/network
 * - selects a radio dynamically via `ubus` (falls back to sensible default)
 * - removes any existing `mode='sta'` wifi-iface sections
 * - atomically creates a new wifi-iface section and sets properties
 * - optionally triggers a non-blocking `wifi reload`
 * - validates that `wwan` obtains an IP address
 *
 * Request JSON parameters (required):
 * - "ssid": SSID to join
 * Optional:
 * - "bssid": BSSID (MAC) of target AP
 * - "encryption": encryption type (e.g., psk2, sae, none)
 * - "key": PSK/password if required by encryption
 * - "band": "2g" or "5g" (preferred band; best-effort)
 * - "apply": boolean (default true) - whether to trigger wifi reload/apply
 */
static int ensure_wwan_interface(void) {
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        return -1;
    }

    int exists = 0;
    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->e.name) continue;
        if (strcmp(sec->e.name, "wwan") == 0) {
            exists = 1;
            break;
        }
    }

    if (!exists) {
        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        char expr[] = "network.wwan=interface";
        if (uci_lookup_ptr(ctx, &ptr, expr, true) != UCI_OK || uci_set(ctx, &ptr) != UCI_OK) {
            uci_close_package(ctx, pkg);
            return -1;
        }
    }

    if (uci_set_option_with_ctx(ctx, "network", "wwan", "proto", "dhcp") != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    if (uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    uci_close_package(ctx, pkg);
    return 0;
}

static char *select_radio_by_band(const char *band_pref) {
    debug(LOG_DEBUG, "select_radio_by_band: start, band_pref=%s", band_pref ? band_pref : "(null)");
    // Try ubus call network.wireless status
    FILE *fp = popen("ubus call network.wireless status 2>/dev/null", "r");
    if (!fp) return NULL;
    size_t buf_size = 4096, len = 0; char *out = malloc(buf_size);
    if (!out) { pclose(fp); return NULL; }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), fp) != NULL) {
        size_t cl = strlen(chunk);
        if (len + cl + 1 > buf_size) {
            buf_size = (len + cl + 1) * 2;
            char *n = realloc(out, buf_size);
            if (!n) break;
            out = n;
        }
        memcpy(out + len, chunk, cl);
        len += cl; out[len] = '\0';
    }
    pclose(fp);
    if (len == 0) { free(out); return NULL; }

    json_object *j = json_tokener_parse(out);
    free(out);
    if (!j) return NULL;

    /* Only use strong signals to infer band:
     * 1) explicit `band`, 2) numeric `channel`, 3) `hwmode`.
     * Do NOT use broad htmode substring matching (e.g. VHT80 contains "HT"),
     * which can misclassify 5g radios as 2g.
     */
    json_object_object_foreach(j, key, val) {
        if (!json_object_is_type(val, json_type_object)) continue;

        json_object *j_config = NULL;
        if (json_object_object_get_ex(val, "config", &j_config) && json_object_is_type(j_config, json_type_object)) {
            // Check explicit band string first
            json_object *j_band = NULL;
            if (json_object_object_get_ex(j_config, "band", &j_band) && json_object_is_type(j_band, json_type_string)) {
                const char *band = json_object_get_string(j_band);
                if (band && strcmp(band_pref, band) == 0) {
                    debug(LOG_INFO, "select_radio_by_band: matched by config.band, band_pref=%s, radio=%s", band_pref, key);
                    char *res = strdup(key);
                    json_object_put(j);
                    return res;
                }
            }

            // Check channel (can be string or int)
            json_object *j_channel = NULL;
            if (json_object_object_get_ex(j_config, "channel", &j_channel)) {
                int ch = 0;
                if (json_object_is_type(j_channel, json_type_string)) {
                    ch = atoi(json_object_get_string(j_channel));
                } else if (json_object_is_type(j_channel, json_type_int)) {
                    ch = json_object_get_int(j_channel);
                }
                if (ch > 0) {
                    if (strcmp(band_pref, "5g") == 0 && ch > 14) {
                        debug(LOG_INFO, "select_radio_by_band: matched by channel, band_pref=%s, channel=%d, radio=%s", band_pref, ch, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                    if (strcmp(band_pref, "2g") == 0 && ch <= 14) {
                        debug(LOG_INFO, "select_radio_by_band: matched by channel, band_pref=%s, channel=%d, radio=%s", band_pref, ch, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                }
            }

            // hwmode fallback: 11a -> 5g, 11b/11g -> 2g
            json_object *j_hwmode = NULL;
            if (json_object_object_get_ex(j_config, "hwmode", &j_hwmode) && json_object_is_type(j_hwmode, json_type_string)) {
                const char *hw = json_object_get_string(j_hwmode);
                if (hw) {
                    if (strcmp(band_pref, "5g") == 0 && strstr(hw, "11a")) {
                        debug(LOG_INFO, "select_radio_by_band: matched by hwmode, band_pref=%s, hwmode=%s, radio=%s", band_pref, hw, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                    if (strcmp(band_pref, "2g") == 0 && (strstr(hw, "11b") || strstr(hw, "11g"))) {
                        debug(LOG_INFO, "select_radio_by_band: matched by hwmode, band_pref=%s, hwmode=%s, radio=%s", band_pref, hw, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                }
            }
        }
    }

    json_object_put(j);
    debug(LOG_WARNING, "select_radio_by_band: no matched radio for band_pref=%s", band_pref ? band_pref : "(null)");
    return NULL;
}

static int remove_existing_sta_iface(void) {
    struct uci_package *pkg = NULL;
    struct uci_context *ctx = NULL;
    if (uci_open_package("wireless", &ctx, &pkg) != 0) {
        return -1;
    }

    char sections[64][128];
    int section_count = 0;

    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || strcmp(sec->type, "wifi-iface") != 0) {
            continue;
        }

        const char *mode = uci_lookup_option_string(ctx, sec, "mode");
        if (!mode || strcmp(mode, "sta") != 0) {
            continue;
        }

        if (!e->name || e->name[0] == '\0') {
            continue;
        }

        // Deduplicate
        int exists = 0;
        for (int i = 0; i < section_count; i++) {
            if (strcmp(sections[i], e->name) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists && section_count < (int)(sizeof(sections) / sizeof(sections[0]))) {
            strncpy(sections[section_count], e->name, sizeof(sections[section_count]) - 1);
            sections[section_count][sizeof(sections[section_count]) - 1] = '\0';
            section_count++;
        }
    }

    if (section_count == 0) {
        uci_close_package(ctx, pkg);
        return 0;
    }

    for (int i = 0; i < section_count; i++) {
        char path[256];
        int n = snprintf(path, sizeof(path), "wireless.%s", sections[i]);
        if (n <= 0 || n >= (int)sizeof(path)) {
            uci_close_package(ctx, pkg);
            return -1;
        }

        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));

        if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK || !ptr.s) {
            uci_close_package(ctx, pkg);
            return -1;
        }

        if (uci_delete(ctx, &ptr) != UCI_OK) {
            uci_close_package(ctx, pkg);
            return -1;
        }
    }

    /* Keep old behavior: only stage changes; commit remains caller-controlled. */
    if (uci_save_package_with_ctx(ctx, pkg) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    uci_close_package(ctx, pkg);
    return 0;
}

static int verify_sta_connection(int timeout_seconds) {
    // Poll ubus for wwan status
    for (int i = 0; i < timeout_seconds; i++) {
        FILE *fp = popen("ubus call network.interface.wwan status 2>/dev/null", "r");
        if (!fp) { sleep(1); continue; }
        size_t buf_size = 2048, len = 0; char *out = malloc(buf_size);
        if (!out) { pclose(fp); sleep(1); continue; }
        out[0] = '\0'; char chunk[512];
        while (fgets(chunk, sizeof(chunk), fp) != NULL) {
            size_t cl = strlen(chunk);
            if (len + cl + 1 > buf_size) { buf_size = (len + cl + 1) * 2; char *n = realloc(out, buf_size); if (!n) break; out = n; }
            memcpy(out + len, chunk, cl); len += cl; out[len] = '\0';
        }
        pclose(fp);
        if (len == 0) { free(out); sleep(1); continue; }
        json_object *j = json_tokener_parse(out);
        free(out);
        if (!j) { sleep(1); continue; }
        json_object *j_up = NULL;
        if (json_object_object_get_ex(j, "up", &j_up) && json_object_is_type(j_up, json_type_boolean)) {
            int up = json_object_get_boolean(j_up);
            json_object_put(j);
            if (up) return 0;
            sleep(1);
            continue;
        }
        json_object_put(j);
        sleep(1);
    }
    return -1;
}

void handle_set_wifi_relay_request(json_object *j_req, api_transport_context_t *transport) {
    // Validate required SSID
    json_object *j_ssid = json_object_object_get(j_req, "ssid");
    if (!j_ssid || !json_object_is_type(j_ssid, json_type_string)) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Missing required 'ssid' parameter"));
        send_json_response(transport, j_err);
        return;
    }
    const char *ssid = json_object_get_string(j_ssid);

    // Optional params
    const char *bssid = NULL; json_object *j_bssid = json_object_object_get(j_req, "bssid");
    if (j_bssid && json_object_is_type(j_bssid, json_type_string)) bssid = json_object_get_string(j_bssid);

    const char *encryption = NULL; json_object *j_enc = json_object_object_get(j_req, "encryption");
    if (j_enc && json_object_is_type(j_enc, json_type_string)) encryption = json_object_get_string(j_enc);

    const char *key = NULL; json_object *j_key = json_object_object_get(j_req, "key");
    if (j_key && json_object_is_type(j_key, json_type_string)) key = json_object_get_string(j_key);

    const char *band = "2g"; json_object *j_band = json_object_object_get(j_req, "band");
    if (j_band && json_object_is_type(j_band, json_type_string)) {
        const char *b = json_object_get_string(j_band);
        if (b && (strcmp(b, "5g") == 0 || strcmp(b, "2g") == 0)) band = b;
    }

    int apply = 1; json_object *j_apply = json_object_object_get(j_req, "apply");
    if (j_apply && json_object_is_type(j_apply, json_type_boolean)) apply = json_object_get_boolean(j_apply);

    // Validate encryption/key semantics
    if (encryption && strcmp(encryption, "none") == 0 && key) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("'key' must not be provided when encryption is 'none'"));
        send_json_response(transport, j_err);
        return;
    }
    if (encryption && (strncmp(encryption, "psk", 3) == 0 || strcmp(encryption, "sae") == 0) && !key) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("'key' is required for WPA-PSK/SAE encryption"));
        send_json_response(transport, j_err);
        return;
    }

    // Ensure wwan exists
    if (ensure_wwan_interface() != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to ensure 'wwan' network interface"));
        send_json_response(transport, j_err);
        return;
    }

    // Select radio dynamically
    char *radio = select_radio_by_band(band);
    if (!radio) {
        // Fallback: reasonable names
        radio = strdup(strcmp(band, "5g") == 0 ? "radio1" : "radio0");
    }

    // Remove existing STA ifaces
    if (remove_existing_sta_iface() != 0) {
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to remove existing STA interfaces"));
        send_json_response(transport, j_err);
        return;
    }

    // Add new wifi-iface and configure with libuci
    char secbuf[128] = {0};
    struct uci_context *w_ctx = NULL;
    struct uci_package *w_pkg = NULL;
    if (uci_open_package("wireless", &w_ctx, &w_pkg) != 0) {
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to open wireless package"));
        send_json_response(transport, j_err);
        return;
    }

    struct uci_section *new_sec = NULL;
    if (uci_add_section(w_ctx, w_pkg, "wifi-iface", &new_sec) != UCI_OK || !new_sec || !new_sec->e.name) {
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to create wireless section"));
        send_json_response(transport, j_err);
        return;
    }

    strncpy(secbuf, new_sec->e.name, sizeof(secbuf) - 1);
    secbuf[sizeof(secbuf) - 1] = '\0';

    int set_failed = 0;
    if (uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "device", radio) != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "mode", "sta") != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "ssid", ssid) != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "network", "wwan") != 0) set_failed = 1;
    if (!set_failed && bssid && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "bssid", bssid) != 0) set_failed = 1;
    if (!set_failed && encryption && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "encryption", encryption) != 0) set_failed = 1;
    if (!set_failed && key && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "key", key) != 0) set_failed = 1;

    if (set_failed) {
        if (secbuf[0]) {
            uci_delete_section_with_ctx(w_ctx, "wireless", secbuf);
            uci_save_package_with_ctx(w_ctx, w_pkg);
        }
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to apply wireless settings"));
        send_json_response(transport, j_err);
        return;
    }

    if (uci_save_commit_package_with_ctx(w_ctx, &w_pkg) != 0 || uci_commit_package_by_name("network") != 0) {
        if (secbuf[0]) {
            uci_delete_section_with_ctx(w_ctx, "wireless", secbuf);
            uci_save_commit_package_with_ctx(w_ctx, &w_pkg);
        }
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to commit UCI changes"));
        send_json_response(transport, j_err);
        return;
    }

    uci_close_package(w_ctx, w_pkg);

    // Trigger wifi reload if requested (non-blocking)
    if (apply) {
        // spawn in background
        int wifi_ret = system("wifi reload >/dev/null 2>&1 &");
        if (wifi_ret != 0) debug(LOG_WARNING, "wifi reload background command failed (ret=%d)", wifi_ret);
    }

    // Verify connection (poll ubus for wwan up)
    int ok = verify_sta_connection(8); // wait up to 8s

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("set_wifi_sta_response"));
    if (ok == 0) {
        json_object_object_add(j_resp, "status", json_object_new_string("success"));
        json_object_object_add(j_resp, "message", json_object_new_string("STA configured and wwan is up"));
    } else {
        json_object_object_add(j_resp, "status", json_object_new_string("error"));
        json_object_object_add(j_resp, "message", json_object_new_string("STA configured but wwan did not come up within timeout"));
    }
    send_json_response(transport, j_resp);

    free(radio);
}

void handle_delete_wifi_relay_request(json_object *j_req, api_transport_context_t *transport) {
    int apply = 1;
    json_object *j_apply = json_object_object_get(j_req, "apply");
    if (j_apply && json_object_is_type(j_apply, json_type_boolean)) {
        apply = json_object_get_boolean(j_apply);
    }

    // Remove existing STA/relay interfaces
    if (remove_existing_sta_iface() != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("delete_wifi_relay_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to remove existing STA interfaces"));
        send_json_response(transport, j_err);
        return;
    }

    // Commit wireless changes
    if (uci_commit_package_by_name("wireless") != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("delete_wifi_relay_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to commit wireless changes"));
        send_json_response(transport, j_err);
        return;
    }

    // Optionally apply runtime changes
    if (apply) {
        int wifi_ret = system("wifi reload >/dev/null 2>&1 &");
        if (wifi_ret != 0) {
            debug(LOG_WARNING, "delete_wifi_relay: wifi reload background command failed (ret=%d)", wifi_ret);
        }
    }

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("delete_wifi_relay_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "apply", json_object_new_boolean(apply));
    json_object_object_add(j_resp, "message", json_object_new_string("WiFi relay/STA configuration removed"));
    send_json_response(transport, j_resp);
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
    send_json_response(transport, j_response);
}

void handle_set_wifi_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data;

    if (!json_object_object_get_ex(j_req, "data", &j_data)) {
        debug(LOG_ERR, "Set wifi info request missing 'data' field");
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'data' field"));
        send_json_response(transport, j_response);
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
    debug(LOG_INFO, "Sending Wi-Fi configuration response: %s", response_str);
    send_json_response(transport, j_response);
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
    send_json_response(transport, j_response);
}
