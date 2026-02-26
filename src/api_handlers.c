// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE
#include "common.h"
#include "api_handlers.h"
#include "debug.h"
#include "api_handlers_internal.h"

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
    const api_route_entry_t *routes = api_get_routes();
    for (const api_route_entry_t *route = routes; route->name != NULL; route++) {
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
int send_response(api_transport_context_t *transport, const char *message) {
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
void send_json_response(api_transport_context_t *transport, json_object *j_response)
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
 * @brief Safe UCI configuration setter with input validation
 * 
 * @param config_path UCI configuration path
 * @param value Value to set
 * @return 0 on success, -1 on error
 */
int run_command_capture(const char *cmd, char **out_str, int *exit_status)
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

/* System/Firmware handlers moved to api_handlers_sys.c */
