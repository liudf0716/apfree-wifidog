// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE
#include "common.h"
#include "api_handlers.h"
#include "debug.h"
#include "api_handlers_internal.h"
#include <limits.h>

// Forward declaration of ws_send function (will be implemented in ws_thread.c)
extern void ws_send(struct evbuffer *buf, const char *msg, const size_t len, int frame_type);

// WebSocket frame types
#define TEXT_FRAME 0x1



static bool transport_should_echo_req_id(const api_transport_context_t *transport)
{
    return transport && transport->req_id;
}

json_object *api_response_new(const char *type)
{
    json_object *j_response = json_object_new_object();
    if (!j_response) {
        return NULL;
    }

    json_object_object_add(j_response, "type",
                           json_object_new_string(type && type[0] ? type : "generic_response"));
    json_object_object_add(j_response, "data", json_object_new_object());

    return j_response;
}

json_object *api_response_get_data(json_object *j_response)
{
    if (!j_response) {
        return NULL;
    }

    json_object *j_data = NULL;
    if (!json_object_object_get_ex(j_response, "data", &j_data) ||
        !json_object_is_type(j_data, json_type_object)) {
        j_data = json_object_new_object();
        json_object_object_add(j_response, "data", j_data);
    }

    return j_data;
}

void api_response_set_success(json_object *j_response, const char *message)
{
    if (!j_response) {
        return;
    }

    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "code", json_object_new_int(0));
    json_object_object_add(j_response, "message",
                           json_object_new_string(message && message[0] ? message : "OK"));
}

void api_response_set_error(json_object *j_response, int code, const char *message)
{
    if (!j_response) {
        return;
    }

    json_object_object_add(j_response, "status", json_object_new_string("error"));
    json_object_object_add(j_response, "code",
                           json_object_new_int(code ? code : 1000));
    json_object_object_add(j_response, "message",
                           json_object_new_string(message && message[0] ? message : "Error"));
}

static void maybe_attach_req_id(api_transport_context_t *transport, json_object *j_response)
{
    if (!transport_should_echo_req_id(transport) || !j_response ||
        !json_object_is_type(j_response, json_type_object)) {
        return;
    }

    json_object *existing = NULL;
    if (json_object_object_get_ex(j_response, "req_id", &existing)) {
        return;
    }

    json_object_object_add(j_response, "req_id", json_object_get(transport->req_id));
}

void api_transport_set_req_id(api_transport_context_t *transport, json_object *req_id)
{
    if (!transport) {
        return;
    }

    if (transport->req_id) {
        json_object_put(transport->req_id);
        transport->req_id = NULL;
    }

    if (req_id) {
        transport->req_id = json_object_get(req_id);
    }
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
 * @param transport Transport context
 * @param message Message to send
 * @param length Length of message
 * @return 0 on success, -1 on error
 */
static int websocket_send_response(api_transport_context_t *transport, const char *message, size_t length) {
    struct bufferevent *bev = transport ? (struct bufferevent *)transport->transport_ctx : NULL;
    if (!bev || !message) {
        return -1;
    }
    
    ws_send(bufferevent_get_output(bev), message, length, TEXT_FRAME);
    return 0;
}

/**
 * @brief MQTT-specific send response implementation
 * 
 * @param transport Transport context
 * @param message Message to send
 * @param length Length of message
 * @return 0 on success, -1 on error
 */
static int mqtt_send_response(api_transport_context_t *transport, const char *message, size_t length) {
    void *mosq = transport ? transport->transport_ctx : NULL;
    if (!mosq || !message) {
        debug(LOG_ERR, "mqtt_send_response: Invalid context or message");
        return -1;
    }

    char *topic = NULL;
    // Get device ID (external function)
    extern const char* get_device_id(void);
    
    // Format topic and response
    if (asprintf(&topic, "wifidogx/v1/%s/s2c/response", get_device_id()) < 0) {
        debug(LOG_ERR, "mqtt_send_response: Failed to allocate topic");
        return -1;
    }

    debug(LOG_INFO, "mqtt_send_response: Publishing to topic: %s", topic);
    
    // Publish via mosquitto library
    int ret = mosquitto_publish(mosq, NULL, topic, 
                               length, message, 0, false);
    
    debug(LOG_INFO, "mqtt_send_response: mosquitto_publish returned: %d", ret);
    
    free(topic);
    
    return ret == 0 ? 0 : -1;
}

/**
 * @brief Create a MQTT transport context
 * 
 * @param mosq The mosquitto instance
 * @param req_id Request ID for correlation
 * @return Allocated transport context, or NULL on error
 */
api_transport_context_t* create_mqtt_transport_context(void *mosq, json_object *req_id) {
    if (!mosq) {
        return NULL;
    }

    api_transport_context_t *transport = malloc(sizeof(api_transport_context_t));
    if (!transport) {
        return NULL;
    }
    
    transport->transport_ctx = mosq;
    transport->send_response = mqtt_send_response;
    transport->protocol_name = "mqtt";
    transport->req_id = NULL;
    api_transport_set_req_id(transport, req_id);
    
    return transport;
}

/**
 * @brief Create a WebSocket transport context
 * 
 * @param bev The bufferevent for WebSocket connection
 * @return Allocated transport context, or NULL on error
 */
api_transport_context_t* create_websocket_transport_context(struct bufferevent *bev, json_object *req_id) {
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
    transport->req_id = NULL;
    api_transport_set_req_id(transport, req_id);
    
    return transport;
}

/**
 * @brief Destroy transport context
 * 
 * @param transport Transport context to destroy
 */
void destroy_transport_context(api_transport_context_t *transport) {
    if (transport) {
        if (transport->req_id) {
            json_object_put(transport->req_id);
            transport->req_id = NULL;
        }
        // transport_ctx is owned by the caller for both MQTT and WebSocket.
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

    json_object *j_message = json_tokener_parse(message);
    if (j_message && json_object_is_type(j_message, json_type_object)) {
        json_object *existing_response = NULL;
        if (json_object_object_get_ex(j_message, "response", &existing_response)) {
            /* Already in MQTT envelope format (e.g. error response), only ensure req_id exists. */
            maybe_attach_req_id(transport, j_message);
            const char *annotated = json_object_to_json_string(j_message);
            int rc = transport->send_response(transport, annotated, strlen(annotated));
            json_object_put(j_message);
            return rc;
        }

        /* Wrap handler output into unified MQTT-style success envelope. */
        json_object *j_envelope = json_object_new_object();
        if (!j_envelope) {
            json_object_put(j_message);
            return transport->send_response(transport, message, strlen(message));
        }

        if (transport->req_id) {
            json_object_object_add(j_envelope, "req_id", json_object_get(transport->req_id));
        }
        json_object_object_add(j_envelope, "response", json_object_new_string("200"));
        json_object_object_add(j_envelope, "data", j_message);

        const char *wrapped = json_object_to_json_string(j_envelope);
        int rc = transport->send_response(transport, wrapped, strlen(wrapped));
        json_object_put(j_envelope);
        return rc;
    }

    if (j_message) {
        json_object_put(j_message);
    }

    /* Non-JSON payload fallback: still use MQTT success envelope with string data. */
    json_object *j_envelope = json_object_new_object();
    if (!j_envelope) {
        return transport->send_response(transport, message, strlen(message));
    }
    if (transport->req_id) {
        json_object_object_add(j_envelope, "req_id", json_object_get(transport->req_id));
    }
    json_object_object_add(j_envelope, "response", json_object_new_string("200"));
    json_object_object_add(j_envelope, "data", json_object_new_string(message));

    const char *wrapped = json_object_to_json_string(j_envelope);
    int rc = transport->send_response(transport, wrapped, strlen(wrapped));
    json_object_put(j_envelope);
    return rc;
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
    maybe_attach_req_id(transport, j_response);
    add_auto_field_descriptions(j_response);

    const char *response_str = json_object_to_json_string(j_response);
    if (response_str) {
        send_response(transport, response_str);
    }
}

/**
 * @brief Generate a request identifier for tracing.
 *
 * The identifier is an unsigned integer composed from the current
 * UNIX millisecond timestamp and a small random suffix to reduce
 * collision probability across devices. The returned json_object is
 * a JSON integer and the caller must free it with json_object_put().
 */
json_object *api_generate_req_id(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long ms = (unsigned long long)tv.tv_sec * 1000ULL + (tv.tv_usec / 1000ULL);
    unsigned int suffix = (unsigned int)(random() % 1000);
    /* Compose a numeric id: ms * 1000 + suffix. Cast to 32-bit int
     * using json_object_new_int() as requested. To avoid negative
     * values from 32-bit overflow, clamp the generated value into
     * the positive 32-bit signed range. */
    unsigned long long id = ms * 1000ULL + (unsigned long long)suffix;
    /* INT_MAX from <limits.h> is used as the clamp upper bound. */
    int clamped = (int)(id % (unsigned long long)INT_MAX);
    if (clamped <= 0) {
        /* Ensure strictly positive */
        clamped = 1;
    }
    return json_object_new_int(clamped);
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
