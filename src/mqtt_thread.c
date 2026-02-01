
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "mqtt_thread.h"
#include "api_handlers.h"
#include "wdctlx_thread.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"
#include "wd_util.h"
#include "centralserver.h"
#include "client_list.h"

static void
send_mqtt_response(struct mosquitto *mosq, const unsigned int req_id, int res_id, const char *msg, const s_config *config)
{
	char *topic = NULL;
	char *res_data = NULL;
	safe_asprintf(&topic, "wifidogx/v1/%s/response", get_device_id());
	safe_asprintf(&res_data, "{\"req_id\":%d,\"response\":\"%d\",\"msg\":\"%s\"}", req_id, res_id, msg==NULL?"null":msg);
	debug(LOG_DEBUG, "send mqtt response: topic is %s msg is %s", topic, res_data);
	mosquitto_publish(mosq, NULL, topic, strlen(res_data), res_data, 0, false);
	free(topic);
	free(res_data);
}

// Special handlers that need custom processing (MQTT-specific)
static bool
handle_special_operation(const char *op, struct mosquitto *mosq, unsigned int req_id, 
                         json_object *json_request, api_transport_context_t *transport, 
                         s_config *config)
{
	if (strcmp(op, "save_rule") == 0) {
		user_cfg_save();
		send_mqtt_response(mosq, req_id, 200, "Ok", config);
		return true;
	}
	
	// TODO operations - return 501 Not Implemented
	const char *todo_ops[] = {
		"reset", "reset_device", "update_config", "qos", "set_default_qos",
		"uci", "get_traffic_stats", "wan_change", "alarm", NULL
	};
	
	for (int i = 0; todo_ops[i] != NULL; i++) {
		if (strcmp(op, todo_ops[i]) == 0) {
			char msg[128];
			snprintf(msg, sizeof(msg), "%s not implemented yet", op);
			send_mqtt_response(mosq, req_id, 501, msg, config);
			return true;
		}
	}
	
	return false;
}

static void
process_mqtt_request(struct mosquitto *mosq, const char *data, s_config *config)
{
	json_object *json_request = json_tokener_parse(data);
	if (is_error(json_request)) {
		debug(LOG_INFO, "user request is not valid");
		send_mqtt_response(mosq, req_id, 400, "Invalid JSON request", config);
		return;
	}

	// Get req_id from JSON payload (v1 format)
	json_object *jo_req_id = json_object_object_get(json_request, "req_id");
	unsigned int req_id = 0;
	if (jo_req_id) {
		req_id = json_object_get_int(jo_req_id);
	} else {
		debug(LOG_INFO, "No req_id in request");
		json_object_put(json_request);
		return;
	}

	// Get operation type
	json_object *jo_op = json_object_object_get(json_request, "op");
	if (!jo_op) {
		debug(LOG_INFO, "No op item in request");
		json_object_put(json_request);
		return;
	}

	const char *op = json_object_get_string(jo_op);
	if (!op) {
		debug(LOG_ERR, "Invalid operation type in JSON (null string)");
		json_object_put(json_request);
		return;
	}

	// Create MQTT transport context
	api_transport_context_t *transport = create_mqtt_transport_context(mosq, req_id);
	if (!transport) {
		debug(LOG_ERR, "Failed to create MQTT transport context");
		json_object_put(json_request);
		send_mqtt_response(mosq, req_id, 500, "Internal error", config);
		return;
	}

	debug(LOG_DEBUG, "Processing MQTT operation: %s (req_id: %u)", op, req_id);

	// Check for special operations first
	if (handle_special_operation(op, mosq, req_id, json_request, transport, config)) {
		goto cleanup;
	}

	// Route to handler using unified API dispatch
	if (!api_dispatch_request(op, json_request, transport)) {
		debug(LOG_ERR, "Unknown MQTT operation type: %s", op);
		send_mqtt_response(mosq, req_id, 400, "Unknown operation", config);
	}

cleanup:
	// Clean up transport context and JSON
	destroy_transport_context(transport);
	json_object_put(json_request);
}

static void 
mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	s_config *config = obj;

	debug(LOG_INFO, "MQTT message received on topic: %s", message->topic);
	if (message->payloadlen) {
		debug(LOG_DEBUG, "topic is %s, data is %s", message->topic, message->payload);
		process_mqtt_request(mosq, message->payload, config);
	}
}

static void
mqtt_connect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	char *default_topic = NULL;
	safe_asprintf(&default_topic, "wifidogx/v1/%s/request", get_device_id());
	mosquitto_subscribe(mosq, NULL, default_topic, 0); // qos is 0
	free(default_topic);
}

void thread_mqtt(void *arg)
{
	s_config *config = arg;
	int major = 0, minor = 0, revision = 0;
	struct mosquitto *mosq = NULL;
	char *host 	= config->mqtt_server->hostname;
	int  port 	= config->mqtt_server->port;
	char *username 	= config->mqtt_server->username;
	char *password 	= config->mqtt_server->password;
	char *cafile = config->mqtt_server->cafile;
	int  keepalive = 60;
	int  retval = 0;

 	mosquitto_lib_version(&major, &minor, &revision);
    debug(LOG_DEBUG, "Mosquitto library version : %d.%d.%d\n", major, minor, revision); 

    /* Init mosquitto library */
    mosquitto_lib_init();

     /* Create a new mosquitto client instance */
    mosq = mosquitto_new(get_device_id(), true, config);
    if( mosq == NULL ) {
        switch(errno){
            case ENOMEM:
                debug(LOG_INFO, "Error: Out of memory.\n");
                break;
            case EINVAL:
                debug(LOG_INFO, "Error: Invalid id and/or clean_session.\n");
                break;
        }
        mosquitto_lib_cleanup();
        return ;
    }
   	
   	// Only set TLS if cafile is configured
   	if (cafile != NULL) {
   		if (mosquitto_tls_set(mosq, cafile, NULL, NULL, NULL, NULL)) {
   			debug(LOG_INFO, "Error : Problem setting TLS option");
        	mosquitto_destroy(mosq);
        	mosquitto_lib_cleanup();
            return ;
   		}

   		// Attention! this setting is not secure, but can simplify our deploy
        if (mosquitto_tls_insecure_set(mosq, true)) {
        	debug(LOG_INFO, "Error : Problem setting TLS insecure option");
        	mosquitto_destroy(mosq);
        	mosquitto_lib_cleanup();
            return ;
        }
   	} else {
   		debug(LOG_DEBUG, "TLS not configured for MQTT connection");
   	}

    mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
    mosquitto_message_callback_set(mosq, mqtt_message_callback);

	if (username != NULL) {
		mosquitto_username_pw_set(mosq, username, password);
	}

   	switch( retval = mosquitto_connect(mosq, host, port, keepalive) ) {
        case MOSQ_ERR_INVAL:
            debug(LOG_INFO, "Error : %s\n", mosquitto_strerror(retval)); 
            break;
        case MOSQ_ERR_ERRNO:
            debug(LOG_INFO, "Error : %s\n", strerror(errno));
            break;
        case MOSQ_ERR_SUCCESS:
            debug(LOG_INFO, "Successfully connected to MQTT broker at %s:%d", host, port);
            break;
        default:
            debug(LOG_INFO, "MQTT connection error: %s", mosquitto_strerror(retval));
            break;
    }

    retval = mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

