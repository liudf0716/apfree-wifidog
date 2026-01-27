
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

static void
process_mqtt_request(struct mosquitto *mosq, const char *data, s_config *config)
{
	json_object *json_request = json_tokener_parse(data);
	if (is_error(json_request)) {
		debug(LOG_INFO, "user request is not valid");
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

	// Route message to appropriate handler based on operation type
	// Same pattern as WebSocket
	if (!strcmp(op, "heartbeat") || !strcmp(op, "connect") || !strcmp(op, "bootstrap")) {
		handle_get_sys_info_request(json_request, transport);
	} else if (!strcmp(op, "auth")) {
		handle_auth_request(json_request);
	} else if (!strcmp(op, "kickoff")) {
		handle_kickoff_request(json_request, transport);
	} else if (!strcmp(op, "tmp_pass")) {
		handle_tmp_pass_request(json_request);
	} else if (!strcmp(op, "get_firmware_info")) {
		handle_get_firmware_info_request(json_request, transport);
	} else if (!strcmp(op, "firmware_upgrade") || !strcmp(op, "ota")) {
		handle_firmware_upgrade_request(json_request, transport);
	} else if (!strcmp(op, "update_device_info")) {
		handle_update_device_info_request(json_request, transport);
	} else if (!strcmp(op, "set_trusted") || !strcmp(op, "sync_trusted_domain")) {
		handle_sync_trusted_domain_request(json_request, transport);
	} else if (!strcmp(op, "get_trusted_domains") || !strcmp(op, "show_trusted")) {
		handle_get_trusted_domains_request(json_request, transport);
	} else if (!strcmp(op, "sync_trusted_wildcard_domains")) {
		handle_sync_trusted_wildcard_domains_request(json_request, transport);
	} else if (!strcmp(op, "get_trusted_wildcard_domains")) {
		handle_get_trusted_wildcard_domains_request(json_request, transport);
	} else if (!strcmp(op, "reboot_device") || !strcmp(op, "reboot")) {
		handle_reboot_device_request(json_request, transport);
	} else if (!strcmp(op, "get_wifi_info")) {
		handle_get_wifi_info_request(json_request, transport);
	} else if (!strcmp(op, "set_wifi_info")) {
		handle_set_wifi_info_request(json_request, transport);
	} else if (!strcmp(op, "get_sys_info") || !strcmp(op, "get_status")) {
		handle_get_sys_info_request(json_request, transport);
	} else if (!strcmp(op, "get_client_info") || !strcmp(op, "get_clients")) {
		handle_get_client_info_request(json_request, transport);
	} else if (!strcmp(op, "save_rule")) {
		user_cfg_save();
		send_mqtt_response(mosq, req_id, 200, "Ok", config);
	} else if (!strcmp(op, "set_auth_serv")) {
		handle_set_auth_server_request(json_request, transport);
	} else if (!strcmp(op, "reset") || !strcmp(op, "reset_device")) {
		// TODO: Implement reset functionality
		send_mqtt_response(mosq, req_id, 501, "Reset not implemented", config);
	} else if (!strcmp(op, "update_config")) {
		// TODO: Implement update_config functionality
		send_mqtt_response(mosq, req_id, 501, "Update config not implemented", config);
	} else if (!strcmp(op, "qos")) {
		// TODO: Implement QoS functionality
		send_mqtt_response(mosq, req_id, 501, "QoS not implemented", config);
	} else if (!strcmp(op, "set_default_qos")) {
		// TODO: Implement default QoS functionality
		send_mqtt_response(mosq, req_id, 501, "Default QoS not implemented", config);
	} else if (!strcmp(op, "uci")) {
		// TODO: Implement UCI functionality
		send_mqtt_response(mosq, req_id, 501, "UCI not implemented", config);
	} else if (!strcmp(op, "get_traffic_stats")) {
		// TODO: Implement traffic stats functionality
		send_mqtt_response(mosq, req_id, 501, "Traffic stats not implemented", config);
	} else if (!strcmp(op, "wan_change")) {
		// TODO: Implement WAN change notification
		send_mqtt_response(mosq, req_id, 501, "WAN change not implemented", config);
	} else if (!strcmp(op, "alarm")) {
		// TODO: Implement alarm functionality
		send_mqtt_response(mosq, req_id, 501, "Alarm not implemented", config);
	} else {
		debug(LOG_ERR, "Unknown operation type: %s", op);
		send_mqtt_response(mosq, req_id, 400, "Unknown operation", config);
	}

	// Clean up transport context
	destroy_transport_context(transport);
	json_object_put(json_request);
}

static void 
mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	s_config *config = obj;

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

        mosquitto_destroy(mosq);
     	mosquitto_lib_cleanup();
        return ;
    }

    retval = mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

