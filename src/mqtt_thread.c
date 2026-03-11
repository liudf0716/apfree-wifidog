
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <mosquitto.h>

/* Internal flag indicating whether MQTT client is connected. */
_Atomic int mqtt_connected = 0;
static pthread_mutex_t mqtt_client_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mosquitto *mqtt_client_instance = NULL;
/* control for graceful shutdown */
static _Atomic int mqtt_thread_should_stop = 0;
static pthread_mutex_t mqtt_thread_ctrl_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t mqtt_thread_ctrl_cond = PTHREAD_COND_INITIALIZER;

/* cached connection parameters (copied from config) to allow reconnect from other threads) */
static char *mqtt_host_cached = NULL;
static int mqtt_port_cached = 0;
static int mqtt_keepalive_cached = 60;
static const int mqtt_reconnect_backstop_sec = 10;
static bool has_default_route(void);

static void
send_mqtt_response(struct mosquitto *mosq, const unsigned int req_id, int res_id, const char *msg, const s_config *config)
{
	char *topic = NULL;
	char *res_data = NULL;
	safe_asprintf(&topic, "wifidogx/v1/%s/s2c/response", get_device_id());
	safe_asprintf(&res_data, "{\"req_id\":%d,\"response\":\"%d\",\"msg\":\"%s\"}", req_id, res_id, msg==NULL?"null":msg);
	debug(LOG_DEBUG, "send mqtt response: topic is %s msg is %s", topic, res_data);
	mosquitto_publish(mosq, NULL, topic, strlen(res_data), res_data, 0, false);
	free(topic);
	free(res_data);
}

static void
process_mqtt_request(struct mosquitto *mosq, const char *data, s_config *config)
{
	unsigned int req_id = 0;
	
	json_object *json_request = json_tokener_parse(data);
	if (is_error(json_request)) {
		debug(LOG_INFO, "user request is not valid");
		send_mqtt_response(mosq, req_id, 400, "Invalid JSON request", config);
		return;
	}

	// Get req_id from JSON payload (v1 format)
	json_object *jo_req_id = json_object_object_get(json_request, "req_id");
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

	// Handle upward reports directly (not routed through downlink command handlers)
	if (strcmp(op, "heartbeat") == 0 || strcmp(op, "connect") == 0 || strcmp(op, "bootstrap") == 0) {
		debug(LOG_INFO, "Received upward report via MQTT: %s (req_id: %u)", op, req_id);
		// For MQTT upward reports: acknowledge receipt if needed
		// Currently upward reports don't require a response back to device
		// This is different from WebSocket where device sends proactively
		destroy_transport_context(transport);
		json_object_put(json_request);
		return;
	}

	// Route downlink commands through API dispatch
	if (!api_dispatch_request(op, json_request, transport)) {
		debug(LOG_ERR, "Unknown MQTT operation type: %s", op);
		send_mqtt_response(mosq, req_id, 400, "Unknown operation", config);
	}

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

		/* Always route MQTT payloads through the unified API dispatcher.
		 * The legacy dedicated shell/command topic handling has been removed
		 * in favor of the `shell` operation handled by api_routes.
		 */
		process_mqtt_request(mosq, message->payload, config);
	}
}

static void
mqtt_connect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	char *s2c_request_topic = NULL;
	char *c2s_response_topic = NULL;

	if (rc == 0) {
		/* connected successfully */
		mqtt_connected = 1;

		/* Subscribe to s2c/request (Server to Client requests)") */
		safe_asprintf(&s2c_request_topic, "wifidogx/v1/%s/s2c/request", get_device_id());
		mosquitto_subscribe(mosq, NULL, s2c_request_topic, 0); // qos is 0

		/* Subscribe to c2s/response (Client to Server responses)  */
		safe_asprintf(&c2s_response_topic, "wifidogx/v1/%s/c2s/response", get_device_id());
		mosquitto_subscribe(mosq, NULL, c2s_response_topic, 0); // qos is 0

		free(s2c_request_topic);
		free(c2s_response_topic);
	} else {
		mqtt_connected = 0;
		debug(LOG_WARNING, "MQTT connect callback: failed with rc=%d (%s)", rc, mosquitto_strerror(rc));
	}
}

static void
mqtt_disconnect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	/* Mark MQTT as disconnected */
	(void)mosq;
	(void)obj;
	/* clear connected flag */
	mqtt_connected = 0;
	debug(LOG_INFO, "MQTT disconnected (rc=%d)", rc);
}

/* removed mosquitto log callback */

void thread_mqtt(void *arg)
{
	s_config *config = arg;
	int major = 0, minor = 0, revision = 0;
	struct mosquitto *mosq = NULL;
	const char *host = config->mqtt_server->hostname;
	int  port 	= config->mqtt_server->port;
	char *username 	= config->mqtt_server->username;
	char *password 	= config->mqtt_server->password;
	char *cafile = config->mqtt_server->cafile;
	int use_tls = config->mqtt_server->use_ssl ? 1 : 0;
	int  keepalive = 60;
	int  retval = 0;

	if (!host || !*host) {
		debug(LOG_ERR, "MQTT server hostname is empty");
		return;
	}

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

	/* expose client instance for out-of-thread reconnect trigger */
	pthread_mutex_lock(&mqtt_client_lock);
	mqtt_client_instance = mosq;
	/* cache host/port/keepalive for use by mqtt_request_reconnect() */
	if (mqtt_host_cached) {
		free(mqtt_host_cached);
		mqtt_host_cached = NULL;
	}
	if (host) {
		mqtt_host_cached = strdup(host);
	}
	mqtt_port_cached = port;
	mqtt_keepalive_cached = keepalive;
	pthread_mutex_unlock(&mqtt_client_lock);
   	
	
	if (use_tls) {
		const char *ca_path = (cafile && *cafile) ? cafile : "/etc/ssl/certs/ca-certificates.crt";
		int tls_rc = mosquitto_tls_set(mosq, ca_path, NULL, NULL, NULL, NULL);
		if (tls_rc != MOSQ_ERR_SUCCESS) {
			debug(LOG_ERR, "mosquitto_tls_set failed for MQTTS: rc=%d (%s)", tls_rc, mosquitto_strerror(tls_rc));
			pthread_mutex_lock(&mqtt_client_lock);
			mqtt_client_instance = NULL;
			if (mqtt_host_cached) {
				free(mqtt_host_cached);
				mqtt_host_cached = NULL;
			}
			pthread_mutex_unlock(&mqtt_client_lock);
			mosquitto_destroy(mosq);
			mosquitto_lib_cleanup();
			return;
		}

		/* Keep existing behavior: skip cert verification by default. */
		int insecure_rc = mosquitto_tls_insecure_set(mosq, true);
		if (insecure_rc != MOSQ_ERR_SUCCESS) {
			debug(LOG_WARNING, "mosquitto_tls_insecure_set failed: rc=%d (%s)", insecure_rc, mosquitto_strerror(insecure_rc));
		}
		debug(LOG_INFO, "MQTT transport: MQTTS (TLS enabled), broker=%s:%d", host, port);
	} else {
		debug(LOG_INFO, "MQTT transport: MQTT (plain TCP), broker=%s:%d", host, port);
	}

	mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
	mosquitto_disconnect_callback_set(mosq, mqtt_disconnect_callback);
	mosquitto_message_callback_set(mosq, mqtt_message_callback);

	if (username != NULL) {
		mosquitto_username_pw_set(mosq, username, password);
	}

	/* Use libmosquitto automatic reconnect handling instead of app-level retry loop.
	 * Configure reconnect delay (initial 5s, max 60s) with exponential backoff. */
	mosquitto_reconnect_delay_set(mosq, 5, 60, true);

	/* Try to start a non-blocking connect; the loop thread will manage retries after disconnects. */
	retval = mosquitto_connect_async(mosq, host, port, keepalive);
	if (retval == MOSQ_ERR_SUCCESS) {
		debug(LOG_INFO, "mosquitto_connect_async initiated to %s:%d", host, port);
	} else if (retval == MOSQ_ERR_ERRNO) {
		debug(LOG_INFO, "mosquitto_connect_async error: %s", strerror(errno));
	} else {
		debug(LOG_INFO, "mosquitto_connect_async error: %s", mosquitto_strerror(retval));
	}

	/* Start background network handling thread provided by libmosquitto. */
	if (mosquitto_loop_start(mosq) != MOSQ_ERR_SUCCESS) {
		debug(LOG_WARNING, "mosquitto_loop_start failed, falling back to loop_forever");
		retval = mosquitto_loop_forever(mosq, -1, 1);
		/* mosquitto_loop_forever only returns on error or finish */
	} else {
		/* Wait for stop signal and provide a periodic reconnect backstop. */
		pthread_mutex_lock(&mqtt_thread_ctrl_lock);
		while (!mqtt_thread_should_stop) {
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += mqtt_reconnect_backstop_sec;

			int wait_rc = pthread_cond_timedwait(&mqtt_thread_ctrl_cond, &mqtt_thread_ctrl_lock, &ts);
			if (mqtt_thread_should_stop) {
				break;
			}
			if (wait_rc == ETIMEDOUT && !mqtt_connected && has_default_route()) {
				pthread_mutex_unlock(&mqtt_thread_ctrl_lock);
				mqtt_request_reconnect();
				pthread_mutex_lock(&mqtt_thread_ctrl_lock);
			}
		}
		pthread_mutex_unlock(&mqtt_thread_ctrl_lock);

		/* Stop the libmosquitto loop; finish work and return */
		mosquitto_loop_stop(mosq, true);
	}

	/* Ensure connected flag is cleared when loop exits */
	mqtt_connected = 0;

	pthread_mutex_lock(&mqtt_client_lock);
	mqtt_client_instance = NULL;
	if (mqtt_host_cached) {
		free(mqtt_host_cached);
		mqtt_host_cached = NULL;
	}
	pthread_mutex_unlock(&mqtt_client_lock);

	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();
}

int mqtt_is_connected(void)
{
	return mqtt_connected != 0;
}

static bool has_default_route(void)
{
	FILE *f = fopen("/proc/net/route", "r");
	if (!f)
		return false;
	char line[256];
	/* skip header */
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return false;
	}
	while (fgets(line, sizeof(line), f)) {
		char iface[64];
		char dest_s[32];
		if (sscanf(line, "%63s %31s", iface, dest_s) >= 2) {
			unsigned long dest = strtoul(dest_s, NULL, 16);
			if (dest == 0) {
				fclose(f);
				return true;
			}
		}
	}
	fclose(f);
	return false;
}

void mqtt_request_reconnect(void)
{
	struct mosquitto *mosq = NULL;

	pthread_mutex_lock(&mqtt_client_lock);
	mosq = mqtt_client_instance;
	/* if no client or thread not running, nothing to do */
	if (!mosq) {
		pthread_mutex_unlock(&mqtt_client_lock);
		debug(LOG_DEBUG, "disreconnect requested but client is not initialized");
		return;
	}

	/* If already connected, let library keep the connection; nothing to do. */
	if (mqtt_connected) {
		pthread_mutex_unlock(&mqtt_client_lock);
		debug(LOG_DEBUG, "MQTT reconnect requested but already connected");
		return;
	}

	/* Keep default route check as requested */
	if (!has_default_route()) {
		pthread_mutex_unlock(&mqtt_client_lock);
		debug(LOG_INFO, "MQTT reconnect requested but no default route; skipping immediate reconnect");
		return;
	}

	/* Request a connect from the library in a thread-safe way.
	 * We avoid calling mosquitto_reconnect_async to prevent mixing reconnect strategies.
	 * Instead, call mosquitto_connect_async when disconnected — lib will manage retries
	 * according to reconnect_delay_set. */
	if (!mqtt_host_cached) {
		pthread_mutex_unlock(&mqtt_client_lock);
		debug(LOG_WARNING, "MQTT reconnect requested but connection parameters unavailable");
		return;
	}

	debug(LOG_INFO, "MQTT reconnect requested: attempting connect to %s:%d", mqtt_host_cached, mqtt_port_cached);
	int rc = mosquitto_connect_async(mosq, mqtt_host_cached, mqtt_port_cached, mqtt_keepalive_cached);
	pthread_mutex_unlock(&mqtt_client_lock);
	if (rc == MOSQ_ERR_SUCCESS) {
		debug(LOG_INFO, "mosquitto_connect_async initiated from reconnect request");
	} else if (rc == MOSQ_ERR_ERRNO) {
		debug(LOG_WARNING, "mosquitto_connect_async errno: %s", strerror(errno));
	} else {
		debug(LOG_WARNING, "mosquitto_connect_async failed: %s", mosquitto_strerror(rc));
	}
}

