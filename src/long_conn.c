// SPDX-License-Identifier: GPL-3.0-only

#include "long_conn.h"
#include "mqtt_thread.h"
#include "ws_thread.h"
#include "conf.h"
#include "wd_util.h"
#include "firewall.h"
#include "centralserver.h"
#include "api_handlers.h"
#include "portal_cache.h"
#include "debug.h"
#include "safe.h"
#include "api_handlers_internal.h"
#include "util.h"
#include <pthread.h>
#include <string.h>
#include <time.h>

#define LONG_CONN_ACK_STALE_SEC 90

static pthread_mutex_t long_conn_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t last_ack_at;
static int authdown_latched;

void
long_conn_note_ack(void)
{
	int was_down;

	pthread_mutex_lock(&long_conn_lock);
	last_ack_at = get_monotonic_time();
	was_down = authdown_latched;
	authdown_latched = 0;
	pthread_mutex_unlock(&long_conn_lock);

	mark_auth_online();
	if (was_down) {
		fw_set_authup();
	}
}

int
long_conn_is_healthy(void)
{
	time_t ack;
	int connected;
	s_config *config = config_get_config();
	int stale_sec = (config && config->checkinterval > 0) ? (config->checkinterval * 2) : LONG_CONN_ACK_STALE_SEC;
	if (stale_sec < LONG_CONN_ACK_STALE_SEC) {
		stale_sec = LONG_CONN_ACK_STALE_SEC;
	}

	if (!get_mqtt_server() && !get_ws_server()) {
		return 0;
	}

	connected = mqtt_is_connected() || ws_is_connected();
	pthread_mutex_lock(&long_conn_lock);
	ack = last_ack_at;
	pthread_mutex_unlock(&long_conn_lock);

	if (!connected || ack == 0) {
		return 0;
	}
	time_t now = get_monotonic_time();
	if (now < ack) {
		return 1;
	}
	return (now - ack) <= stale_sec;
}

void
long_conn_handle_server_response(json_object *jobj)
{
	json_object *j_data = NULL;
	json_object *j_type = NULL;
	const char *type = NULL;

	if (!jobj) {
		return;
	}
	if (!json_object_object_get_ex(jobj, "data", &j_data) || !j_data) {
		return;
	}
	if (json_object_object_get_ex(j_data, "type", &j_type) && j_type) {
		type = json_object_get_string(j_type);
	}
	if (!type) {
		return;
	}

	if (strcmp(type, "heartbeat") == 0 || strcmp(type, "heartbeart") == 0 ||
	    strcmp(type, "connect") == 0 || strcmp(type, "bootstrap") == 0) {
		long_conn_note_ack();
		handle_gateway_state_heartbeat_request(j_data, NULL);
		if (strcmp(type, "connect") == 0 || strcmp(type, "bootstrap") == 0) {
			portal_cache_trigger_update(j_data);
		}
	} else if (strcmp(type, "counters_response") == 0 || strcmp(type, "counters") == 0) {
		long_conn_note_ack();
		process_auth_server_counter_v2_json(j_data, NULL);
	}
}

static json_object *
wrap_counters_payload(char *body)
{
	json_object *root;
	json_object *rid;

	if (!body) {
		return NULL;
	}
	root = json_tokener_parse(body);
	free(body);
	if (!root) {
		return NULL;
	}
	json_object_object_add(root, "op", json_object_new_string("counters"));
	rid = api_generate_req_id();
	if (rid) {
		json_object_object_add(root, "req_id", rid);
	}
	return root;
}

void
long_conn_publish_counters(void)
{
	char *body;
	json_object *root;
	const char *payload;

	if (is_local_auth_mode()) {
		return;
	}

	body = fw_build_counter_v2_payload();
	root = wrap_counters_payload(body);
	if (!root) {
		return;
	}
	payload = json_object_to_json_string(root);
	if (payload) {
		if (mqtt_is_connected()) {
			mqtt_publish_c2s(payload);
		} else if (ws_is_connected()) {
			ws_publish_text(payload);
		}
	}
	json_object_put(root);
}

void
long_conn_publish_logout(const char *gw_id, const char *mac, const char *ip)
{
	json_object *root;
	json_object *rid;
	const char *payload;
	const char *device_id;

	root = json_object_new_object();
	if (!root) {
		return;
	}
	json_object_object_add(root, "op", json_object_new_string("logout"));
	device_id = get_device_id();
	if (device_id) {
		json_object_object_add(root, "device_id", json_object_new_string(device_id));
	}
	if (gw_id && gw_id[0]) {
		json_object_object_add(root, "gw_id", json_object_new_string(gw_id));
	}
	if (mac && mac[0]) {
		json_object_object_add(root, "mac", json_object_new_string(mac));
	}
	if (ip && ip[0]) {
		json_object_object_add(root, "ip", json_object_new_string(ip));
	}
	rid = api_generate_req_id();
	if (rid) {
		json_object_object_add(root, "req_id", rid);
	}

	payload = json_object_to_json_string(root);
	if (payload) {
		if (mqtt_is_connected()) {
			mqtt_publish_c2s(payload);
		} else if (ws_is_connected()) {
			ws_publish_text(payload);
		}
	}
	json_object_put(root);
}
