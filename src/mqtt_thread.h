
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef	_MQTT_THREAD_H_
#define	_MQTT_THREAD_H_

#include "conf.h"

// Implemented operation handlers
void set_trusted_op(void *mosq, const char *value, const int req_id, const s_config *config);
void del_trusted_op(void *mosq, const char *value, const int req_id, const s_config *config);
void clear_trusted_op(void *mosq, const char *value, const int req_id, const s_config *config);
void show_trusted_op(void *mosq, const char *value, const int req_id, const s_config *config);
void save_rule_op(void *mosq, const char *value, const int req_id, const s_config *config);
void get_status_op(void *mosq, const char *value, const int req_id, const s_config *config);
void reboot_device_op(void *mosq, const char *value, const int req_id, const s_config *config);
void reset_device_op(void *mosq, const char *value, const int req_id, const s_config *config);
void set_auth_server_op(void *mosq, const char *value, const int req_id, const s_config *config);

// Pending implementation operation handlers
void bootstrap_op(void *mosq, const char *value, const int req_id, const s_config *config);
void update_config_op(void *mosq, const char *value, const int req_id, const s_config *config);
void ota_op(void *mosq, const char *value, const int req_id, const s_config *config);
void qos_op(void *mosq, const char *value, const int req_id, const s_config *config);
void uci_op(void *mosq, const char *value, const int req_id, const s_config *config);
void get_traffic_stats_op(void *mosq, const char *value, const int req_id, const s_config *config);
void get_clients_op(void *mosq, const char *value, const int req_id, const s_config *config);
void heartbeat_op(void *mosq, const char *value, const int req_id, const s_config *config);
void wan_change_op(void *mosq, const char *value, const int req_id, const s_config *config);
void alarm_op(void *mosq, const char *value, const int req_id, const s_config *config);
void wan_select_op(void *mosq, const char *value, const int req_id, const s_config *config);
void wan_priority_op(void *mosq, const char *value, const int req_id, const s_config *config);

void thread_mqtt(void *arg);

/* Return non-zero if MQTT client is currently connected to broker */
int mqtt_is_connected(void);

/* Request MQTT client to disconnect and reconnect immediately */
void mqtt_request_reconnect(void);


#endif