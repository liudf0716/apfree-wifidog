
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef	_MQTT_THREAD_H_
#define	_MQTT_THREAD_H_

#include "conf.h"

void set_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void del_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void clear_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void show_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void save_rule_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void get_status_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void reboot_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void reset_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void set_auth_server_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);

void thread_mqtt(void *arg);


#endif