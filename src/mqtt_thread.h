
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef	_MQTT_THREAD_H_
#define	_MQTT_THREAD_H_

#include "conf.h"

void thread_mqtt(void *arg);

/* Return non-zero if MQTT client is currently connected to broker */
int mqtt_is_connected(void);

/* Request MQTT client to disconnect and reconnect immediately */
void mqtt_request_reconnect(void);


#endif