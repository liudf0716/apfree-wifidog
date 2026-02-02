// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 AWAS Shell Command Handler
 * MQTT Shell Command Handler for Remote Command Execution
 */

#ifndef _MQTT_SHELL_HANDLER_H_
#define _MQTT_SHELL_HANDLER_H_

#include "conf.h"

/**
 * Handle shell command execution via MQTT
 * Topic: wifidogx/v1/<device_id>/shell/command
 * 
 * Request payload:
 * {
 *   "req_id": "unique_request_id",
 *   "command": "ls -la /home",
 *   "timeout": 30
 * }
 * 
 * Response topic: wifidogx/v1/<device_id>/shell/response
 * Response payload:
 * {
 *   "req_id": "unique_request_id",
 *   "code": 0,
 *   "msg": "OK",
 *   "output": "...",
 *   "error": ""
 * }
 */

void handle_shell_command_request(struct mosquitto *mosq, 
                                   const char *payload, 
                                   int payload_len,
                                   const s_config *config);

#endif /* _MQTT_SHELL_HANDLER_H_ */
