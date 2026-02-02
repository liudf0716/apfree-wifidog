// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 AWAS Shell Command Handler
 * MQTT Shell Command Handler for Remote Command Execution
 */

#include "common.h"
#include "mqtt_shell_handler.h"
#include "client_library/shell_executor.h"
#include "debug.h"
#include "safe.h"

/**
 * Send shell command response via MQTT
 */
static void
mqtt_send_shell_response(struct mosquitto *mosq,
                         const char *req_id,
                         int code,
                         const char *msg,
                         const char *output,
                         const s_config *config)
{
    char *topic = NULL;
    char *response = NULL;
    json_object *json_resp = NULL;
    
    // Build response topic
    safe_asprintf(&topic, "wifidogx/v1/%s/shell/response", get_device_id());
    
    // Build response JSON
    json_resp = json_object_new_object();
    if (!json_resp) {
        debug(LOG_ERR, "[shell] Failed to create JSON response object");
        goto cleanup;
    }
    
    json_object_object_add(json_resp, "req_id", json_object_new_string(req_id ? req_id : ""));
    json_object_object_add(json_resp, "code", json_object_new_int(code));
    json_object_object_add(json_resp, "msg", json_object_new_string(msg ? msg : ""));
    json_object_object_add(json_resp, "output", json_object_new_string(output ? output : ""));
    
    response = (char *)json_object_to_json_string(json_resp);
    
    debug(LOG_DEBUG, "[shell] Sending response to %s: %s", topic, response);
    
    // Publish response
    if (mosquitto_publish(mosq, NULL, topic, strlen(response), response, 0, false) != MOSQ_ERR_SUCCESS) {
        debug(LOG_ERR, "[shell] Failed to publish response");
    }

cleanup:
    if (json_resp) {
        json_object_put(json_resp);
    }
    if (topic) {
        free(topic);
    }
}

/**
 * Handle shell command execution via MQTT
 */
void
handle_shell_command_request(struct mosquitto *mosq,
                              const char *payload,
                              int payload_len,
                              const s_config *config)
{
    json_object *json_request = NULL;
    json_object *jo_req_id = NULL;
    json_object *jo_command = NULL;
    json_object *jo_timeout = NULL;
    const char *req_id = NULL;
    const char *command = NULL;
    int timeout = 30;
    shell_exec_result_t result;
    
    if (!payload || payload_len <= 0) {
        debug(LOG_ERR, "[shell] Invalid payload");
        return;
    }
    
    // Parse JSON payload
    json_request = json_tokener_parse(payload);
    if (is_error(json_request)) {
        debug(LOG_ERR, "[shell] Failed to parse JSON payload");
        mqtt_send_shell_response(mosq, "", -1, "JSON parse error", "", config);
        return;
    }
    
    // Extract req_id
    jo_req_id = json_object_object_get(json_request, "req_id");
    if (!jo_req_id) {
        debug(LOG_ERR, "[shell] Missing req_id in request");
        mqtt_send_shell_response(mosq, "", -1, "Missing req_id", "", config);
        json_object_put(json_request);
        return;
    }
    req_id = json_object_get_string(jo_req_id);
    
    // Extract command
    jo_command = json_object_object_get(json_request, "command");
    if (!jo_command) {
        debug(LOG_ERR, "[shell] Missing command in request");
        mqtt_send_shell_response(mosq, req_id, -2, "Missing command", "", config);
        json_object_put(json_request);
        return;
    }
    command = json_object_get_string(jo_command);
    
    if (!command || strlen(command) == 0) {
        debug(LOG_ERR, "[shell] Empty command");
        mqtt_send_shell_response(mosq, req_id, -2, "Empty command", "", config);
        json_object_put(json_request);
        return;
    }
    
    // Extract timeout (optional)
    jo_timeout = json_object_object_get(json_request, "timeout");
    if (jo_timeout) {
        timeout = json_object_get_int(jo_timeout);
        if (timeout <= 0 || timeout > shell_executor_get_timeout()) {
            timeout = shell_executor_get_timeout();
        }
    }
    
    debug(LOG_DEBUG, "[shell] Executing command: %s (timeout: %d)", command, timeout);
    
    // Check command length
    if (strlen(command) > shell_executor_get_max_command_length()) {
        debug(LOG_ERR, "[shell] Command too long: %zu > %d",
              strlen(command), shell_executor_get_max_command_length());
        mqtt_send_shell_response(mosq, req_id, -3, "Command too long", "", config);
        json_object_put(json_request);
        return;
    }
    
    // Initialize result structure
    memset(&result, 0, sizeof(result));
    
    // Execute command using shell_executor
    int exec_ret = shell_executor_execute(command, timeout, &result);
    
    if (exec_ret != 0) {
        debug(LOG_ERR, "[shell] Command execution failed: ret=%d", exec_ret);
        mqtt_send_shell_response(mosq, req_id, exec_ret, "Execution failed",
                                 result.output, config);
    } else {
        debug(LOG_DEBUG, "[shell] Command executed successfully");
        mqtt_send_shell_response(mosq, req_id, result.exit_code, "OK",
                                 result.output, config);
    }
    
    json_object_put(json_request);
}
