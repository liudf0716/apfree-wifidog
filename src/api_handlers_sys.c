// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"
#include "debug.h"
#include "conf.h"
#include "ping_thread.h"

/**
 * @brief Handles a request for firmware information.
 *
 * This function is called when a "get_firmware_info" message is received.
 * It reads firmware information from /etc/openwrt_release and sends it back
 * as a JSON response.
 *
 * @param j_req The JSON request object (unused for this request type)
 * @param bev The bufferevent associated with the WebSocket connection
 */
void handle_get_firmware_info_request(json_object *j_req, api_transport_context_t *transport) {
    FILE *fp;
    char buffer[256];
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    debug(LOG_INFO, "Get firmware info request received");

    fp = popen("cat /etc/openwrt_release 2>/dev/null", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute firmware info command");

        json_object *j_type = json_object_new_string("firmware_info_error");
        json_object *j_error = json_object_new_string("Failed to execute command");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;

        char *key = strtok(buffer, "=");
        char *value = strtok(NULL, "=");

        if (key && value) {
            if (value[0] == '\'' && value[strlen(value)-1] == '\'') {
                value[strlen(value)-1] = 0;
                value++;
            }

            bool valid_key = true;
            for (char *p = key; *p; p++) {
                if (!isalnum(*p) && *p != '_') {
                    valid_key = false;
                    break;
                }
            }
            if (valid_key) {
                json_object_object_add(j_data, key, json_object_new_string(value));
            }
        }
    }

    pclose(fp);

    json_object *j_type = json_object_new_string("firmware_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "data", json_object_new_string("Map of firmware/release keys to string values (e.g. DISTRIB_RELEASE, DISTRIB_ID). Keys vary by device image."));
    json_object_object_add(j_data, "field_descriptions", j_fd);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending firmware info response: %s", response_str);
    send_json_response(transport, j_response);

    debug(LOG_INFO, "Firmware info sent successfully");
}

/**
 * @brief Handles a request for firmware upgrade.
 */
void handle_firmware_upgrade_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_url, *j_force;

    debug(LOG_INFO, "Firmware upgrade request received");

    if (!json_object_object_get_ex(j_req, "url", &j_url)) {
        debug(LOG_ERR, "Missing 'url' field in firmware upgrade request");

        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Missing or invalid 'url' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    const char *url_str = json_object_get_string(j_url);
    if (!url_str || strlen(url_str) == 0) {
        debug(LOG_ERR, "Invalid URL in firmware upgrade request");

        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Missing or invalid 'url' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    if (strncmp(url_str, "http://", 7) != 0 && strncmp(url_str, "https://", 8) != 0) {
        debug(LOG_ERR, "Invalid URL protocol in firmware upgrade request: %s", url_str);

        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("Invalid URL protocol, only HTTP/HTTPS allowed");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    if (strlen(url_str) > 1024) {
        debug(LOG_ERR, "URL too long in firmware upgrade request");

        json_object *j_type = json_object_new_string("firmware_upgrade_error");
        json_object *j_error = json_object_new_string("URL too long");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    bool force_upgrade = false;
    if (json_object_object_get_ex(j_req, "force", &j_force)) {
        force_upgrade = json_object_get_boolean(j_force);
    }

    debug(LOG_INFO, "Starting firmware upgrade from URL: %s (force: %s)",
          url_str, force_upgrade ? "true" : "false");

    json_object *j_type = json_object_new_string("firmware_upgrade_response");
    json_object *j_status = json_object_new_string("success");
    json_object *j_message = json_object_new_string("Firmware upgrade initiated successfully");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "status", j_status);
    json_object_object_add(j_response, "message", j_message);

    send_json_response(transport, j_response);

    char *escaped_url = malloc(strlen(url_str) * 2 + 1);
    if (!escaped_url) {
        debug(LOG_ERR, "Memory allocation failed for URL escaping");
        return;
    }

    char *dst = escaped_url;
    for (const char *src = url_str; *src; src++) {
        if (*src == '\'' || *src == '"' || *src == '\\' || *src == '$' || *src == '`') {
            *dst++ = '\\';
        }
        *dst++ = *src;
    }
    *dst = '\0';

    char command[512];
    int ret;
    if (force_upgrade) {
        ret = snprintf(command, sizeof(command), "sysupgrade -F '%s' &", escaped_url);
    } else {
        ret = snprintf(command, sizeof(command), "sysupgrade '%s' &", escaped_url);
    }

    free(escaped_url);

    if (ret >= (int)sizeof(command)) {
        debug(LOG_ERR, "Sysupgrade command too long");
        return;
    }

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute sysupgrade command");
        return;
    }

    pclose(fp);
    debug(LOG_INFO, "Firmware upgrade command executed successfully - system may reboot");
}

/**
 * @brief Handles a request to reboot the device.
 */
void handle_reboot_device_request(json_object *j_req, api_transport_context_t *transport) {
    debug(LOG_INFO, "Reboot device request received");

    FILE *fp = popen("reboot &", "r");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to execute reboot command");

        json_object *j_response = json_object_new_object();
        json_object *j_type = json_object_new_string("reboot_device_error");
        json_object *j_error = json_object_new_string("Failed to execute reboot command");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    pclose(fp);
    debug(LOG_INFO, "Device is rebooting now");
}

void handle_get_sys_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    debug(LOG_INFO, "System info request received");

    struct sys_info sysinfo;
    get_sys_info(&sysinfo);

    json_object_object_add(j_data, "sys_uptime", json_object_new_int64(sysinfo.sys_uptime));
    json_object_object_add(j_data, "sys_memfree", json_object_new_int(sysinfo.sys_memfree));
    json_object_object_add(j_data, "sys_load", json_object_new_double(sysinfo.sys_load));
    json_object_object_add(j_data, "nf_conntrack_count", json_object_new_int64(sysinfo.nf_conntrack_count));
    json_object_object_add(j_data, "cpu_usage", json_object_new_double(sysinfo.cpu_usage));
    json_object_object_add(j_data, "wifidog_uptime", json_object_new_int64(sysinfo.wifidog_uptime));
    json_object_object_add(j_data, "cpu_temp", json_object_new_int(sysinfo.cpu_temp));

    json_object_object_add(j_response, "type", json_object_new_string("get_sys_info_response"));
    json_object_object_add(j_response, "data", j_data);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending system info response: %s", response_str);
    send_json_response(transport, j_response);
}
