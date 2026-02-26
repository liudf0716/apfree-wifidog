// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "client_list.h"
#include "gateway.h"
#include "fw_nft.h"
#include "wd_util.h"
#include "version.h"
#include "commandline.h"
#include "mqtt_thread.h"
#include "ping_thread.h"
#include "wdctlx_thread.h"
#include "safe.h"
#include "uci_helper.h"
#include "client_library/shell_executor.h"

void handle_heartbeat_request(json_object *j_heartbeat, api_transport_context_t *transport)
{
    mark_auth_online();

    json_object *gw_array = json_object_object_get(j_heartbeat, "gateway");
    if (!gw_array || !json_object_is_type(gw_array, json_type_array)) {
        debug(LOG_ERR, "Heartbeat: Invalid or missing gateway array");
        send_response(transport, "{\"error\":\"Invalid or missing gateway array\"}");
        return;
    }

    bool state_changed = false;

    int gw_count = json_object_array_length(gw_array);
    for (int i = 0; i < gw_count; i++) {
        json_object *gw = json_object_array_get_idx(gw_array, i);
        json_object *gw_id = json_object_object_get(gw, "gw_id");
        json_object *auth_mode = json_object_object_get(gw, "auth_mode");

        if (!gw_id || !auth_mode) {
            debug(LOG_ERR, "Heartbeat: Missing required gateway fields");
            continue;
        }

        const char *gw_id_str = json_object_get_string(gw_id);
        int new_auth_mode = json_object_get_int(auth_mode);

        t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
        if (!gw_setting) {
            debug(LOG_ERR, "Heartbeat: Gateway %s not found", gw_id_str);
            continue;
        }

        if (gw_setting->auth_mode != new_auth_mode) {
            debug(LOG_DEBUG, "Heartbeat: Gateway %s auth mode changed to %d", gw_id_str, new_auth_mode);
            gw_setting->auth_mode = new_auth_mode;
            state_changed = true;
        }
    }

    if (state_changed) {
        debug(LOG_DEBUG, "Gateway states changed, reloading firewall rules");
#ifdef AW_FW4
        nft_reload_gw();
#endif
    }

    send_response(transport, "{\"status\":\"heartbeat_received\"}");
}

void handle_tmp_pass_request(json_object *j_tmp_pass, api_transport_context_t *transport)
{
    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring tmp_pass request from server");
        send_response(transport, "{\"error\":\"Portal authentication is disabled\"}");
        return;
    }

    json_object *client_mac = json_object_object_get(j_tmp_pass, "client_mac");
    if (!client_mac) {
        debug(LOG_ERR, "Temporary pass: Missing client MAC address");
        return;
    }
    const char *client_mac_str = json_object_get_string(client_mac);

    uint32_t timeout_value = 5 * 60;
    json_object *timeout = json_object_object_get(j_tmp_pass, "timeout");
    if (timeout) {
        timeout_value = json_object_get_int(timeout);
    }

    fw_set_mac_temporary(client_mac_str, timeout_value);
    debug(LOG_DEBUG, "Set temporary access for MAC %s with timeout %u seconds", client_mac_str, timeout_value);
}

void handle_shell_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_response = json_object_new_object();
    json_object *jo_req_id = NULL;
    json_object *jo_command = NULL;
    json_object *jo_timeout = NULL;
    const char *command = NULL;
    int timeout = shell_executor_get_timeout();
    shell_exec_result_t result;

    if (!j_req || !transport) {
        if (j_response) {
            json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
            json_object_object_add(j_response, "code", json_object_new_int(-1));
            json_object_object_add(j_response, "msg", json_object_new_string("Invalid request"));
            json_object_object_add(j_response, "output", json_object_new_string(""));
            send_json_response(transport, j_response);
        }
        return;
    }

    jo_req_id = json_object_object_get(j_req, "req_id");
    if (jo_req_id) {
        const char *req_id_str = json_object_get_string(jo_req_id);
        json_object_object_add(j_response, "req_id", json_object_new_string(req_id_str ? req_id_str : ""));
    }

    jo_command = json_object_object_get(j_req, "command");
    if (!jo_command || !json_object_is_type(jo_command, json_type_string)) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-2));
        json_object_object_add(j_response, "msg", json_object_new_string("Missing command"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    command = json_object_get_string(jo_command);
    if (!command || strlen(command) == 0) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-2));
        json_object_object_add(j_response, "msg", json_object_new_string("Empty command"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    jo_timeout = json_object_object_get(j_req, "timeout");
    if (jo_timeout) {
        timeout = json_object_get_int(jo_timeout);
        if (timeout <= 0 || timeout > shell_executor_get_timeout()) {
            timeout = shell_executor_get_timeout();
        }
    }

    if (strlen(command) > (size_t)shell_executor_get_max_command_length()) {
        json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
        json_object_object_add(j_response, "code", json_object_new_int(-3));
        json_object_object_add(j_response, "msg", json_object_new_string("Command too long"));
        json_object_object_add(j_response, "output", json_object_new_string(""));
        send_json_response(transport, j_response);
        return;
    }

    memset(&result, 0, sizeof(result));
    int exec_ret = shell_executor_execute(command, timeout, &result);

    json_object_object_add(j_response, "type", json_object_new_string("shell_response"));
    if (exec_ret != 0) {
        json_object_object_add(j_response, "code", json_object_new_int(exec_ret));
        json_object_object_add(j_response, "msg", json_object_new_string("Execution failed"));
        json_object_object_add(j_response, "output", json_object_new_string(result.output));
    } else {
        json_object_object_add(j_response, "code", json_object_new_int(result.exit_code));
        json_object_object_add(j_response, "msg", json_object_new_string("OK"));
        json_object_object_add(j_response, "output", json_object_new_string(result.output));
    }

    send_json_response(transport, j_response);
}

void handle_get_client_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_mac;

    debug(LOG_INFO, "Get client info request received");

    if (!json_object_object_get_ex(j_req, "mac", &j_mac)) {
        debug(LOG_ERR, "Missing 'mac' field in get_client_info request");
        json_object_object_add(j_response, "type", json_object_new_string("get_client_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'mac' field in request"));
        send_json_response(transport, j_response);
        return;
    }

    const char *mac_str = json_object_get_string(j_mac);
    if (!mac_str || strlen(mac_str) == 0) {
        debug(LOG_ERR, "Invalid MAC address in get_client_info request");
        json_object_object_add(j_response, "type", json_object_new_string("get_client_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC address"));
        send_json_response(transport, j_response);
        return;
    }

    debug(LOG_DEBUG, "Updating client counters before retrieving info for MAC: %s", mac_str);
    if (fw_counters_update() == -1) {
        debug(LOG_WARNING, "Failed to update client counters, proceeding with cached data");
    }

    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_mac(mac_str);

    if (!client) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_INFO, "Client with MAC %s not found", mac_str);
        json_object_object_add(j_response, "type", json_object_new_string("get_client_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Client not found"));
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_data = json_object_new_object();

    json_object_object_add(j_data, "id", json_object_new_int64(client->id));
    if (client->ip) json_object_object_add(j_data, "ip", json_object_new_string(client->ip));
    if (client->ip6) json_object_object_add(j_data, "ip6", json_object_new_string(client->ip6));
    if (client->mac) json_object_object_add(j_data, "mac", json_object_new_string(client->mac));
    if (client->token) json_object_object_add(j_data, "token", json_object_new_string(client->token));
    json_object_object_add(j_data, "fw_connection_state", json_object_new_int(client->fw_connection_state));
    if (client->name) json_object_object_add(j_data, "name", json_object_new_string(client->name));
    json_object_object_add(j_data, "is_online", json_object_new_int(client->is_online));
    json_object_object_add(j_data, "wired", json_object_new_int(client->wired));
    json_object_object_add(j_data, "first_login", json_object_new_int64(client->first_login));

    json_object *j_counters = json_object_new_object();
    json_object_object_add(j_counters, "incoming_bytes", json_object_new_int64(client->counters.incoming_bytes));
    json_object_object_add(j_counters, "incoming_packets", json_object_new_int64(client->counters.incoming_packets));
    json_object_object_add(j_counters, "outgoing_bytes", json_object_new_int64(client->counters.outgoing_bytes));
    json_object_object_add(j_counters, "outgoing_packets", json_object_new_int64(client->counters.outgoing_packets));
    json_object_object_add(j_counters, "incoming_rate", json_object_new_int(client->counters.incoming_rate));
    json_object_object_add(j_counters, "outgoing_rate", json_object_new_int(client->counters.outgoing_rate));
    json_object_object_add(j_counters, "last_updated", json_object_new_int64(client->counters.last_updated));
    json_object_object_add(j_data, "counters", j_counters);

    json_object *j_counters6 = json_object_new_object();
    json_object_object_add(j_counters6, "incoming_bytes", json_object_new_int64(client->counters6.incoming_bytes));
    json_object_object_add(j_counters6, "incoming_packets", json_object_new_int64(client->counters6.incoming_packets));
    json_object_object_add(j_counters6, "outgoing_bytes", json_object_new_int64(client->counters6.outgoing_bytes));
    json_object_object_add(j_counters6, "outgoing_packets", json_object_new_int64(client->counters6.outgoing_packets));
    json_object_object_add(j_counters6, "incoming_rate", json_object_new_int(client->counters6.incoming_rate));
    json_object_object_add(j_counters6, "outgoing_rate", json_object_new_int(client->counters6.outgoing_rate));
    json_object_object_add(j_counters6, "last_updated", json_object_new_int64(client->counters6.last_updated));
    json_object_object_add(j_data, "counters6", j_counters6);

    UNLOCK_CLIENT_LIST();

    json_object_object_add(j_response, "type", json_object_new_string("get_client_info_response"));
    json_object_object_add(j_response, "data", j_data);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "id", json_object_new_string("Client internal id (int64)"));
    json_object_object_add(j_fd, "ip", json_object_new_string("IPv4 address of client (string)"));
    json_object_object_add(j_fd, "ip6", json_object_new_string("IPv6 address of client (string) if present"));
    json_object_object_add(j_fd, "mac", json_object_new_string("Client MAC address (string)"));
    json_object_object_add(j_fd, "token", json_object_new_string("Authentication token assigned to client (string)"));
    json_object_object_add(j_fd, "fw_connection_state", json_object_new_string("Firewall/connection state (int) - internal enum"));
    json_object_object_add(j_fd, "name", json_object_new_string("Optional client name (string)"));
    json_object_object_add(j_fd, "is_online", json_object_new_string("Is client currently online (boolean as int: 0/1)"));
    json_object_object_add(j_fd, "wired", json_object_new_string("Is client wired (boolean as int: 0/1)"));
    json_object_object_add(j_fd, "first_login", json_object_new_string("Epoch timestamp of first login (int64)"));

    json_object *j_cnt_desc = json_object_new_object();
    json_object_object_add(j_cnt_desc, "incoming_bytes", json_object_new_string("IPv4 incoming bytes (int64)"));
    json_object_object_add(j_cnt_desc, "incoming_packets", json_object_new_string("IPv4 incoming packets (int64)"));
    json_object_object_add(j_cnt_desc, "outgoing_bytes", json_object_new_string("IPv4 outgoing bytes (int64)"));
    json_object_object_add(j_cnt_desc, "outgoing_packets", json_object_new_string("IPv4 outgoing packets (int64)"));
    json_object_object_add(j_cnt_desc, "incoming_rate", json_object_new_string("IPv4 incoming rate (int, bytes/sec)"));
    json_object_object_add(j_cnt_desc, "outgoing_rate", json_object_new_string("IPv4 outgoing rate (int, bytes/sec)"));
    json_object_object_add(j_cnt_desc, "last_updated", json_object_new_string("Epoch timestamp when counters were last updated (int64)"));
    json_object_object_add(j_fd, "counters", j_cnt_desc);

    json_object *j_cnt6_desc = json_object_new_object();
    json_object_object_add(j_cnt6_desc, "incoming_bytes", json_object_new_string("IPv6 incoming bytes (int64)"));
    json_object_object_add(j_cnt6_desc, "incoming_packets", json_object_new_string("IPv6 incoming packets (int64)"));
    json_object_object_add(j_cnt6_desc, "outgoing_bytes", json_object_new_string("IPv6 outgoing bytes (int64)"));
    json_object_object_add(j_cnt6_desc, "outgoing_packets", json_object_new_string("IPv6 outgoing packets (int64)"));
    json_object_object_add(j_cnt6_desc, "incoming_rate", json_object_new_string("IPv6 incoming rate (int, bytes/sec)"));
    json_object_object_add(j_cnt6_desc, "outgoing_rate", json_object_new_string("IPv6 outgoing rate (int, bytes/sec)"));
    json_object_object_add(j_cnt6_desc, "last_updated", json_object_new_string("Epoch timestamp when counters6 were last updated (int64)"));
    json_object_object_add(j_fd, "counters6", j_cnt6_desc);
    json_object_object_add(j_data, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
    debug(LOG_INFO, "Client info for MAC %s sent successfully", mac_str);
}

void handle_kickoff_request(json_object *j_auth, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring kickoff request from server");
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Portal authentication is disabled"));
        send_json_response(transport, j_response);
        return;
    }

    json_object *client_ip = json_object_object_get(j_auth, "client_ip");
    json_object *client_mac = json_object_object_get(j_auth, "client_mac");
    json_object *device_id = json_object_object_get(j_auth, "device_id");
    json_object *gw_id = json_object_object_get(j_auth, "gw_id");

    if (!client_ip || !client_mac || !device_id || !gw_id) {
        debug(LOG_ERR, "Kickoff: Missing required fields in request");
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required fields in request"));
        send_json_response(transport, j_response);
        return;
    }

    const char *client_ip_str = json_object_get_string(client_ip);
    const char *client_mac_str = json_object_get_string(client_mac);
    const char *device_id_str = json_object_get_string(device_id);
    const char *gw_id_str = json_object_get_string(gw_id);

    t_client *client = client_list_find(client_ip_str, client_mac_str);
    if (!client) {
        debug(LOG_ERR, "Kickoff: Client %s (%s) not found", client_mac_str, client_ip_str);
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Client not found"));
        json_object_object_add(j_response, "client_ip", json_object_new_string(client_ip_str));
        json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
        send_json_response(transport, j_response);
        return;
    }

    const char *local_device_id = get_device_id();
    if (!local_device_id || strcmp(local_device_id, device_id_str) != 0) {
        debug(LOG_ERR, "Kickoff: Device ID mismatch - expected %s", device_id_str);
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Device ID mismatch"));
        json_object_object_add(j_response, "expected_device_id", json_object_new_string(device_id_str));
        json_object_object_add(j_response, "actual_device_id", json_object_new_string(local_device_id ? local_device_id : "null"));
        send_json_response(transport, j_response);
        return;
    }

    if (!client->gw_setting || strcmp(client->gw_setting->gw_id, gw_id_str) != 0) {
        debug(LOG_ERR, "Kickoff: Gateway mismatch for client %s - expected %s", client_mac_str, gw_id_str);
        json_object_object_add(j_response, "type", json_object_new_string("kickoff_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Gateway ID mismatch"));
        json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
        json_object_object_add(j_response, "expected_gw_id", json_object_new_string(gw_id_str));
        json_object_object_add(j_response, "actual_gw_id", json_object_new_string(client->gw_setting ? client->gw_setting->gw_id : "null"));
        send_json_response(transport, j_response);
        return;
    }

    LOCK_CLIENT_LIST();
    fw_deny(client);
    client_list_remove(client);
    client_free_node(client);
    UNLOCK_CLIENT_LIST();

    debug(LOG_DEBUG, "Kicked off client %s (%s)", client_mac_str, client_ip_str);

    json_object_object_add(j_response, "type", json_object_new_string("kickoff_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "client_ip", json_object_new_string(client_ip_str));
    json_object_object_add(j_response, "client_mac", json_object_new_string(client_mac_str));
    json_object_object_add(j_response, "message", json_object_new_string("Client kicked off successfully"));
    send_json_response(transport, j_response);
}

void handle_get_clients_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    debug(LOG_INFO, "Get clients list request received");
    if (fw_counters_update() == -1) {
        debug(LOG_WARNING, "Failed to update client counters, proceeding with cached data");
    }

    json_object *j_clients_array = json_object_new_array();

    LOCK_CLIENT_LIST();
    t_client *client = client_get_first_client();
    while (client) {
        json_object *j_client = json_object_new_object();

        json_object_object_add(j_client, "id", json_object_new_int64(client->id));
        if (client->ip) json_object_object_add(j_client, "ip", json_object_new_string(client->ip));
        if (client->ip6) json_object_object_add(j_client, "ip6", json_object_new_string(client->ip6));
        if (client->mac) json_object_object_add(j_client, "mac", json_object_new_string(client->mac));
        if (client->token) json_object_object_add(j_client, "token", json_object_new_string(client->token));

        json_object_object_add(j_client, "fw_connection_state", json_object_new_int(client->fw_connection_state));
        if (client->name) json_object_object_add(j_client, "name", json_object_new_string(client->name));
        json_object_object_add(j_client, "is_online", json_object_new_int(client->is_online));
        json_object_object_add(j_client, "wired", json_object_new_int(client->wired));
        json_object_object_add(j_client, "first_login", json_object_new_int64(client->first_login));

        json_object *j_counters = json_object_new_object();
        json_object_object_add(j_counters, "incoming_bytes", json_object_new_int64(client->counters.incoming_bytes));
        json_object_object_add(j_counters, "incoming_packets", json_object_new_int64(client->counters.incoming_packets));
        json_object_object_add(j_counters, "outgoing_bytes", json_object_new_int64(client->counters.outgoing_bytes));
        json_object_object_add(j_counters, "outgoing_packets", json_object_new_int64(client->counters.outgoing_packets));
        json_object_object_add(j_counters, "incoming_rate", json_object_new_int(client->counters.incoming_rate));
        json_object_object_add(j_counters, "outgoing_rate", json_object_new_int(client->counters.outgoing_rate));
        json_object_object_add(j_counters, "last_updated", json_object_new_int64(client->counters.last_updated));
        json_object_object_add(j_client, "counters", j_counters);

        json_object *j_counters6 = json_object_new_object();
        json_object_object_add(j_counters6, "incoming_bytes", json_object_new_int64(client->counters6.incoming_bytes));
        json_object_object_add(j_counters6, "incoming_packets", json_object_new_int64(client->counters6.incoming_packets));
        json_object_object_add(j_counters6, "outgoing_bytes", json_object_new_int64(client->counters6.outgoing_bytes));
        json_object_object_add(j_counters6, "outgoing_packets", json_object_new_int64(client->counters6.outgoing_packets));
        json_object_object_add(j_counters6, "incoming_rate", json_object_new_int(client->counters6.incoming_rate));
        json_object_object_add(j_counters6, "outgoing_rate", json_object_new_int(client->counters6.outgoing_rate));
        json_object_object_add(j_counters6, "last_updated", json_object_new_int64(client->counters6.last_updated));
        json_object_object_add(j_client, "counters6", j_counters6);

        json_object_array_add(j_clients_array, j_client);
        client = client->next;
    }
    UNLOCK_CLIENT_LIST();

    json_object_object_add(j_response, "type", json_object_new_string("get_clients_response"));
    json_object_object_add(j_response, "clients", j_clients_array);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "clients", json_object_new_string("Array of client objects. Each object contains id, ip, ip6, mac, token, counters, counters6, etc."));
    json_object *j_client_desc = json_object_new_object();
    json_object_object_add(j_client_desc, "id", json_object_new_string("Client internal id (int64)"));
    json_object_object_add(j_client_desc, "ip", json_object_new_string("IPv4 address (string)"));
    json_object_object_add(j_client_desc, "ip6", json_object_new_string("IPv6 address (string) if present"));
    json_object_object_add(j_client_desc, "mac", json_object_new_string("MAC address (string)"));
    json_object_object_add(j_client_desc, "token", json_object_new_string("Auth token (string)"));
    json_object_object_add(j_client_desc, "fw_connection_state", json_object_new_string("Firewall/connection state (int)"));
    json_object_object_add(j_client_desc, "name", json_object_new_string("Optional human name for client (string)"));
    json_object_object_add(j_client_desc, "is_online", json_object_new_string("Online flag (0/1)"));
    json_object_object_add(j_client_desc, "wired", json_object_new_string("Wired flag (0/1)"));
    json_object_object_add(j_client_desc, "first_login", json_object_new_string("Epoch timestamp of first login (int64)"));
    json_object_object_add(j_fd, "client_object", j_client_desc);
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
    debug(LOG_INFO, "Clients list sent successfully");
}

void handle_set_auth_server_request(json_object *j_req, api_transport_context_t *transport) {
    if (!j_req || !transport) {
        debug(LOG_ERR, "Invalid parameters for set_auth_server");
        return;
    }

    s_config *config = config_get_config();
    if (!config || !config->auth_servers) {
        debug(LOG_ERR, "Config or auth_servers is NULL");
        send_response(transport, "{\"error\":\"Internal configuration error\"}");
        return;
    }

    char *hostname = config->auth_servers->authserv_hostname;
    char *path = config->auth_servers->authserv_path;
    const char *tmp_host_name = NULL;
    const char *tmp_http_port = NULL;
    const char *tmp_path = NULL;

    json_object *jo_host_name = json_object_object_get(j_req, "hostname");
    json_object *jo_http_port = json_object_object_get(j_req, "port");
    json_object *jo_path = json_object_object_get(j_req, "path");

    const char *json_host = NULL;
    const char *json_port = NULL;
    const char *json_path = NULL;

    if (jo_host_name != NULL) json_host = json_object_get_string(jo_host_name);
    if (jo_http_port != NULL) json_port = json_object_get_string(jo_http_port);
    if (jo_path != NULL) json_path = json_object_get_string(jo_path);

    LOCK_CONFIG();
    if (json_host != NULL && hostname && strcmp(hostname, json_host) != 0) {
        free(hostname);
        config->auth_servers->authserv_hostname = safe_strdup(json_host);
        tmp_host_name = config->auth_servers->authserv_hostname;
    }

    if (json_path != NULL && path && strcmp(path, json_path) != 0) {
        free(path);
        config->auth_servers->authserv_path = safe_strdup(json_path);
        tmp_path = config->auth_servers->authserv_path;
    }

    if (json_port != NULL) {
        config->auth_servers->authserv_http_port = atoi(json_port);
        tmp_http_port = json_port;
    }
    UNLOCK_CONFIG();

    debug(LOG_DEBUG, "Set auth server - hostname: %s, port: %s, path: %s",
          tmp_host_name ? tmp_host_name : "(unchanged)",
          tmp_http_port ? tmp_http_port : "(unchanged)",
          tmp_path ? tmp_path : "(unchanged)");

    char selected_section[128] = {0};
    if (uci_get_value("wifidogx", "wifidog", "selected_auth_server", selected_section, sizeof(selected_section)) == 0 && selected_section[0] != '\0') {
        if (tmp_host_name != NULL) {
            uci_set_value("wifidogx", selected_section, "auth_server_hostname", tmp_host_name);
        }
        if (tmp_path != NULL) {
            uci_set_value("wifidogx", selected_section, "auth_server_path", tmp_path);
        }
        if (tmp_http_port != NULL) {
            char portbuf[16];
            snprintf(portbuf, sizeof(portbuf), "%d", config->auth_servers->authserv_http_port);
            uci_set_value("wifidogx", selected_section, "auth_server_port", portbuf);
        }
    } else {
        debug(LOG_WARNING, "No selected_auth_server found in UCI; skipping persistence to auth section");
    }

    json_object *response = json_object_new_object();
    json_object_object_add(response, "status", json_object_new_string("success"));
    json_object_object_add(response, "message", json_object_new_string("Auth server configuration updated"));
    send_json_response(transport, response);
}

void handle_get_auth_server_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    s_config *config = config_get_config();
    if (!config || !config->auth_servers) {
        debug(LOG_ERR, "Get auth server: Config or auth_servers is NULL");
        json_object_object_add(j_response, "type", json_object_new_string("get_auth_serv_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Internal configuration error"));
        send_json_response(transport, j_response);
        return;
    }

    char *hostname_copy = NULL;
    char *path_copy = NULL;
    int port_copy = 0;

    LOCK_CONFIG();
    if (config->auth_servers->authserv_hostname) {
        hostname_copy = safe_strdup(config->auth_servers->authserv_hostname);
    }
    port_copy = config->auth_servers->authserv_http_port;
    if (config->auth_servers->authserv_path) {
        path_copy = safe_strdup(config->auth_servers->authserv_path);
    }
    UNLOCK_CONFIG();

    json_object *j_data = json_object_new_object();
    if (hostname_copy) json_object_object_add(j_data, "hostname", json_object_new_string(hostname_copy));
    json_object_object_add(j_data, "port", json_object_new_int(port_copy));
    if (path_copy) json_object_object_add(j_data, "path", json_object_new_string(path_copy));

    json_object_object_add(j_response, "type", json_object_new_string("get_auth_serv_response"));
    json_object_object_add(j_response, "data", j_data);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "hostname", json_object_new_string("Auth server hostname (string) from runtime config"));
    json_object_object_add(j_fd, "port", json_object_new_string("Auth server HTTP port (int) from runtime config"));
    json_object_object_add(j_fd, "path", json_object_new_string("Auth server path (string) from runtime config"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);

    free(hostname_copy);
    free(path_copy);
}

void handle_auth_request(json_object *j_auth, api_transport_context_t *transport) {
    if (is_portal_auth_disabled()) {
        debug(LOG_WARNING, "Portal authentication is disabled, ignoring auth request from server");
        send_response(transport, "{\"error\":\"Portal authentication is disabled\"}");
        return;
    }

    json_object *token = json_object_object_get(j_auth, "token");
    json_object *client_ip = json_object_object_get(j_auth, "client_ip");
    json_object *client_mac = json_object_object_get(j_auth, "client_mac");
    json_object *gw_id = json_object_object_get(j_auth, "gw_id");
    json_object *once_auth = json_object_object_get(j_auth, "once_auth");
    json_object *client_name = json_object_object_get(j_auth, "client_name");

    if (!token || !client_ip || !client_mac || !gw_id || !once_auth) {
        debug(LOG_ERR, "Auth: Missing required fields in JSON response");
        return;
    }

    const char *gw_id_str = json_object_get_string(gw_id);
    t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
    if (!gw_setting) {
        debug(LOG_ERR, "Auth: Gateway %s not found", gw_id_str);
        return;
    }

    if (json_object_get_boolean(once_auth)) {
        gw_setting->auth_mode = 0;
        debug(LOG_DEBUG, "Auth: Once-auth enabled, setting gateway %s auth mode to 0", gw_id_str);
#ifdef AW_FW4
        nft_reload_gw();
#endif
        char response_msg[128];
        snprintf(response_msg, sizeof(response_msg), "{\"status\":\"once_auth_enabled\",\"gw_id\":\"%s\"}", gw_id_str);
        send_response(transport, response_msg);
        return;
    }

    const char *client_ip_str = json_object_get_string(client_ip);
    const char *client_mac_str = json_object_get_string(client_mac);
    const char *token_str = json_object_get_string(token);

    if (client_list_find(client_ip_str, client_mac_str)) {
        debug(LOG_DEBUG, "Auth: Client %s (%s) already authenticated", client_mac_str, client_ip_str);
        char response_msg[256];
        snprintf(response_msg, sizeof(response_msg), "{\"status\":\"already_authenticated\",\"client_ip\":\"%s\",\"client_mac\":\"%s\"}", client_ip_str, client_mac_str);
        send_response(transport, response_msg);
        return;
    }

    LOCK_CLIENT_LIST();
    t_client *client = client_list_add(client_ip_str, client_mac_str, token_str, gw_setting);
    client->auth_type = AUTH_TYPE_AUTH_SERVER;
    fw_allow(client, FW_MARK_KNOWN);

    if (client_name) {
        const char *name_str = json_object_get_string(client_name);
        if (name_str && strlen(name_str) > 0) {
            if (strlen(name_str) <= 64) {
                if (client->name) free(client->name);
                client->name = strdup(name_str);
            } else {
                debug(LOG_WARNING, "Client name too long, truncating");
                if (client->name) free(client->name);
                client->name = strndup(name_str, 64);
            }
        }
    }

    client->first_login = time(NULL);
    client->is_online = 1;
    UNLOCK_CLIENT_LIST();

    LOCK_OFFLINE_CLIENT_LIST();
    t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);
    if (o_client) {
        offline_client_list_delete(o_client);
    }
    UNLOCK_OFFLINE_CLIENT_LIST();

    debug(LOG_DEBUG, "Auth: Added client %s (%s) with token %s", client_mac_str, client_ip_str, token_str);

    char response_msg[256];
    snprintf(response_msg, sizeof(response_msg), "{\"status\":\"auth_success\",\"client_ip\":\"%s\",\"client_mac\":\"%s\"}", client_ip_str, client_mac_str);
    send_response(transport, response_msg);
}

void handle_get_aw_status_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();

    char *aw_uptime = get_aw_uptime();

    struct sys_info info;
    memset(&info, 0, sizeof(info));
    get_sys_info(&info);

    char selected_section[128] = {0};
    if (uci_get_value("wifidogx", "wifidog", "selected_auth_server", selected_section, sizeof(selected_section)) != 0) {
        selected_section[0] = '\0';
    }

    char *hostname_copy = NULL;
    char *path_copy = NULL;
    int port_copy = 0;
    s_config *config = config_get_config();

    LOCK_CONFIG();
    if (config && config->auth_servers) {
        if (config->auth_servers->authserv_hostname) {
            hostname_copy = safe_strdup(config->auth_servers->authserv_hostname);
        }
        port_copy = config->auth_servers->authserv_http_port;
        if (config->auth_servers->authserv_path) {
            path_copy = safe_strdup(config->auth_servers->authserv_path);
        }
    }

    t_gateway_setting *gw_settings = NULL;
    t_mqtt_server *mqtt_server = NULL;
    if (config) {
        gw_settings = config->gateway_settings;
        mqtt_server = config->mqtt_server;
    }
    int gw_port = config ? config->gw_port : DEFAULT_GATEWAYPORT;
    int gw_https_port = config ? config->gw_https_port : DEFAULT_GATEWAY_HTTPS_PORT;
    int check_interval = config ? config->checkinterval : DEFAULT_CHECKINTERVAL;
    int client_timeout = config ? config->clienttimeout : DEFAULT_CLIENTTIMEOUT;
    int fw4_enabled = config ? config->fw4_enable : 0;
    int anti_nat = config ? config->enable_anti_nat : 0;
    int del_conntrack = config ? config->enable_del_conntrack : 0;

    UNLOCK_CONFIG();

    json_object_object_add(j_data, "service", json_object_new_string("apfree-wifidog"));
    json_object_object_add(j_data, "version", json_object_new_string(VERSION));
    if (aw_uptime) {
        json_object_object_add(j_data, "uptime", json_object_new_string(aw_uptime));
    }
    json_object_object_add(j_data, "uptime_seconds", json_object_new_int64(info.wifidog_uptime));

    extern pid_t restart_orig_pid;
    json_object_object_add(j_data, "has_been_restarted", json_object_new_string(restart_orig_pid ? "yes" : "no"));
    json_object_object_add(j_data, "restart_orig_pid", json_object_new_int((int)restart_orig_pid));

    const char *auth_mode_str = is_local_auth_mode() ? "Local" : (is_bypass_mode() ? "Bypass" : "Cloud");
    json_object_object_add(j_data, "auth_server_mode", json_object_new_string(auth_mode_str));
    json_object_object_add(j_data, "portal_auth", json_object_new_string(is_portal_auth_disabled() ? "Disabled" : "Enabled"));
    json_object_object_add(j_data, "bypass_mode", json_object_new_string(is_bypass_mode() ? "Yes" : "No"));

    json_object_object_add(j_data, "gateway_port", json_object_new_int(gw_port));
    json_object_object_add(j_data, "https_port", json_object_new_int(gw_https_port));
    json_object_object_add(j_data, "check_interval", json_object_new_int(check_interval));
    json_object_object_add(j_data, "client_timeout", json_object_new_int(client_timeout));

    json_object_object_add(j_data, "internet_connectivity", json_object_new_string(is_online() ? "yes" : "no"));
    json_object_object_add(j_data, "auth_server_reachable", json_object_new_string(is_auth_online() ? "yes" : "no"));

    if (selected_section[0]) {
        json_object_object_add(j_data, "selected_auth_server", json_object_new_string(selected_section));
    }

    json_object *j_auth = json_object_new_object();
    if (hostname_copy) {
        json_object_object_add(j_auth, "hostname", json_object_new_string(hostname_copy));
    }
    json_object_object_add(j_auth, "port", json_object_new_int(port_copy));
    if (path_copy) {
        json_object_object_add(j_auth, "path", json_object_new_string(path_copy));
    }
    json_object_object_add(j_data, "auth_server", j_auth);

    if (gw_settings) {
        json_object *j_gws = json_object_new_array();
        t_gateway_setting *g = gw_settings;
        while (g) {
            json_object *j_gw = json_object_new_object();
            json_object_object_add(j_gw, "interface", json_object_new_string(g->gw_interface ? g->gw_interface : "N/A"));
            json_object_object_add(j_gw, "gateway_id", json_object_new_string(g->gw_id ? g->gw_id : "N/A"));
            json_object_object_add(j_gw, "ipv4", json_object_new_string(g->gw_address_v4 ? g->gw_address_v4 : "N/A"));
            json_object_object_add(j_gw, "ipv6", json_object_new_string(g->gw_address_v6 ? g->gw_address_v6 : "N/A"));
            json_object_object_add(j_gw, "channel", json_object_new_string(g->gw_channel ? g->gw_channel : "N/A"));
            json_object_array_add(j_gws, j_gw);
            g = g->next;
        }
        json_object_object_add(j_data, "gateway_settings", j_gws);
    }

    json_object *j_sys = json_object_new_object();
    json_object_object_add(j_sys, "system_uptime_seconds", json_object_new_int64(info.sys_uptime));
    json_object_object_add(j_sys, "free_memory_kb", json_object_new_int(info.sys_memfree));
    json_object_object_add(j_sys, "load_average", json_object_new_double(info.sys_load));
    json_object_object_add(j_sys, "cpu_usage_percent", json_object_new_double(info.cpu_usage));
    if (info.cpu_temp > 0) {
        json_object_object_add(j_sys, "cpu_temperature_c", json_object_new_int(info.cpu_temp));
    }
    json_object_object_add(j_sys, "netfilter_conntrack", json_object_new_int64(info.nf_conntrack_count));
    json_object_object_add(j_data, "system_resources", j_sys);

    json_object *j_fw = json_object_new_object();
    json_object_object_add(j_fw, "fw4_enabled", json_object_new_boolean(fw4_enabled));
    json_object_object_add(j_fw, "anti_nat_enabled", json_object_new_boolean(anti_nat));
    json_object_object_add(j_fw, "del_conntrack", json_object_new_boolean(del_conntrack));
    json_object_object_add(j_data, "firewall_status", j_fw);

    if (mqtt_server) {
        json_object *j_mqtt = json_object_new_object();
        json_object_object_add(j_mqtt, "host", json_object_new_string(mqtt_server->hostname ? mqtt_server->hostname : "N/A"));
        json_object_object_add(j_mqtt, "port", json_object_new_int(mqtt_server->port));
        json_object_object_add(j_mqtt, "username", json_object_new_string(mqtt_server->username ? mqtt_server->username : "N/A"));
        json_object_object_add(j_mqtt, "connected", json_object_new_boolean(mqtt_is_connected()));
        json_object_object_add(j_data, "mqtt_server", j_mqtt);
    }

    json_object_object_add(j_data, "portal_auth_enabled", json_object_new_boolean(!is_portal_auth_disabled()));

    json_object *j_field_desc = json_object_new_object();
    json_object_object_add(j_field_desc, "service", json_object_new_string("Service name (string) - identifies this software component"));
    json_object_object_add(j_field_desc, "version", json_object_new_string("Version (string) - software version string"));
    json_object_object_add(j_field_desc, "uptime", json_object_new_string("Human-readable uptime (string), e.g. '1D 2H 3M 4S'"));
    json_object_object_add(j_field_desc, "uptime_seconds", json_object_new_string("Uptime in seconds (int64) since service start"));
    json_object_object_add(j_field_desc, "has_been_restarted", json_object_new_string("Indicates whether process was restarted during this run ('yes'/'no')"));
    json_object_object_add(j_field_desc, "restart_orig_pid", json_object_new_string("Original parent PID if restarted (int)"));
    json_object_object_add(j_field_desc, "auth_server_mode", json_object_new_string("Auth mode (string) - 'Local', 'Cloud' or 'Bypass'"));
    json_object_object_add(j_field_desc, "portal_auth", json_object_new_string("Portal authentication status (string) - 'Enabled' or 'Disabled'"));
    json_object_object_add(j_field_desc, "bypass_mode", json_object_new_string("Bypass mode flag (string) - 'Yes' or 'No'"));
    json_object_object_add(j_field_desc, "gateway_port", json_object_new_string("Gateway HTTP port (int) used by captive portal"));
    json_object_object_add(j_field_desc, "https_port", json_object_new_string("Gateway HTTPS port (int) used by captive portal"));
    json_object_object_add(j_field_desc, "check_interval", json_object_new_string("Connectivity check interval (int, seconds)"));
    json_object_object_add(j_field_desc, "client_timeout", json_object_new_string("Client session timeout (int, seconds)"));
    json_object_object_add(j_field_desc, "internet_connectivity", json_object_new_string("Hint whether Internet connectivity appears available ('yes'/'no')"));
    json_object_object_add(j_field_desc, "auth_server_reachable", json_object_new_string("Hint whether the configured auth server is reachable ('yes'/'no')"));
    json_object_object_add(j_field_desc, "selected_auth_server", json_object_new_string("UCI section name of the selected auth server (string), if configured"));

    json_object *j_auth_desc = json_object_new_object();
    json_object_object_add(j_auth_desc, "hostname", json_object_new_string("Auth server hostname (string) from runtime config"));
    json_object_object_add(j_auth_desc, "port", json_object_new_string("Auth server HTTP port (int) from runtime config"));
    json_object_object_add(j_auth_desc, "path", json_object_new_string("Auth server path (string) used for authentication requests"));
    json_object_object_add(j_field_desc, "auth_server", j_auth_desc);

    json_object_object_add(j_field_desc, "gateway_settings", json_object_new_string("Array of gateway objects. Each object: interface (string), gateway_id (string), ipv4 (string), ipv6 (string), channel (string)"));

    json_object *j_sys_desc = json_object_new_object();
    json_object_object_add(j_sys_desc, "system_uptime_seconds", json_object_new_string("System uptime in seconds (int64)"));
    json_object_object_add(j_sys_desc, "free_memory_kb", json_object_new_string("Free memory in KB (int)"));
    json_object_object_add(j_sys_desc, "load_average", json_object_new_string("System load average (double)"));
    json_object_object_add(j_sys_desc, "cpu_usage_percent", json_object_new_string("Estimated CPU usage percent (double)"));
    json_object_object_add(j_sys_desc, "cpu_temperature_c", json_object_new_string("CPU temperature in Celsius (int) if available"));
    json_object_object_add(j_sys_desc, "netfilter_conntrack", json_object_new_string("Number of conntrack entries (int64)"));
    json_object_object_add(j_field_desc, "system_resources", j_sys_desc);

    json_object *j_fw_desc = json_object_new_object();
    json_object_object_add(j_fw_desc, "fw4_enabled", json_object_new_string("IPv4 firewall enabled boolean"));
    json_object_object_add(j_fw_desc, "anti_nat_enabled", json_object_new_string("Anti-NAT rules enabled boolean"));
    json_object_object_add(j_fw_desc, "del_conntrack", json_object_new_string("Whether conntrack entries are removed on client disconnect (boolean)"));
    json_object_object_add(j_field_desc, "firewall_status", j_fw_desc);

    json_object *j_mqtt_desc = json_object_new_object();
    json_object_object_add(j_mqtt_desc, "host", json_object_new_string("MQTT broker hostname (string) from runtime config"));
    json_object_object_add(j_mqtt_desc, "port", json_object_new_string("MQTT broker port (int)"));
    json_object_object_add(j_mqtt_desc, "username", json_object_new_string("MQTT username (string) if configured"));
    json_object_object_add(j_mqtt_desc, "connected", json_object_new_string("Current MQTT connection state (boolean) - true if client connected to broker"));
    json_object_object_add(j_field_desc, "mqtt_server", j_mqtt_desc);

    json_object_object_add(j_field_desc, "portal_auth_enabled", json_object_new_string("Boolean (true/false) duplicate convenience indicating portal auth is enabled"));

    json_object_object_add(j_data, "field_descriptions", j_field_desc);

    json_object_object_add(j_response, "type", json_object_new_string("get_status_response"));
    json_object_object_add(j_response, "data", j_data);

    send_json_response(transport, j_response);

    free(aw_uptime);
    free(hostname_copy);
    free(path_copy);
}

void handle_update_device_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_device_info;

    debug(LOG_INFO, "Update device info request received");

    if (!json_object_object_get_ex(j_req, "device_info", &j_device_info)) {
        debug(LOG_ERR, "Update device info request missing 'device_info' field");

        json_object *j_type = json_object_new_string("update_device_info_error");
        json_object *j_error = json_object_new_string("Missing 'device_info' field");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    t_device_info *device_info = get_device_info();
    if (!device_info) {
        device_info = safe_malloc(sizeof(t_device_info));
        memset(device_info, 0, sizeof(t_device_info));
        config_get_config()->device_info = device_info;
    }

    json_object *j_ap_device_id, *j_ap_mac_address, *j_ap_longitude, *j_ap_latitude, *j_location_id;

    if (json_object_object_get_ex(j_device_info, "ap_device_id", &j_ap_device_id)) {
        const char *ap_device_id = json_object_get_string(j_ap_device_id);
        if (ap_device_id && strlen(ap_device_id) > 0 && strlen(ap_device_id) <= 64) {
            if (device_info->ap_device_id) free(device_info->ap_device_id);
            device_info->ap_device_id = safe_strdup(ap_device_id);
            uci_set_value("wifidogx", "common", "ap_device_id", ap_device_id);
            debug(LOG_DEBUG, "Updated ap_device_id: %s", ap_device_id);
        } else {
            debug(LOG_WARNING, "Invalid ap_device_id length");
        }
    }

    if (json_object_object_get_ex(j_device_info, "ap_mac_address", &j_ap_mac_address)) {
        const char *ap_mac_address = json_object_get_string(j_ap_mac_address);
        if (ap_mac_address && strlen(ap_mac_address) > 0 && strlen(ap_mac_address) <= 18) {
            if (device_info->ap_mac_address) free(device_info->ap_mac_address);
            device_info->ap_mac_address = safe_strdup(ap_mac_address);
            uci_set_value("wifidogx", "common", "ap_mac_address", ap_mac_address);
            debug(LOG_DEBUG, "Updated ap_mac_address: %s", ap_mac_address);
        } else {
            debug(LOG_WARNING, "Invalid ap_mac_address format");
        }
    }

    if (json_object_object_get_ex(j_device_info, "ap_longitude", &j_ap_longitude)) {
        const char *ap_longitude = json_object_get_string(j_ap_longitude);
        if (ap_longitude && strlen(ap_longitude) > 0 && strlen(ap_longitude) <= 32) {
            if (device_info->ap_longitude) free(device_info->ap_longitude);
            device_info->ap_longitude = safe_strdup(ap_longitude);
            uci_set_value("wifidogx", "common", "ap_longitude", ap_longitude);
            debug(LOG_DEBUG, "Updated ap_longitude: %s", ap_longitude);
        } else {
            debug(LOG_WARNING, "Invalid ap_longitude format");
        }
    }

    if (json_object_object_get_ex(j_device_info, "ap_latitude", &j_ap_latitude)) {
        const char *ap_latitude = json_object_get_string(j_ap_latitude);
        if (ap_latitude && strlen(ap_latitude) > 0 && strlen(ap_latitude) <= 32) {
            if (device_info->ap_latitude) free(device_info->ap_latitude);
            device_info->ap_latitude = safe_strdup(ap_latitude);
            uci_set_value("wifidogx", "common", "ap_latitude", ap_latitude);
            debug(LOG_DEBUG, "Updated ap_latitude: %s", ap_latitude);
        } else {
            debug(LOG_WARNING, "Invalid ap_latitude format");
        }
    }

    if (json_object_object_get_ex(j_device_info, "location_id", &j_location_id)) {
        const char *location_id = json_object_get_string(j_location_id);
        if (location_id && strlen(location_id) > 0 && strlen(location_id) <= 64) {
            if (device_info->location_id) free(device_info->location_id);
            device_info->location_id = safe_strdup(location_id);
            uci_set_value("wifidogx", "common", "location_id", location_id);
            debug(LOG_DEBUG, "Updated location_id: %s", location_id);
        } else {
            debug(LOG_WARNING, "Invalid location_id format");
        }
    }

    json_object *j_type = json_object_new_string("update_device_info_response");
    json_object *j_status = json_object_new_string("success");
    json_object *j_message = json_object_new_string("Device info updated successfully");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "status", j_status);
    json_object_object_add(j_response, "message", j_message);

    send_json_response(transport, j_response);

    debug(LOG_INFO, "Device info updated successfully");
}

void handle_get_device_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    debug(LOG_INFO, "Get device info request received");

    t_device_info *device_info = get_device_info();
    if (!device_info) {
        json_object *j_type = json_object_new_string("get_device_info_error");
        json_object *j_error = json_object_new_string("Device info not set");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_data = json_object_new_object();

    if (device_info->ap_device_id) {
        json_object_object_add(j_data, "ap_device_id", json_object_new_string(device_info->ap_device_id));
    }
    if (device_info->ap_mac_address) {
        json_object_object_add(j_data, "ap_mac_address", json_object_new_string(device_info->ap_mac_address));
    }
    if (device_info->ap_longitude) {
        json_object_object_add(j_data, "ap_longitude", json_object_new_string(device_info->ap_longitude));
    }
    if (device_info->ap_latitude) {
        json_object_object_add(j_data, "ap_latitude", json_object_new_string(device_info->ap_latitude));
    }
    if (device_info->location_id) {
        json_object_object_add(j_data, "location_id", json_object_new_string(device_info->location_id));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_device_info_response"));
    json_object_object_add(j_response, "data", j_data);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending device info response: %s", response_str);
    send_json_response(transport, j_response);

    debug(LOG_INFO, "Device info sent successfully");
}

void handle_get_trusted_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "domains", json_object_new_string("Array of trusted domain strings (exact hostnames)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
}

void handle_sync_trusted_domain_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    clear_trusted_domains();
    uci_del_list_option("wifidogx", "common", "trusted_domains");

    if (json_object_object_get_ex(j_req, "domains", &j_domains) && json_object_is_type(j_domains, json_type_array)) {
        int array_len = json_object_array_length(j_domains);
        for (int i = 0; i < array_len; i++) {
            json_object *j_domain = json_object_array_get_idx(j_domains, i);
            if (json_object_is_type(j_domain, json_type_string)) {
                const char *domain_str = json_object_get_string(j_domain);
                add_trusted_domains(domain_str);
                uci_add_list_value("wifidogx", "common", "trusted_domains", domain_str);
            }
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_domain_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted domains synchronized successfully"));
    send_json_response(transport, j_response);
}

void handle_get_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains = json_object_new_array();

    t_domain_trusted *trusted_domains = get_trusted_wildcard_domains();
    for (t_domain_trusted *d = trusted_domains; d; d = d->next) {
        json_object_array_add(j_domains, json_object_new_string(d->domain));
    }

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "domains", j_domains);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "domains", json_object_new_string("Array of trusted wildcard domain strings (may include leading '*.' patterns)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
}

void handle_sync_trusted_wildcard_domains_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_domains;

    clear_trusted_wildcard_domains();
    uci_del_list_option("wifidogx", "common", "trusted_wildcard_domains");

    if (json_object_object_get_ex(j_req, "domains", &j_domains) && json_object_is_type(j_domains, json_type_array)) {
        int array_len = json_object_array_length(j_domains);
        for (int i = 0; i < array_len; i++) {
            json_object *j_domain = json_object_array_get_idx(j_domains, i);
            if (json_object_is_type(j_domain, json_type_string)) {
                const char *domain_str = json_object_get_string(j_domain);
                add_trusted_wildcard_domains(domain_str);
                uci_add_list_value("wifidogx", "common", "trusted_wildcard_domains", domain_str);
            }
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_wildcard_domains_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted wildcard domains synchronized successfully"));
    send_json_response(transport, j_response);
}

void handle_get_trusted_mac_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_macs = json_object_new_array();

    char *macs = mqtt_get_serialize_maclist(TRUSTED_MAC);
    if (macs && strlen(macs) > 0) {
        char *saveptr = NULL;
        char *token = strtok_r(macs, ",", &saveptr);
        while (token) {
            trim_newline(token);
            json_object_array_add(j_macs, json_object_new_string(token));
            token = strtok_r(NULL, ",", &saveptr);
        }
    }
    if (macs) free(macs);

    json_object_object_add(j_response, "type", json_object_new_string("get_trusted_mac_response"));
    json_object_object_add(j_response, "macs", j_macs);

    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "macs", json_object_new_string("Array of trusted MAC address strings (format aa:bb:cc:dd:ee:ff)"));
    json_object_object_add(j_response, "field_descriptions", j_fd);

    send_json_response(transport, j_response);
}

void handle_sync_trusted_mac_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();

    clear_trusted_maclist();
    uci_del_list_option("wifidogx", "common", "trustd_macs");

    json_object *j_macs = NULL;
    if (json_object_object_get_ex(j_req, "macs", &j_macs) && json_object_is_type(j_macs, json_type_array)) {
        int len = json_object_array_length(j_macs);
        size_t buf_len = len * 18 + 16;
        char *buf = calloc(1, buf_len);
        if (buf) {
            char *p = buf;
            for (int i = 0; i < len; i++) {
                json_object *j_mac = json_object_array_get_idx(j_macs, i);
                if (!json_object_is_type(j_mac, json_type_string)) continue;
                const char *mac = json_object_get_string(j_mac);
                if (!mac) continue;
                uci_add_list_value("wifidogx", "common", "trustd_macs", mac);
                if (p != buf) { *p++ = ','; }
                strncpy(p, mac, buf_len - (p - buf) - 1);
                p += strlen(p);
            }
            if (strlen(buf) > 0) add_trusted_maclist(buf);
            free(buf);
        }
    } else if (json_object_object_get_ex(j_req, "values", &j_macs) && json_object_is_type(j_macs, json_type_array)) {
        int len = json_object_array_length(j_macs);
        size_t buf_len = len * 18 + 16;
        char *buf = calloc(1, buf_len);
        if (buf) {
            char *p = buf;
            for (int i = 0; i < len; i++) {
                json_object *j_mac = json_object_array_get_idx(j_macs, i);
                if (!json_object_is_type(j_mac, json_type_string)) continue;
                const char *mac = json_object_get_string(j_mac);
                if (!mac) continue;
                uci_add_list_value("wifidogx", "common", "trustd_macs", mac);
                if (p != buf) { *p++ = ','; }
                strncpy(p, mac, buf_len - (p - buf) - 1);
                p += strlen(p);
            }
            if (strlen(buf) > 0) add_trusted_maclist(buf);
            free(buf);
        }
    }

    json_object_object_add(j_response, "type", json_object_new_string("sync_trusted_mac_response"));
    json_object_object_add(j_response, "status", json_object_new_string("success"));
    json_object_object_add(j_response, "message", json_object_new_string("Trusted MACs synchronized successfully"));
    send_json_response(transport, j_response);
}


