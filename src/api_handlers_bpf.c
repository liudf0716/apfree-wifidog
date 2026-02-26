// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"

#include <arpa/inet.h>
#include <ctype.h>

/* Validate requested aw-bpfctl table name */
static int is_valid_bpf_table(const char *table)
{
    if (!table) return 0;
    if (strcmp(table, "ipv4") == 0) return 1;
    if (strcmp(table, "ipv6") == 0) return 1;
    if (strcmp(table, "mac") == 0) return 1;
    return 0;
}

/* Validate IPv4 address using inet_pton */
static int is_valid_ipv4_address(const char *addr)
{
    if (!addr) return 0;
    struct in_addr in;
    return inet_pton(AF_INET, addr, &in) == 1;
}

/* Validate IPv6 address using inet_pton */
static int is_valid_ipv6_address(const char *addr)
{
    if (!addr) return 0;
    struct in6_addr in6;
    return inet_pton(AF_INET6, addr, &in6) == 1;
}

/* Validate MAC address formats: aa:bb:cc:dd:ee:ff or aabbccddeeff */
static int is_valid_mac_address(const char *mac)
{
    if (!mac) return 0;
    size_t len = strlen(mac);
    if (len == 17) {
        int vals[6];
        if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        if (sscanf(mac, "%x-%x-%x-%x-%x-%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        return 0;
    } else if (len == 12) {
        for (size_t i = 0; i < 12; i++) {
            if (!isxdigit((unsigned char)mac[i])) return 0;
        }
        return 1;
    }
    return 0;
}

/* Validate bitrates (bps). Accept 1 .. 10_000_000_000 (10 Gbps) */
static int is_valid_bitrate_long(long long v)
{
    if (v <= 0) return 0;
    if (v > 10000000000LL) return 0;
    return 1;
}

void handle_bpf_add_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");

    json_object *j_response = json_object_new_object();

    if (!j_table || !j_addr) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' or 'address' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC address"));
            send_json_response(transport, j_response);
            return;
        }
    }

    char cmd[512];
    int ret = snprintf(cmd, sizeof(cmd), "aw-bpfctl %s add %s", table, addr);
    if (ret <= 0 || ret >= (int)sizeof(cmd)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_add_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Command buffer overflow"));
        send_json_response(transport, j_response);
        return;
    }

    char *out = NULL;
    int status = 0;
    int rc = run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_add_response"));
    json_object_object_add(j_response, "status", json_object_new_string((rc == 0) ? "success" : "error"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));

    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_del_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_addr) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' or 'address' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 address"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_del_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC address"));
            send_json_response(transport, j_response);
            return;
        }
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s del %s", table, addr);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_del_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_flush_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = json_object_new_object();

    if (!j_table) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s flush", table);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_flush_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_json_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = json_object_new_object();

    if (!j_table) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_json_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_json_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s json", table);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_json_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));

    if (out && strlen(out) > 0) {
        json_object *parsed = json_tokener_parse(out);
        if (parsed) {
            json_object_object_add(j_response, "data", parsed);
        } else {
            json_object_object_add(j_response, "output", json_object_new_string(out));
        }
    } else {
        json_object_object_add(j_response, "output", json_object_new_string(""));
    }

    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_update_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_target = json_object_object_get(j_req, "target");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_target || !j_down || !j_up) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required parameters: 'table','target','downrate','uprate'"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }
    const char *target = json_object_get_string(j_target);

    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv4 target"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid IPv6 target"));
            send_json_response(transport, j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(target)) {
            json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Invalid MAC target"));
            send_json_response(transport, j_response);
            return;
        }
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update %s downrate %lld uprate %lld", table, target, down, up);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_update_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}

void handle_bpf_update_all_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = json_object_new_object();

    if (!j_table || !j_down || !j_up) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing required parameters: 'table','downrate','uprate'"));
        send_json_response(transport, j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'table' parameter"));
        send_json_response(transport, j_response);
        return;
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)"));
        send_json_response(transport, j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update_all downrate %lld uprate %lld", table, down, up);

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    json_object_object_add(j_response, "type", json_object_new_string("bpf_update_all_response"));
    json_object_object_add(j_response, "exit_code", json_object_new_int(status));
    json_object_object_add(j_response, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_response);
    free(out);
}
