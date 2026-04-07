// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>

/* Check for aw-bpfctl availability in PATH or common locations */
static int aw_bpfctl_available(void)
{
    const char *name = "aw-bpfctl";
    const char *cands[] = {"/usr/bin/aw-bpfctl", "/usr/local/bin/aw-bpfctl", NULL};
    for (int i = 0; cands[i]; i++) {
        if (access(cands[i], X_OK) == 0) return 1;
    }
    const char *path = getenv("PATH");
    if (!path) return 0;
    char *p = strdup(path);
    if (!p) return 0;
    char *tok = strtok(p, ":");
    while (tok) {
        char buf[PATH_MAX];
        snprintf(buf, sizeof(buf), "%s/%s", tok, name);
        if (access(buf, X_OK) == 0) {
            free(p);
            return 1;
        }
        tok = strtok(NULL, ":");
    }
    free(p);
    return 0;
}

static int run_aw_bpfctl_command(json_object *j_response, json_object *j_data,
                                 api_transport_context_t *transport,
                                 const char *cmd, const char *ok_message)
{
    char *out = NULL;
    int status = 0;

    if (!aw_bpfctl_available()) {
        api_response_set_error(j_response, 2001, "aw-bpfctl not available on system");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(-1));
            json_object_object_add(j_data, "output", json_object_new_string(""));
        }
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return -1;
    }

    run_command_capture(cmd, &out, &status);

    if (status != 0) {
        api_response_set_error(j_response, 3001, "aw-bpfctl command failed");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(status));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_response);
        json_object_put(j_response);
        free(out);
        return -1;
    }

    api_response_set_success(j_response, ok_message ? ok_message : "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(status));
        json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
    free(out);
    return 0;
}

/* Validate requested aw-bpfctl table name */
static int is_valid_bpf_table(const char *table)
{
    if (!table) return 0;
    if (strcmp(table, "ipv4") == 0) return 1;
    if (strcmp(table, "ipv6") == 0) return 1;
    if (strcmp(table, "mac") == 0) return 1;
    return 0;
}

/* Validate bpf_json table names. Query view additionally supports sid and l7. */
static int is_valid_bpf_json_table(const char *table)
{
    if (is_valid_bpf_table(table)) return 1;
    if (strcmp(table, "sid") == 0) return 1;
    if (strcmp(table, "l7") == 0) return 1;
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

    json_object *j_response = api_response_new("bpf_add_response");

    if (!j_table || !j_addr) {
        api_response_set_error(j_response, 1000, "Missing 'table' or 'address' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
       
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid MAC address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    char cmd[512];
    int ret = snprintf(cmd, sizeof(cmd), "aw-bpfctl %s add %s", table, addr);
    if (ret <= 0 || ret >= (int)sizeof(cmd)) {
        api_response_set_error(j_response, 3000, "Command buffer overflow");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    run_aw_bpfctl_command(j_response, NULL, transport, cmd, "Entry added successfully");
}

void handle_bpf_del_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");
    json_object *j_response = api_response_new("bpf_del_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_addr) {
        api_response_set_error(j_response, 1000, "Missing 'table' or 'address' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid MAC address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s del %s", table, addr);

    run_aw_bpfctl_command(j_response, j_data, transport, cmd, "OK");
}

void handle_bpf_flush_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = api_response_new("bpf_flush_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table) {
        api_response_set_error(j_response, 1000, "Missing 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s flush", table);

    run_aw_bpfctl_command(j_response, j_data, transport, cmd, "OK");
}

void handle_bpf_json_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = api_response_new("bpf_json_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table) {
        api_response_set_error(j_response, 1000, "Missing 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_json_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s json", table);

    if (!aw_bpfctl_available()) {
        api_response_set_error(j_response, 2001, "aw-bpfctl not available on system");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(-1));
            json_object_object_add(j_data, "output", json_object_new_string(""));
        }
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    char *out = NULL;
    int status = 0;
    run_command_capture(cmd, &out, &status);

    if (status != 0) {
        api_response_set_error(j_response, 3001, "aw-bpfctl command failed");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(status));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_response);
        json_object_put(j_response);
        free(out);
        return;
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(status));
    }

    if (out && strlen(out) > 0) {
        json_object *parsed = json_tokener_parse(out);
        if (parsed && j_data) {
            json_object_object_add(j_data, "payload", parsed);
        } else if (j_data) {
            json_object_object_add(j_data, "output", json_object_new_string(out));
        }
    } else {
        if (j_data) {
            json_object_object_add(j_data, "output", json_object_new_string(""));
        }
    }

    send_json_response(transport, j_response);
    json_object_put(j_response);
    free(out);
}

void handle_bpf_update_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_target = json_object_object_get(j_req, "target");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = api_response_new("bpf_update_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_target || !j_down || !j_up) {
        api_response_set_error(j_response, 1000, "Missing required parameters: 'table','target','downrate','uprate'");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
    const char *target = json_object_get_string(j_target);

    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid MAC target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        api_response_set_error(j_response, 1002, "Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update %s downrate %lld uprate %lld", table, target, down, up);

    run_aw_bpfctl_command(j_response, j_data, transport, cmd, "OK");
}

void handle_bpf_update_all_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = api_response_new("bpf_update_all_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_down || !j_up) {
        api_response_set_error(j_response, 1000, "Missing required parameters: 'table','downrate','uprate'");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        api_response_set_error(j_response, 1002, "Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "aw-bpfctl %s update_all downrate %lld uprate %lld", table, down, up);

    run_aw_bpfctl_command(j_response, j_data, transport, cmd, "OK");
}
