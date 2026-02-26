// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"
#include "uci_helper.h"

#include <uci.h>

static int json_value_to_uci_string(json_object *value_obj, char *buf, size_t buf_len, const char **out_str)
{
    if (!value_obj || !out_str) {
        return -1;
    }

    json_type t = json_object_get_type(value_obj);
    switch (t) {
        case json_type_string:
            *out_str = json_object_get_string(value_obj);
            return *out_str ? 0 : -1;
        case json_type_boolean:
            if (!buf || buf_len < 2) return -1;
            snprintf(buf, buf_len, "%d", json_object_get_boolean(value_obj) ? 1 : 0);
            *out_str = buf;
            return 0;
        case json_type_int:
            if (!buf || buf_len < 4) return -1;
            snprintf(buf, buf_len, "%lld", (long long)json_object_get_int64(value_obj));
            *out_str = buf;
            return 0;
        case json_type_double:
            if (!buf || buf_len < 8) return -1;
            snprintf(buf, buf_len, "%.15g", json_object_get_double(value_obj));
            *out_str = buf;
            return 0;
        default:
            return -1;
    }
}

static void append_uci_option_to_json(struct uci_option *opt, json_object *j_target)
{
    if (!opt || !j_target || !opt->e.name) {
        return;
    }

    if (opt->type == UCI_TYPE_STRING) {
        json_object_object_add(j_target, opt->e.name, json_object_new_string(opt->v.string ? opt->v.string : ""));
        return;
    }

    if (opt->type == UCI_TYPE_LIST) {
        json_object *arr = json_object_new_array();
        struct uci_element *e = NULL;
        uci_foreach_element(&opt->v.list, e) {
            json_object_array_add(arr, json_object_new_string(e->name ? e->name : ""));
        }
        json_object_object_add(j_target, opt->e.name, arr);
    }
}

static int ipsec_add_list_option_with_ctx(struct uci_context *ctx, const char *section_name, const char *option_name, json_object *j_arr)
{
    if (!ctx || !section_name || !option_name || !j_arr || !json_object_is_type(j_arr, json_type_array)) {
        return -1;
    }

    int count = (int)json_object_array_length(j_arr);
    for (int i = 0; i < count; i++) {
        json_object *item = json_object_array_get_idx(j_arr, i);
        if (!item) continue;

        char value_buf[64];
        const char *value_str = NULL;
        if (json_value_to_uci_string(item, value_buf, sizeof(value_buf), &value_str) != 0 || !value_str) {
            continue;
        }

        char path[256];
        int n = snprintf(path, sizeof(path), "ipsec.%s.%s", section_name, option_name);
        if (n <= 0 || n >= (int)sizeof(path)) {
            return -1;
        }

        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) {
            return -1;
        }

        ptr.value = (char *)value_str;
        if (uci_add_list(ctx, &ptr) != UCI_OK) {
            return -1;
        }
    }

    return 0;
}

static int ipsec_add_section_from_json(struct uci_context *ctx, struct uci_package *pkg, const char *section_type, json_object *j_section)
{
    if (!ctx || !pkg || !section_type || !j_section || !json_object_is_type(j_section, json_type_object)) {
        return -1;
    }

    struct uci_section *new_sec = NULL;
    if (uci_add_section(ctx, pkg, section_type, &new_sec) != UCI_OK || !new_sec || !new_sec->e.name) {
        return -1;
    }

    const char *sec_name = new_sec->e.name;
    json_object_object_foreach(j_section, key, val) {
        if (!key || strcmp(key, "_name") == 0 || !val) {
            continue;
        }

        if (json_object_is_type(val, json_type_array)) {
            if (ipsec_add_list_option_with_ctx(ctx, sec_name, key, val) != 0) {
                return -1;
            }
            continue;
        }

        char value_buf[64];
        const char *value_str = NULL;
        if (json_value_to_uci_string(val, value_buf, sizeof(value_buf), &value_str) != 0 || !value_str) {
            continue;
        }

        if (uci_set_option_with_ctx(ctx, "ipsec", sec_name, key, value_str) != 0) {
            return -1;
        }
    }

    return 0;
}

void handle_get_ipsec_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    json_object *j_proposals = json_object_new_array();
    json_object *j_tunnels = json_object_new_array();
    json_object *j_remotes = json_object_new_array();

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("ipsec", &ctx, &pkg) != 0) {
        json_object_object_add(j_response, "type", json_object_new_string("get_ipsec_vpn_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to open ipsec config"));
        send_json_response(transport, j_response);
        return;
    }

    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || !sec->e.name) continue;

        json_object *j_section = json_object_new_object();
        json_object_object_add(j_section, "_name", json_object_new_string(sec->e.name));

        struct uci_element *oe = NULL;
        uci_foreach_element(&sec->options, oe) {
            struct uci_option *opt = uci_to_option(oe);
            append_uci_option_to_json(opt, j_section);
        }

        if (strcmp(sec->type, "ipsec") == 0) {
            if (!json_object_object_get(j_data, "global")) {
                json_object_object_add(j_data, "global", j_section);
            } else {
                json_object_put(j_section);
            }
        } else if (strcmp(sec->type, "crypto_proposal") == 0) {
            json_object_array_add(j_proposals, j_section);
        } else if (strcmp(sec->type, "tunnel") == 0) {
            json_object_array_add(j_tunnels, j_section);
        } else if (strcmp(sec->type, "remote") == 0) {
            json_object_array_add(j_remotes, j_section);
        } else {
            json_object_put(j_section);
        }
    }

    uci_close_package(ctx, pkg);

    json_object_object_add(j_data, "crypto_proposals", j_proposals);
    json_object_object_add(j_data, "tunnels", j_tunnels);
    json_object_object_add(j_data, "remotes", j_remotes);

    json_object_object_add(j_response, "type", json_object_new_string("get_ipsec_vpn_response"));
    json_object_object_add(j_response, "data", j_data);
    send_json_response(transport, j_response);
}

void handle_set_ipsec_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_data = json_object_object_get(j_req, "data");
    if (!j_data || !json_object_is_type(j_data, json_type_object)) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_ipsec_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Missing or invalid 'data' object"));
        send_json_response(transport, j_err);
        return;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("ipsec", &ctx, &pkg) != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_ipsec_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to open ipsec config"));
        send_json_response(transport, j_err);
        return;
    }

    int rc = 0;

    char old_sections[128][128];
    int old_count = 0;
    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        if (!e->name || e->name[0] == '\0') continue;
        if (old_count >= (int)(sizeof(old_sections) / sizeof(old_sections[0]))) break;
        strncpy(old_sections[old_count], e->name, sizeof(old_sections[old_count]) - 1);
        old_sections[old_count][sizeof(old_sections[old_count]) - 1] = '\0';
        old_count++;
    }

    for (int i = 0; i < old_count; i++) {
        if (uci_delete_section_with_ctx(ctx, "ipsec", old_sections[i]) != 0) {
            rc = -1;
            break;
        }
    }

    if (rc == 0) {
        json_object *j_global = json_object_object_get(j_data, "global");
        if (j_global && json_object_is_type(j_global, json_type_object)) {
            if (ipsec_add_section_from_json(ctx, pkg, "ipsec", j_global) != 0) {
                rc = -1;
            }
        }
    }

    if (rc == 0) {
        json_object *j_props = json_object_object_get(j_data, "crypto_proposals");
        if (j_props && json_object_is_type(j_props, json_type_array)) {
            int n = (int)json_object_array_length(j_props);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_props, i);
                if (obj && json_object_is_type(obj, json_type_object)) {
                    if (ipsec_add_section_from_json(ctx, pkg, "crypto_proposal", obj) != 0) {
                        rc = -1;
                        break;
                    }
                }
            }
        }
    }

    if (rc == 0) {
        json_object *j_tns = json_object_object_get(j_data, "tunnels");
        if (j_tns && json_object_is_type(j_tns, json_type_array)) {
            int n = (int)json_object_array_length(j_tns);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_tns, i);
                if (obj && json_object_is_type(obj, json_type_object)) {
                    if (ipsec_add_section_from_json(ctx, pkg, "tunnel", obj) != 0) {
                        rc = -1;
                        break;
                    }
                }
            }
        }
    }

    if (rc == 0) {
        json_object *j_rms = json_object_object_get(j_data, "remotes");
        if (j_rms && json_object_is_type(j_rms, json_type_array)) {
            int n = (int)json_object_array_length(j_rms);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_rms, i);
                if (obj && json_object_is_type(obj, json_type_object)) {
                    if (ipsec_add_section_from_json(ctx, pkg, "remote", obj) != 0) {
                        rc = -1;
                        break;
                    }
                }
            }
        }
    }

    if (rc == 0 && uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        rc = -1;
    }

    uci_close_package(ctx, pkg);

    if (rc != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_ipsec_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to update ipsec config"));
        send_json_response(transport, j_err);
        return;
    }

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("set_ipsec_vpn_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "message", json_object_new_string("IPsec VPN configuration updated"));
    send_json_response(transport, j_resp);
}

void handle_get_ipsec_vpn_status_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_resp = json_object_new_object();
    char *out = NULL;
    int exit_code = 0;

    int rc = run_command_capture("swanctl -l 2>&1", &out, &exit_code);
    if (rc != 0) {
        json_object_object_add(j_resp, "type", json_object_new_string("get_ipsec_vpn_status_error"));
        json_object_object_add(j_resp, "error", json_object_new_string("Failed to execute swanctl -l"));
        json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    if (exit_code != 0) {
        json_object_object_add(j_resp, "type", json_object_new_string("get_ipsec_vpn_status_error"));
        json_object_object_add(j_resp, "error", json_object_new_string("swanctl -l returned non-zero exit code"));
        json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    json_object_object_add(j_resp, "type", json_object_new_string("get_ipsec_vpn_status_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
    json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_resp);

    free(out);
}

static int is_wireguard_peer_section_type(const char *section_type)
{
    if (!section_type) {
        return 0;
    }
    return strncmp(section_type, "wireguard_", strlen("wireguard_")) == 0;
}

static int add_list_option_with_ctx(struct uci_context *ctx, const char *package_name, const char *section_name, const char *option_name, json_object *j_arr)
{
    if (!ctx || !package_name || !section_name || !option_name || !j_arr || !json_object_is_type(j_arr, json_type_array)) {
        return -1;
    }

    int count = (int)json_object_array_length(j_arr);
    for (int i = 0; i < count; i++) {
        json_object *item = json_object_array_get_idx(j_arr, i);
        if (!item) continue;

        char value_buf[64];
        const char *value_str = NULL;
        if (json_value_to_uci_string(item, value_buf, sizeof(value_buf), &value_str) != 0 || !value_str) {
            continue;
        }

        char path[256];
        int n = snprintf(path, sizeof(path), "%s.%s.%s", package_name, section_name, option_name);
        if (n <= 0 || n >= (int)sizeof(path)) {
            return -1;
        }

        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK) {
            return -1;
        }

        ptr.value = (char *)value_str;
        if (uci_add_list(ctx, &ptr) != UCI_OK) {
            return -1;
        }
    }

    return 0;
}

static int add_network_section_from_json(struct uci_context *ctx, struct uci_package *pkg, const char *section_type, json_object *j_section)
{
    if (!ctx || !pkg || !section_type || !j_section || !json_object_is_type(j_section, json_type_object)) {
        return -1;
    }

    struct uci_section *new_sec = NULL;
    if (uci_add_section(ctx, pkg, section_type, &new_sec) != UCI_OK || !new_sec || !new_sec->e.name) {
        return -1;
    }

    const char *sec_name = new_sec->e.name;
    if (strcmp(section_type, "interface") == 0) {
        if (uci_set_option_with_ctx(ctx, "network", sec_name, "proto", "wireguard") != 0) {
            return -1;
        }
    }

    json_object_object_foreach(j_section, key, val) {
        if (!key || !val || strcmp(key, "_name") == 0 || strcmp(key, "_type") == 0 || strcmp(key, "interface") == 0) {
            continue;
        }

        if (json_object_is_type(val, json_type_array)) {
            if (add_list_option_with_ctx(ctx, "network", sec_name, key, val) != 0) {
                return -1;
            }
            continue;
        }

        char value_buf[64];
        const char *value_str = NULL;
        if (json_value_to_uci_string(val, value_buf, sizeof(value_buf), &value_str) != 0 || !value_str) {
            continue;
        }

        if (uci_set_option_with_ctx(ctx, "network", sec_name, key, value_str) != 0) {
            return -1;
        }
    }

    return 0;
}

void handle_get_wireguard_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    json_object *j_interfaces = json_object_new_array();
    json_object *j_peers = json_object_new_array();

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        json_object_object_add(j_response, "type", json_object_new_string("get_wireguard_vpn_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to open network config"));
        send_json_response(transport, j_response);
        return;
    }

    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || !sec->e.name) continue;

        if (strcmp(sec->type, "interface") != 0 && !is_wireguard_peer_section_type(sec->type)) {
            continue;
        }

        if (strcmp(sec->type, "interface") == 0) {
            const char *proto = uci_lookup_option_string(ctx, sec, "proto");
            if (!proto || strcmp(proto, "wireguard") != 0) {
                continue;
            }
        }

        json_object *j_section = json_object_new_object();
        json_object_object_add(j_section, "_name", json_object_new_string(sec->e.name));
        json_object_object_add(j_section, "_type", json_object_new_string(sec->type));

        if (is_wireguard_peer_section_type(sec->type)) {
            const char *prefix = "wireguard_";
            size_t prefix_len = strlen(prefix);
            if (strlen(sec->type) > prefix_len) {
                json_object_object_add(j_section, "interface", json_object_new_string(sec->type + prefix_len));
            }
        }

        struct uci_element *oe = NULL;
        uci_foreach_element(&sec->options, oe) {
            struct uci_option *opt = uci_to_option(oe);
            append_uci_option_to_json(opt, j_section);
        }

        if (strcmp(sec->type, "interface") == 0) {
            json_object_array_add(j_interfaces, j_section);
        } else {
            json_object_array_add(j_peers, j_section);
        }
    }

    uci_close_package(ctx, pkg);

    json_object_object_add(j_data, "interfaces", j_interfaces);
    json_object_object_add(j_data, "peers", j_peers);

    json_object_object_add(j_response, "type", json_object_new_string("get_wireguard_vpn_response"));
    json_object_object_add(j_response, "data", j_data);
    send_json_response(transport, j_response);
}

void handle_set_wireguard_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_data = json_object_object_get(j_req, "data");
    if (!j_data || !json_object_is_type(j_data, json_type_object)) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wireguard_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Missing or invalid 'data' object"));
        send_json_response(transport, j_err);
        return;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wireguard_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to open network config"));
        send_json_response(transport, j_err);
        return;
    }

    int rc = 0;

    char old_sections[128][128];
    int old_count = 0;
    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || !sec->e.name || sec->e.name[0] == '\0') continue;

        int is_wg_interface = 0;
        if (strcmp(sec->type, "interface") == 0) {
            const char *proto = uci_lookup_option_string(ctx, sec, "proto");
            if (proto && strcmp(proto, "wireguard") == 0) {
                is_wg_interface = 1;
            }
        }

        if (!is_wg_interface && !is_wireguard_peer_section_type(sec->type)) {
            continue;
        }

        if (old_count >= (int)(sizeof(old_sections) / sizeof(old_sections[0]))) {
            break;
        }
        strncpy(old_sections[old_count], sec->e.name, sizeof(old_sections[old_count]) - 1);
        old_sections[old_count][sizeof(old_sections[old_count]) - 1] = '\0';
        old_count++;
    }

    for (int i = 0; i < old_count; i++) {
        if (uci_delete_section_with_ctx(ctx, "network", old_sections[i]) != 0) {
            rc = -1;
            break;
        }
    }

    if (rc == 0) {
        json_object *j_interfaces = json_object_object_get(j_data, "interfaces");
        if (j_interfaces && json_object_is_type(j_interfaces, json_type_array)) {
            int n = (int)json_object_array_length(j_interfaces);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_interfaces, i);
                if (!obj || !json_object_is_type(obj, json_type_object)) {
                    continue;
                }

                if (add_network_section_from_json(ctx, pkg, "interface", obj) != 0) {
                    rc = -1;
                    break;
                }
            }
        }
    }

    if (rc == 0) {
        json_object *j_peers = json_object_object_get(j_data, "peers");
        if (j_peers && json_object_is_type(j_peers, json_type_array)) {
            int n = (int)json_object_array_length(j_peers);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_peers, i);
                if (!obj || !json_object_is_type(obj, json_type_object)) {
                    continue;
                }

                const char *section_type = NULL;
                json_object *j_type = json_object_object_get(obj, "_type");
                if (j_type && json_object_is_type(j_type, json_type_string)) {
                    const char *v = json_object_get_string(j_type);
                    if (v && is_wireguard_peer_section_type(v)) {
                        section_type = v;
                    }
                }

                char type_buf[64];
                if (!section_type) {
                    json_object *j_interface = json_object_object_get(obj, "interface");
                    const char *ifname = NULL;
                    if (j_interface && json_object_is_type(j_interface, json_type_string)) {
                        ifname = json_object_get_string(j_interface);
                    }
                    if (!ifname || ifname[0] == '\0') {
                        ifname = "wg0";
                    }

                    int nlen = snprintf(type_buf, sizeof(type_buf), "wireguard_%s", ifname);
                    if (nlen <= 0 || nlen >= (int)sizeof(type_buf)) {
                        rc = -1;
                        break;
                    }
                    section_type = type_buf;
                }

                if (add_network_section_from_json(ctx, pkg, section_type, obj) != 0) {
                    rc = -1;
                    break;
                }
            }
        }
    }

    if (rc == 0 && uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        rc = -1;
    }

    uci_close_package(ctx, pkg);

    if (rc != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wireguard_vpn_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to update wireguard config"));
        send_json_response(transport, j_err);
        return;
    }

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("set_wireguard_vpn_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "message", json_object_new_string("WireGuard VPN configuration updated"));
    send_json_response(transport, j_resp);
}

void handle_get_wireguard_vpn_status_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_resp = json_object_new_object();
    char *out = NULL;
    int exit_code = 0;

    int rc = run_command_capture("wg show 2>&1", &out, &exit_code);
    if (rc != 0) {
        json_object_object_add(j_resp, "type", json_object_new_string("get_wireguard_vpn_status_error"));
        json_object_object_add(j_resp, "error", json_object_new_string("Failed to execute wg show"));
        json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    if (exit_code != 0) {
        json_object_object_add(j_resp, "type", json_object_new_string("get_wireguard_vpn_status_error"));
        json_object_object_add(j_resp, "error", json_object_new_string("wg show returned non-zero exit code"));
        json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    json_object_object_add(j_resp, "type", json_object_new_string("get_wireguard_vpn_status_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "exit_code", json_object_new_int(exit_code));
    json_object_object_add(j_resp, "output", json_object_new_string(out ? out : ""));
    send_json_response(transport, j_resp);

    free(out);
}
