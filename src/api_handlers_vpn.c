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

    json_object *j_response = api_response_new("get_ipsec_vpn_response");
    json_object *j_data = api_response_get_data(j_response);
    json_object *j_proposals = json_object_new_array();
    json_object *j_tunnels = json_object_new_array();
    json_object *j_remotes = json_object_new_array();

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("ipsec", &ctx, &pkg) != 0) {
        api_response_set_error(j_response, 3001, "Failed to open ipsec config");
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

    api_response_set_success(j_response, "OK");
    send_json_response(transport, j_response);
}

void handle_set_ipsec_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_data = json_object_object_get(j_req, "data");
    if (!j_data || !json_object_is_type(j_data, json_type_object)) {
        json_object *j_err = api_response_new("set_ipsec_vpn_response");
        api_response_set_error(j_err, 1000, "Missing or invalid 'data' object");
        send_json_response(transport, j_err);
        return;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("ipsec", &ctx, &pkg) != 0) {
        json_object *j_err = api_response_new("set_ipsec_vpn_response");
        api_response_set_error(j_err, 3001, "Failed to open ipsec config");
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
        json_object *j_err = api_response_new("set_ipsec_vpn_response");
        api_response_set_error(j_err, 3000, "Failed to update ipsec config");
        send_json_response(transport, j_err);
        return;
    }

    json_object *j_resp = api_response_new("set_ipsec_vpn_response");
    api_response_set_success(j_resp, "IPsec VPN configuration updated");
    send_json_response(transport, j_resp);
}

void handle_get_ipsec_vpn_status_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_resp = api_response_new("get_ipsec_vpn_status_response");
    json_object *j_data = api_response_get_data(j_resp);
    char *out = NULL;
    int exit_code = 0;

    int rc = run_command_capture("swanctl -l 2>&1", &out, &exit_code);
    if (rc != 0) {
        api_response_set_error(j_resp, 3000, "Failed to execute swanctl -l");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    if (exit_code != 0) {
        api_response_set_error(j_resp, 3000, "swanctl -l returned non-zero exit code");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    api_response_set_success(j_resp, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
    }
    send_json_response(transport, j_resp);

    free(out);
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

static int set_named_section_options_from_json(struct uci_context *ctx, const char *package_name, const char *section_name, json_object *j_section, const char **skip_keys, int skip_count)
{
    if (!ctx || !package_name || !section_name || !j_section || !json_object_is_type(j_section, json_type_object)) {
        return -1;
    }

    json_object_object_foreach(j_section, key, val) {
        if (!key || !val) continue;

        int skip = 0;
        for (int i = 0; i < skip_count; i++) {
            if (strcmp(key, skip_keys[i]) == 0) { skip = 1; break; }
        }
        if (skip) continue;

        if (json_object_is_type(val, json_type_array)) {
            if (add_list_option_with_ctx(ctx, package_name, section_name, key, val) != 0) {
                return -1;
            }
            continue;
        }

        char value_buf[64];
        const char *value_str = NULL;
        if (json_value_to_uci_string(val, value_buf, sizeof(value_buf), &value_str) != 0 || !value_str) {
            continue;
        }

        if (uci_set_option_with_ctx(ctx, package_name, section_name, key, value_str) != 0) {
            return -1;
        }
    }

    return 0;
}

#define WG_IFACE_NAME "wg0"
#define WG_PEER_SECTION_TYPE "wireguard_" WG_IFACE_NAME

void handle_get_wireguard_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_response = api_response_new("get_wireguard_vpn_response");
    json_object *j_data = api_response_get_data(j_response);

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        api_response_set_error(j_response, 3001, "Failed to open network config");
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_interface = NULL;
    json_object *j_peers = json_object_new_array();

    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || !sec->e.name) continue;

        /* Match the wg0 interface section */
        if (strcmp(sec->type, "interface") == 0 && strcmp(sec->e.name, WG_IFACE_NAME) == 0) {
            const char *proto = uci_lookup_option_string(ctx, sec, "proto");
            if (!proto || strcmp(proto, "wireguard") != 0) continue;

            j_interface = json_object_new_object();
            struct uci_element *oe = NULL;
            uci_foreach_element(&sec->options, oe) {
                struct uci_option *opt = uci_to_option(oe);
                append_uci_option_to_json(opt, j_interface);
            }
            continue;
        }

        /* Match wireguard_wg0 peer sections */
        if (strcmp(sec->type, WG_PEER_SECTION_TYPE) == 0) {
            json_object *j_peer = json_object_new_object();
            json_object_object_add(j_peer, "_name", json_object_new_string(sec->e.name));

            struct uci_element *oe = NULL;
            uci_foreach_element(&sec->options, oe) {
                struct uci_option *opt = uci_to_option(oe);
                append_uci_option_to_json(opt, j_peer);
            }
            json_object_array_add(j_peers, j_peer);
        }
    }

    uci_close_package(ctx, pkg);

    if (j_interface) {
        json_object_object_add(j_data, "interface", j_interface);
    }
    json_object_object_add(j_data, "peers", j_peers);

    api_response_set_success(j_response, "OK");
    send_json_response(transport, j_response);
}

void handle_set_wireguard_vpn_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_data = json_object_object_get(j_req, "data");
    if (!j_data || !json_object_is_type(j_data, json_type_object)) {
        json_object *j_err = api_response_new("set_wireguard_vpn_response");
        api_response_set_error(j_err, 1000, "Missing or invalid 'data' object");
        send_json_response(transport, j_err);
        return;
    }

    json_object *j_interface = json_object_object_get(j_data, "interface");
    if (!j_interface || !json_object_is_type(j_interface, json_type_object)) {
        json_object *j_err = api_response_new("set_wireguard_vpn_response");
        api_response_set_error(j_err, 1000, "Missing or invalid 'interface' object");
        send_json_response(transport, j_err);
        return;
    }

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        json_object *j_err = api_response_new("set_wireguard_vpn_response");
        api_response_set_error(j_err, 3001, "Failed to open network config");
        send_json_response(transport, j_err);
        return;
    }

    int rc = 0;

    /* Step 0: If caller omits private_key, preserve the existing one from wg0 */
    char saved_private_key[128] = {0};
    int has_existing_privkey = 0;
    {
        /* Check if the incoming JSON has private_key */
        json_object *j_privkey = json_object_object_get(j_interface, "private_key");
        if (!j_privkey) {
            /* No private_key in request — check if one exists in current UCI config */
            struct uci_section *sec = uci_lookup_section(ctx, pkg, WG_IFACE_NAME);
            if (sec) {
                const char *existing_pk = uci_lookup_option_string(ctx, sec, "private_key");
                if (existing_pk && existing_pk[0]) {
                    strncpy(saved_private_key, existing_pk, sizeof(saved_private_key) - 1);
                    has_existing_privkey = 1;
                }
            }
        }
    }

    /* Step 1: Delete existing wg0 interface and all wireguard_wg0 peer sections */
    char old_sections[128][128];
    int old_count = 0;
    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || !sec->e.name || sec->e.name[0] == '\0') continue;

        int match = 0;
        if (strcmp(sec->type, "interface") == 0 && strcmp(sec->e.name, WG_IFACE_NAME) == 0) {
            const char *proto = uci_lookup_option_string(ctx, sec, "proto");
            if (proto && strcmp(proto, "wireguard") == 0) {
                match = 1;
            }
        } else if (strcmp(sec->type, WG_PEER_SECTION_TYPE) == 0) {
            match = 1;
        }

        if (!match) continue;
        if (old_count >= (int)(sizeof(old_sections) / sizeof(old_sections[0]))) break;
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

    /* Step 2: Create named interface section: config interface 'wg0' */
    if (rc == 0) {
        if (uci_add_named_section_with_ctx(ctx, "network", WG_IFACE_NAME, "interface") != 0) {
            rc = -1;
        }
    }

    if (rc == 0) {
        if (uci_set_option_with_ctx(ctx, "network", WG_IFACE_NAME, "proto", "wireguard") != 0) {
            rc = -1;
        }
    }

    /* Step 3: Set interface options from JSON (skip meta keys) */
    if (rc == 0) {
        static const char *iface_skip_keys[] = { "_name", "_type", "proto" };
        if (set_named_section_options_from_json(ctx, "network", WG_IFACE_NAME, j_interface,
                iface_skip_keys, (int)(sizeof(iface_skip_keys) / sizeof(iface_skip_keys[0]))) != 0) {
            rc = -1;
        }
    }

    /* Step 3b: Restore preserved private_key if caller didn't supply one */
    if (rc == 0 && has_existing_privkey) {
        if (uci_set_option_with_ctx(ctx, "network", WG_IFACE_NAME, "private_key", saved_private_key) != 0) {
            rc = -1;
        }
        memset(saved_private_key, 0, sizeof(saved_private_key));
    }

    /* Step 4: Create peer sections as anonymous wireguard_wg0 sections */
    if (rc == 0) {
        json_object *j_peers = json_object_object_get(j_data, "peers");
        if (j_peers && json_object_is_type(j_peers, json_type_array)) {
            int n = (int)json_object_array_length(j_peers);
            for (int i = 0; i < n; i++) {
                json_object *obj = json_object_array_get_idx(j_peers, i);
                if (!obj || !json_object_is_type(obj, json_type_object)) continue;

                struct uci_section *new_sec = NULL;
                if (uci_add_section(ctx, pkg, WG_PEER_SECTION_TYPE, &new_sec) != UCI_OK || !new_sec || !new_sec->e.name) {
                    rc = -1;
                    break;
                }

                static const char *peer_skip_keys[] = { "_name", "_type", "interface" };
                if (set_named_section_options_from_json(ctx, "network", new_sec->e.name, obj,
                        peer_skip_keys, (int)(sizeof(peer_skip_keys) / sizeof(peer_skip_keys[0]))) != 0) {
                    rc = -1;
                    break;
                }
            }
        }
    }

    /* Step 5: Save and commit */
    if (rc == 0 && uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        rc = -1;
    }

    uci_close_package(ctx, pkg);

    if (rc != 0) {
        json_object *j_err = api_response_new("set_wireguard_vpn_response");
        api_response_set_error(j_err, 3000, "Failed to update wireguard config");
        send_json_response(transport, j_err);
        return;
    }

    /* Step 6: Apply the configuration - bring up the WireGuard interface */
    char *cmd_out = NULL;
    int exit_code = 0;
    run_command_capture("ifdown " WG_IFACE_NAME " 2>&1; ifup " WG_IFACE_NAME " 2>&1", &cmd_out, &exit_code);
    free(cmd_out);

    json_object *j_resp = api_response_new("set_wireguard_vpn_response");
    json_object *j_resp_data = api_response_get_data(j_resp);
    if (exit_code != 0) {
        api_response_set_success(j_resp, "WireGuard VPN configuration updated but interface restart returned non-zero");
        if (j_resp_data) {
            json_object_object_add(j_resp_data, "ifup_exit_code", json_object_new_int(exit_code));
        }
    } else {
        api_response_set_success(j_resp, "WireGuard VPN configuration updated and applied");
    }
    send_json_response(transport, j_resp);
}

void handle_get_wireguard_vpn_status_request(json_object *j_req, api_transport_context_t *transport) {
    (void)j_req;

    json_object *j_resp = api_response_new("get_wireguard_vpn_status_response");
    json_object *j_data = api_response_get_data(j_resp);
    char *out = NULL;
    int exit_code = 0;

    int rc = run_command_capture("wg show 2>&1; echo '---ROUTES---'; ip route show dev " WG_IFACE_NAME " proto static 2>/dev/null", &out, &exit_code);
    if (rc != 0) {
        api_response_set_error(j_resp, 3000, "Failed to execute wg show");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    if (exit_code != 0) {
        api_response_set_error(j_resp, 3000, "wg show returned non-zero exit code");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
            json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
        }
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    api_response_set_success(j_resp, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(exit_code));
        json_object_object_add(j_data, "output", json_object_new_string(out ? out : ""));
    }
    send_json_response(transport, j_resp);

    free(out);
}

/* ------------------------------------------------------------------ */
/*  WireGuard key generation — keys stay on device, only pubkey sent  */
/* ------------------------------------------------------------------ */

void handle_generate_wireguard_keys_request(json_object *j_req, api_transport_context_t *transport)
{
    (void)j_req;

    json_object *j_resp = api_response_new("generate_wireguard_keys_response");
    json_object *j_data = api_response_get_data(j_resp);

    /* Step 1: Generate private key */
    char *privkey_out = NULL;
    int privkey_exit = 0;
    int rc = run_command_capture("wg genkey 2>/dev/null", &privkey_out, &privkey_exit);
    if (rc != 0 || privkey_exit != 0 || !privkey_out || privkey_out[0] == '\0') {
        api_response_set_error(j_resp, 3000, "Failed to generate WireGuard private key (is wireguard-tools installed?)");
        send_json_response(transport, j_resp);
        free(privkey_out);
        return;
    }

    /* Trim trailing newline */
    char *nl = strchr(privkey_out, '\n');
    if (nl) *nl = '\0';

    /* Step 2: Derive public key from private key */
    char pubkey_cmd[256];
    snprintf(pubkey_cmd, sizeof(pubkey_cmd), "echo '%s' | wg pubkey 2>/dev/null", privkey_out);
    char *pubkey_out = NULL;
    int pubkey_exit = 0;
    rc = run_command_capture(pubkey_cmd, &pubkey_out, &pubkey_exit);
    if (rc != 0 || pubkey_exit != 0 || !pubkey_out || pubkey_out[0] == '\0') {
        api_response_set_error(j_resp, 3000, "Failed to derive WireGuard public key");
        send_json_response(transport, j_resp);
        free(privkey_out);
        free(pubkey_out);
        return;
    }

    nl = strchr(pubkey_out, '\n');
    if (nl) *nl = '\0';

    /* Step 3: Write private key directly to UCI — never leaves the device */
    struct uci_context *ctx = uci_alloc_context();
    if (!ctx) {
        api_response_set_error(j_resp, 3000, "Failed to allocate UCI context");
        send_json_response(transport, j_resp);
        free(privkey_out);
        free(pubkey_out);
        return;
    }

    struct uci_package *pkg = NULL;
    int uci_rc = 0;

    if (uci_load(ctx, "network", &pkg) != UCI_OK || !pkg) {
        uci_rc = -1;
    }

    /* Ensure wg0 interface section exists */
    if (uci_rc == 0) {
        struct uci_section *sec = uci_lookup_section(ctx, pkg, WG_IFACE_NAME);
        if (!sec) {
            /* Create the section if it doesn't exist */
            if (uci_add_named_section_with_ctx(ctx, "network", WG_IFACE_NAME, "interface") != 0) {
                uci_rc = -1;
            }
            if (uci_rc == 0 && uci_set_option_with_ctx(ctx, "network", WG_IFACE_NAME, "proto", "wireguard") != 0) {
                uci_rc = -1;
            }
        }
    }

    /* Set private_key on the interface section */
    if (uci_rc == 0) {
        if (uci_set_option_with_ctx(ctx, "network", WG_IFACE_NAME, "private_key", privkey_out) != 0) {
            uci_rc = -1;
        }
    }

    /* Save and commit */
    if (uci_rc == 0 && uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        uci_rc = -1;
    }

    uci_close_package(ctx, pkg);
    uci_free_context(ctx);

    /* Wipe private key from memory immediately after UCI write */
    memset(privkey_out, 0, strlen(privkey_out));
    free(privkey_out);

    if (uci_rc != 0) {
        api_response_set_error(j_resp, 3000, "Failed to write private key to UCI config");
        free(pubkey_out);
        send_json_response(transport, j_resp);
        return;
    }

    /* Step 4: Return only the public key — private key never leaves the device */
    api_response_set_success(j_resp, "WireGuard keys generated. Private key stored in UCI; only public key returned.");
    if (j_data) {
        json_object_object_add(j_data, "public_key", json_object_new_string(pubkey_out));
        json_object_object_add(j_data, "interface", json_object_new_string(WG_IFACE_NAME));
    }
    send_json_response(transport, j_resp);

    free(pubkey_out);
}

/* ------------------------------------------------------------------ */
/*  VPN Route management — ip route based policy routing for wg0      */
/* ------------------------------------------------------------------ */

/**
 * Validate a CIDR destination string (basic check).
 * Accepts forms like "8.8.8.8/32", "10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1".
 * Rejects empty, whitespace-only, or strings containing shell-dangerous chars.
 */
static int is_valid_route_destination(const char *dest)
{
    if (!dest || dest[0] == '\0') return 0;
    for (const char *p = dest; *p; p++) {
        /* Allow digits, dots, colons (IPv6), slash, letters (a-f for hex) */
        if ((*p >= '0' && *p <= '9') || *p == '.' || *p == '/' ||
            *p == ':' || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            continue;
        }
        return 0;
    }
    /* Must contain a slash for CIDR */
    return strchr(dest, '/') != NULL;
}

void handle_get_vpn_routes_request(json_object *j_req, api_transport_context_t *transport)
{
    (void)j_req;

    json_object *j_resp = api_response_new("get_vpn_routes_response");
    json_object *j_data = api_response_get_data(j_resp);

    /* Retrieve all proto static routes on wg0 */
    char *out = NULL;
    int exit_code = 0;
    int rc = run_command_capture("ip -j route show dev " WG_IFACE_NAME " proto static 2>/dev/null", &out, &exit_code);

    if (rc != 0 || exit_code != 0) {
        /* Non-fatal: interface may not exist yet */
        api_response_set_success(j_resp, "OK");
        if (j_data) {
            json_object_object_add(j_data, "interface", json_object_new_string(WG_IFACE_NAME));
            json_object_object_add(j_data, "routes", json_object_new_array());
            json_object_object_add(j_data, "tunnel_up", json_object_new_boolean(0));
        }
        send_json_response(transport, j_resp);
        free(out);
        return;
    }

    /* Check if wg0 is up */
    char *wg_out = NULL;
    int wg_exit = 0;
    run_command_capture("ip link show " WG_IFACE_NAME " 2>/dev/null | grep -q 'state UP'", &wg_out, &wg_exit);
    free(wg_out);

    /* Parse ip -j output (JSON array) */
    json_object *j_routes_raw = json_tokener_parse(out ? out : "[]");
    json_object *j_routes = json_object_new_array();

    if (j_routes_raw && json_object_is_type(j_routes_raw, json_type_array)) {
        int n = (int)json_object_array_length(j_routes_raw);
        for (int i = 0; i < n; i++) {
            json_object *entry = json_object_array_get_idx(j_routes_raw, i);
            if (!entry) continue;
            json_object *j_dst = NULL;
            if (json_object_object_get_ex(entry, "dst", &j_dst) && j_dst) {
                json_object *route = json_object_new_object();
                json_object_object_add(route, "destination",
                    json_object_new_string(json_object_get_string(j_dst)));
                json_object_array_add(j_routes, route);
            }
        }
    }
    if (j_routes_raw) json_object_put(j_routes_raw);

    api_response_set_success(j_resp, "OK");
    if (j_data) {
        json_object_object_add(j_data, "interface", json_object_new_string(WG_IFACE_NAME));
        json_object_object_add(j_data, "routes", j_routes);
        json_object_object_add(j_data, "tunnel_up", json_object_new_boolean(wg_exit == 0 ? 1 : 0));
    }
    send_json_response(transport, j_resp);
    free(out);
}

void handle_set_vpn_routes_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_data_in = json_object_object_get(j_req, "data");
    if (!j_data_in || !json_object_is_type(j_data_in, json_type_object)) {
        json_object *j_err = api_response_new("set_vpn_routes_response");
        api_response_set_error(j_err, 1000, "Missing or invalid 'data' object");
        send_json_response(transport, j_err);
        return;
    }

    /* Extract interface (default "wg0") */
    json_object *j_iface = json_object_object_get(j_data_in, "interface");
    const char *iface = (j_iface && json_object_is_type(j_iface, json_type_string))
                        ? json_object_get_string(j_iface) : WG_IFACE_NAME;

    /* Extract mode: "selective" or "full_tunnel" */
    json_object *j_mode = json_object_object_get(j_data_in, "mode");
    const char *mode = (j_mode && json_object_is_type(j_mode, json_type_string))
                       ? json_object_get_string(j_mode) : "selective";

    int is_full_tunnel = (strcmp(mode, "full_tunnel") == 0);

    /* Step 1: Flush existing proto static routes on the interface */
    char cmd[512];
    char *cmd_out = NULL;
    int cmd_exit = 0;

    snprintf(cmd, sizeof(cmd), "ip route flush dev %s proto static 2>&1", iface);
    run_command_capture(cmd, &cmd_out, &cmd_exit);
    free(cmd_out); cmd_out = NULL;

    int added = 0;
    int failed = 0;

    if (is_full_tunnel) {
        /* Full tunnel: exclude VPS IP(s) first, then add 0.0.0.0/1 + 128.0.0.0/1 */
        json_object *j_exclude = json_object_object_get(j_data_in, "exclude_ips");
        if (j_exclude && json_object_is_type(j_exclude, json_type_array)) {
            int n = (int)json_object_array_length(j_exclude);
            for (int i = 0; i < n; i++) {
                json_object *item = json_object_array_get_idx(j_exclude, i);
                if (!item) continue;
                const char *excl_ip = json_object_get_string(item);
                if (!excl_ip || excl_ip[0] == '\0') continue;

                /* Validate — must be IP/CIDR only */
                char excl_dest[128];
                /* If no CIDR suffix, append /32 */
                if (!strchr(excl_ip, '/')) {
                    snprintf(excl_dest, sizeof(excl_dest), "%s/32", excl_ip);
                } else {
                    snprintf(excl_dest, sizeof(excl_dest), "%s", excl_ip);
                }

                if (!is_valid_route_destination(excl_dest)) continue;

                /* Get current default gateway to route excluded IPs via original path */
                char *gw_out = NULL;
                int gw_exit = 0;
                run_command_capture("ip route show default 2>/dev/null | head -1 | awk '{for(i=1;i<=NF;i++) if($i==\"via\") print $(i+1)}'", &gw_out, &gw_exit);
                if (!gw_out || gw_out[0] == '\0') {
                    free(gw_out);
                    json_object *j_err = api_response_new("set_vpn_routes_response");
                    api_response_set_error(j_err, 4000,
                        "Cannot detect default gateway; exclude_ips would cause routing loop. "
                        "Ensure a default route exists before enabling full tunnel mode.");
                    send_json_response(transport, j_err);
                    return;
                }
                if (gw_out[0] != '\0') {
                    /* Trim trailing newline */
                    char *nl = strchr(gw_out, '\n');
                    if (nl) *nl = '\0';

                    snprintf(cmd, sizeof(cmd), "ip route add %s via %s proto static 2>&1",
                             excl_dest, gw_out);
                    run_command_capture(cmd, &cmd_out, &cmd_exit);
                    free(cmd_out); cmd_out = NULL;
                }
                free(gw_out);
            }
        }

        /* Add the two halves that cover all IPv4 */
        snprintf(cmd, sizeof(cmd), "ip route add 0.0.0.0/1 dev %s proto static 2>&1", iface);
        run_command_capture(cmd, &cmd_out, &cmd_exit);
        free(cmd_out); cmd_out = NULL;
        if (cmd_exit == 0) added++; else failed++;

        snprintf(cmd, sizeof(cmd), "ip route add 128.0.0.0/1 dev %s proto static 2>&1", iface);
        run_command_capture(cmd, &cmd_out, &cmd_exit);
        free(cmd_out); cmd_out = NULL;
        if (cmd_exit == 0) added++; else failed++;

    } else {
        /* Selective mode: add each route individually */
        json_object *j_routes = json_object_object_get(j_data_in, "routes");
        if (!j_routes || !json_object_is_type(j_routes, json_type_array)) {
            json_object *j_err = api_response_new("set_vpn_routes_response");
            api_response_set_error(j_err, 1000, "Missing or invalid 'routes' array in selective mode");
            send_json_response(transport, j_err);
            return;
        }

        int n = (int)json_object_array_length(j_routes);
        for (int i = 0; i < n; i++) {
            json_object *route_obj = json_object_array_get_idx(j_routes, i);
            if (!route_obj) continue;

            const char *dest = NULL;

            /* Accept both plain strings ["1.2.3.0/24"] and objects [{"destination":"1.2.3.0/24"}] */
            if (json_object_is_type(route_obj, json_type_string)) {
                dest = json_object_get_string(route_obj);
            } else if (json_object_is_type(route_obj, json_type_object)) {
                json_object *j_dest = json_object_object_get(route_obj, "destination");
                if (j_dest && json_object_is_type(j_dest, json_type_string)) {
                    dest = json_object_get_string(j_dest);
                }
            }

            if (!dest || !is_valid_route_destination(dest)) {
                failed++;
                continue;
            }

            snprintf(cmd, sizeof(cmd), "ip route add %s dev %s proto static 2>&1", dest, iface);
            run_command_capture(cmd, &cmd_out, &cmd_exit);
            free(cmd_out); cmd_out = NULL;

            if (cmd_exit == 0) {
                added++;
            } else {
                failed++;
            }
        }
    }

    json_object *j_resp = api_response_new("set_vpn_routes_response");
    json_object *j_data = api_response_get_data(j_resp);
    if (failed > 0) {
        api_response_set_success(j_resp, "VPN routes applied with some failures");
    } else {
        api_response_set_success(j_resp, "VPN routes applied");
    }
    if (j_data) {
        json_object_object_add(j_data, "interface", json_object_new_string(iface));
        json_object_object_add(j_data, "mode", json_object_new_string(mode));
        json_object_object_add(j_data, "added", json_object_new_int(added));
        json_object_object_add(j_data, "failed", json_object_new_int(failed));
    }
    send_json_response(transport, j_resp);
}

void handle_delete_vpn_routes_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_data_in = json_object_object_get(j_req, "data");
    if (!j_data_in || !json_object_is_type(j_data_in, json_type_object)) {
        json_object *j_err = api_response_new("delete_vpn_routes_response");
        api_response_set_error(j_err, 1000, "Missing or invalid 'data' object");
        send_json_response(transport, j_err);
        return;
    }

    json_object *j_iface = json_object_object_get(j_data_in, "interface");
    const char *iface = (j_iface && json_object_is_type(j_iface, json_type_string))
                        ? json_object_get_string(j_iface) : WG_IFACE_NAME;

    /* Check if flush_all is requested */
    json_object *j_flush = json_object_object_get(j_data_in, "flush_all");
    int flush_all = (j_flush && json_object_get_boolean(j_flush));

    char cmd[512];
    char *cmd_out = NULL;
    int cmd_exit = 0;
    int deleted = 0;
    int failed = 0;

    if (flush_all) {
        snprintf(cmd, sizeof(cmd), "ip route flush dev %s proto static 2>&1", iface);
        run_command_capture(cmd, &cmd_out, &cmd_exit);
        free(cmd_out); cmd_out = NULL;
        if (cmd_exit == 0) {
            deleted = -1; /* indicates flush-all */
        } else {
            failed = 1;
        }
    } else {
        json_object *j_routes = json_object_object_get(j_data_in, "routes");
        if (!j_routes || !json_object_is_type(j_routes, json_type_array)) {
            json_object *j_err = api_response_new("delete_vpn_routes_response");
            api_response_set_error(j_err, 1000, "Missing 'routes' array or 'flush_all' flag");
            send_json_response(transport, j_err);
            return;
        }

        int n = (int)json_object_array_length(j_routes);
        for (int i = 0; i < n; i++) {
            json_object *item = json_object_array_get_idx(j_routes, i);
            const char *dest = NULL;

            if (json_object_is_type(item, json_type_string)) {
                dest = json_object_get_string(item);
            } else if (json_object_is_type(item, json_type_object)) {
                json_object *j_dest = json_object_object_get(item, "destination");
                if (j_dest && json_object_is_type(j_dest, json_type_string)) {
                    dest = json_object_get_string(j_dest);
                }
            }

            if (!dest || !is_valid_route_destination(dest)) {
                failed++;
                continue;
            }

            snprintf(cmd, sizeof(cmd), "ip route del %s dev %s proto static 2>&1", dest, iface);
            run_command_capture(cmd, &cmd_out, &cmd_exit);
            free(cmd_out); cmd_out = NULL;

            if (cmd_exit == 0) {
                deleted++;
            } else {
                failed++;
            }
        }
    }

    json_object *j_resp = api_response_new("delete_vpn_routes_response");
    json_object *j_data = api_response_get_data(j_resp);
    if (failed > 0) {
        api_response_set_success(j_resp, "VPN routes deletion completed with some failures");
    } else {
        api_response_set_success(j_resp, flush_all ? "All VPN routes flushed" : "VPN routes deleted");
    }
    if (j_data) {
        json_object_object_add(j_data, "interface", json_object_new_string(iface));
        json_object_object_add(j_data, "deleted", json_object_new_int(deleted));
        json_object_object_add(j_data, "failed", json_object_new_int(failed));
        json_object_object_add(j_data, "flush_all", json_object_new_boolean(flush_all));
    }
    send_json_response(transport, j_resp);
}
