// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"
#include "debug.h"
#include "conf.h"
#include "safe.h"
#include "uci_helper.h"
#include <uci.h>

static int set_uci_config(const char *config_path, const char *value) {
    if (!config_path || !value) {
        debug(LOG_ERR, "Invalid parameters for UCI config");
        return -1;
    }

    if (uci_set_config_path_staged(config_path, value) != 0) {
        debug(LOG_ERR, "Failed to set UCI option: %s", config_path);
        return -1;
    }

    return 0;
}

/**
 * @brief Helper function to commit UCI changes
 */
static int commit_uci_changes(void) {
    if (uci_commit_package_by_name("wireless") != 0) {
        debug(LOG_ERR, "Failed to commit UCI changes for wireless");
        return -1;
    }
    
    return 0;
}

/* Helper: run shell command and capture stdout into allocated string. */

void handle_get_wifi_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data = json_object_new_object();
    
    debug(LOG_INFO, "Get WiFi info request received");
    
    // Storage for device and interface information
    struct wifi_device_info devices[8];
    struct wifi_interface_info interfaces[32];
    int device_count = 0;
    int interface_count = 0;
    
    // Initialize storage
    memset(devices, 0, sizeof(devices));
    memset(interfaces, 0, sizeof(interfaces));

    struct uci_context *w_ctx = NULL;
    struct uci_package *w_pkg = NULL;
    if (uci_open_package("wireless", &w_ctx, &w_pkg) != 0) {
        debug(LOG_ERR, "Failed to open UCI package: wireless");

        json_object *j_type = json_object_new_string("get_wifi_info_error");
        json_object *j_error = json_object_new_string("Failed to read wireless config");
        json_object_object_add(j_response, "type", j_type);
        json_object_object_add(j_response, "error", j_error);

        send_json_response(transport, j_response);
        return;
    }

    struct uci_element *e = NULL;
    uci_foreach_element(&w_pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->e.name || !sec->type) continue;

        if (strcmp(sec->type, "wifi-device") == 0) {
            int idx = -1;
            for (int i = 0; i < device_count; i++) {
                if (strcmp(devices[i].device_name, sec->e.name) == 0) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1 && device_count < 8) {
                idx = device_count++;
                strncpy(devices[idx].device_name, sec->e.name, sizeof(devices[idx].device_name) - 1);
                devices[idx].device_name[sizeof(devices[idx].device_name) - 1] = '\0';
            }
            if (idx < 0) continue;

            const char *type = uci_lookup_option_string(w_ctx, sec, "type");
            const char *path = uci_lookup_option_string(w_ctx, sec, "path");
            const char *band = uci_lookup_option_string(w_ctx, sec, "band");
            const char *channel = uci_lookup_option_string(w_ctx, sec, "channel");
            const char *htmode = uci_lookup_option_string(w_ctx, sec, "htmode");
            const char *cell_density = uci_lookup_option_string(w_ctx, sec, "cell_density");

            if (type) {
                strncpy(devices[idx].type, type, sizeof(devices[idx].type) - 1);
                devices[idx].type[sizeof(devices[idx].type) - 1] = '\0';
            }
            if (path) {
                strncpy(devices[idx].path, path, sizeof(devices[idx].path) - 1);
                devices[idx].path[sizeof(devices[idx].path) - 1] = '\0';
            }
            if (band) {
                strncpy(devices[idx].band, band, sizeof(devices[idx].band) - 1);
                devices[idx].band[sizeof(devices[idx].band) - 1] = '\0';
            }
            if (channel) {
                devices[idx].channel = atoi(channel);
            }
            if (htmode) {
                strncpy(devices[idx].htmode, htmode, sizeof(devices[idx].htmode) - 1);
                devices[idx].htmode[sizeof(devices[idx].htmode) - 1] = '\0';
            }
            if (cell_density) {
                devices[idx].cell_density = atoi(cell_density);
            }
            continue;
        }

        if (strcmp(sec->type, "wifi-iface") == 0) {
            int idx = -1;
            for (int i = 0; i < interface_count; i++) {
                if (strcmp(interfaces[i].interface_name, sec->e.name) == 0) {
                    idx = i;
                    break;
                }
            }
            if (idx == -1 && interface_count < 32) {
                idx = interface_count++;
                strncpy(interfaces[idx].interface_name, sec->e.name, sizeof(interfaces[idx].interface_name) - 1);
                interfaces[idx].interface_name[sizeof(interfaces[idx].interface_name) - 1] = '\0';
            }
            if (idx < 0) continue;

            const char *device = uci_lookup_option_string(w_ctx, sec, "device");
            const char *mode = uci_lookup_option_string(w_ctx, sec, "mode");
            const char *ssid = uci_lookup_option_string(w_ctx, sec, "ssid");
            const char *key = uci_lookup_option_string(w_ctx, sec, "key");
            const char *encryption = uci_lookup_option_string(w_ctx, sec, "encryption");
            const char *network = uci_lookup_option_string(w_ctx, sec, "network");
            const char *mesh_id = uci_lookup_option_string(w_ctx, sec, "mesh_id");
            const char *disabled = uci_lookup_option_string(w_ctx, sec, "disabled");

            if (device) {
                strncpy(interfaces[idx].device, device, sizeof(interfaces[idx].device) - 1);
                interfaces[idx].device[sizeof(interfaces[idx].device) - 1] = '\0';
            }
            if (mode) {
                strncpy(interfaces[idx].mode, mode, sizeof(interfaces[idx].mode) - 1);
                interfaces[idx].mode[sizeof(interfaces[idx].mode) - 1] = '\0';
            }
            if (ssid) {
                strncpy(interfaces[idx].ssid, ssid, sizeof(interfaces[idx].ssid) - 1);
                interfaces[idx].ssid[sizeof(interfaces[idx].ssid) - 1] = '\0';
            }
            if (key) {
                strncpy(interfaces[idx].key, key, sizeof(interfaces[idx].key) - 1);
                interfaces[idx].key[sizeof(interfaces[idx].key) - 1] = '\0';
            }
            if (encryption) {
                strncpy(interfaces[idx].encryption, encryption, sizeof(interfaces[idx].encryption) - 1);
                interfaces[idx].encryption[sizeof(interfaces[idx].encryption) - 1] = '\0';
            }
            if (network) {
                strncpy(interfaces[idx].network, network, sizeof(interfaces[idx].network) - 1);
                interfaces[idx].network[sizeof(interfaces[idx].network) - 1] = '\0';
            }
            if (mesh_id) {
                strncpy(interfaces[idx].mesh_id, mesh_id, sizeof(interfaces[idx].mesh_id) - 1);
                interfaces[idx].mesh_id[sizeof(interfaces[idx].mesh_id) - 1] = '\0';
            }
            if (disabled) {
                interfaces[idx].disabled = atoi(disabled);
            }
        }
    }

    uci_close_package(w_ctx, w_pkg);

    // Build JSON response for each radio device
    for (int d = 0; d < device_count; d++) {
        json_object *j_radio = json_object_new_object();
        
        // Add device information
        json_object_object_add(j_radio, "type", json_object_new_string(devices[d].type));
        json_object_object_add(j_radio, "path", json_object_new_string(devices[d].path));
        json_object_object_add(j_radio, "band", json_object_new_string(devices[d].band));
        json_object_object_add(j_radio, "channel", json_object_new_int(devices[d].channel));
        json_object_object_add(j_radio, "htmode", json_object_new_string(devices[d].htmode));
        json_object_object_add(j_radio, "cell_density", json_object_new_int(devices[d].cell_density));
        
        // Add interfaces for this radio
        json_object *j_interfaces = json_object_new_array();
        for (int i = 0; i < interface_count; i++) {
            if (strcmp(interfaces[i].device, devices[d].device_name) == 0) {
                json_object *j_iface = json_object_new_object();
                json_object_object_add(j_iface, "interface_name", json_object_new_string(interfaces[i].interface_name));
                json_object_object_add(j_iface, "mode", json_object_new_string(interfaces[i].mode));
                json_object_object_add(j_iface, "network", json_object_new_string(interfaces[i].network));
                json_object_object_add(j_iface, "encryption", json_object_new_string(interfaces[i].encryption));
                json_object_object_add(j_iface, "disabled", json_object_new_boolean(interfaces[i].disabled));
                
                if (strlen(interfaces[i].ssid) > 0) {
                    json_object_object_add(j_iface, "ssid", json_object_new_string(interfaces[i].ssid));
                }
                if (strlen(interfaces[i].key) > 0) {
                    json_object_object_add(j_iface, "key", json_object_new_string(interfaces[i].key));
                }
                if (strlen(interfaces[i].mesh_id) > 0) {
                    json_object_object_add(j_iface, "mesh_id", json_object_new_string(interfaces[i].mesh_id));
                }
                
                json_object_array_add(j_interfaces, j_iface);
            }
        }
        json_object_object_add(j_radio, "interfaces", j_interfaces);
        
        // Add radio to data
        json_object_object_add(j_data, devices[d].device_name, j_radio);
    }

    // Get available network interfaces list for WiFi configuration (only static proto)
    json_object *j_networks = json_object_new_array();
    
    struct uci_context *n_ctx = NULL;
    struct uci_package *n_pkg = NULL;
    if (uci_open_package("network", &n_ctx, &n_pkg) == 0) {
        struct uci_element *ne = NULL;
        uci_foreach_element(&n_pkg->sections, ne) {
            struct uci_section *sec = uci_to_section(ne);
            if (!sec || !sec->e.name) continue;

            const char *interface_name = sec->e.name;
            if (strcmp(interface_name, "loopback") == 0 || strcmp(interface_name, "globals") == 0) {
                continue;
            }

            const char *proto = uci_lookup_option_string(n_ctx, sec, "proto");
            if (!proto || strcmp(proto, "static") != 0) {
                continue;
            }

            int found = 0;
            int array_len = json_object_array_length(j_networks);
            for (int i = 0; i < array_len; i++) {
                json_object *existing = json_object_array_get_idx(j_networks, i);
                if (existing) {
                    const char *existing_name = json_object_get_string(existing);
                    if (existing_name && strcmp(existing_name, interface_name) == 0) {
                        found = 1;
                        break;
                    }
                }
            }

            if (!found) {
                json_object_array_add(j_networks, json_object_new_string(interface_name));
            }
        }
        uci_close_package(n_ctx, n_pkg);
    }
    json_object_object_add(j_data, "available_networks", j_networks);

    // Build success response
    json_object *j_type = json_object_new_string("get_wifi_info_response");
    json_object_object_add(j_response, "type", j_type);
    json_object_object_add(j_response, "data", j_data);
    /* Describe fields for AI/clients */
    json_object *j_fd = json_object_new_object();

    /* radio_device describes the structure for each radio key (e.g., radio0, radio1) */
    json_object *j_radio_desc = json_object_new_object();
    json_object_object_add(j_radio_desc, "type", json_object_new_string("Radio device driver/type string (e.g., mac80211)"));
    json_object_object_add(j_radio_desc, "path", json_object_new_string("Kernel/platform path for the radio device (string)"));
    json_object_object_add(j_radio_desc, "band", json_object_new_string("Radio band (string) e.g., 2g, 5g"));
    json_object_object_add(j_radio_desc, "channel", json_object_new_string("Operating channel (int)"));
    json_object_object_add(j_radio_desc, "htmode", json_object_new_string("HT mode (string), e.g., HT20, HE80"));
    json_object_object_add(j_radio_desc, "cell_density", json_object_new_string("Cell density (int)"));

    /* Interface object description */
    json_object *j_iface_desc = json_object_new_object();
    json_object_object_add(j_iface_desc, "interface_name", json_object_new_string("Logical interface name (string)"));
    json_object_object_add(j_iface_desc, "mode", json_object_new_string("Interface mode (string) e.g., ap, sta"));
    json_object_object_add(j_iface_desc, "network", json_object_new_string("Associated network name (string)"));
    json_object_object_add(j_iface_desc, "encryption", json_object_new_string("Encryption type (string) e.g., psk2"));
    json_object_object_add(j_iface_desc, "disabled", json_object_new_string("Disabled flag (boolean)"));
    json_object_object_add(j_iface_desc, "ssid", json_object_new_string("SSID string (if configured)"));
    json_object_object_add(j_iface_desc, "key", json_object_new_string("Pre-shared key/passphrase (if present)"));
    json_object_object_add(j_iface_desc, "mesh_id", json_object_new_string("Mesh identifier string (if present)"));

    json_object_object_add(j_radio_desc, "interfaces", j_iface_desc);

    json_object_object_add(j_fd, "radio_device", j_radio_desc);
    json_object_object_add(j_fd, "available_networks", json_object_new_string("Array of available static network interface names (array of strings)"));

    json_object_object_add(j_response, "field_descriptions", j_fd);

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_DEBUG, "Sending complete Wi-Fi info response: %s", response_str);
    send_json_response(transport, j_response);
    
    debug(LOG_INFO, "WiFi info sent successfully");
}

/* VPN handlers moved to api_handlers_vpn.c */

static char *select_radio_by_band(const char *band_pref);

void handle_scan_wifi_request(json_object *j_req, api_transport_context_t *transport) {
    const char *band = "2g";
    json_object *j_band = json_object_object_get(j_req, "band");
    if (j_band && json_object_is_type(j_band, json_type_string)) {
        const char *b = json_object_get_string(j_band);
        if (b && (strcmp(b, "5g") == 0 || strcmp(b, "2g") == 0)) band = b;
    }

    json_object *j_response = json_object_new_object();
    json_object *j_networks = json_object_new_array();

    /* Use ubus to perform scan and return JSON results.
     * Select radio dynamically via select_radio_by_band(); fall back to
     * legacy names when not available.
     */
    char *device = select_radio_by_band(band);
    if (!device) {
        /* Fallback should map 5g->radio1 and 2g->radio0 on common OpenWrt layouts. */
        device = strdup(strcmp(band, "5g") == 0 ? "radio1" : "radio0");
    }
    if (!device) {
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to select scan device"));
        send_json_response(transport, j_response);
        return;
    }
    debug(LOG_INFO, "scan_wifi: requested band=%s, selected device=%s", band, device ? device : "(null)");
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ubus call iwinfo scan '{\"device\":\"%s\"}' 2>/dev/null", device);

    FILE *sfp = popen(cmd, "r");
    if (!sfp) {
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to invoke ubus iwinfo scan"));
        if (device) free(device);
        send_json_response(transport, j_response);
        return;
    }

    // Read entire output into buffer
    size_t out_len = 0;
    size_t buf_size = 4096;
    char *out = malloc(buf_size);
    if (!out) {
        pclose(sfp);
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Memory allocation failed"));
        send_json_response(transport, j_response);
        return;
    }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), sfp) != NULL) {
        size_t chunk_len = strlen(chunk);
        if (out_len + chunk_len + 1 > buf_size) {
            buf_size = (out_len + chunk_len + 1) * 2;
            char *n = realloc(out, buf_size);
            if (!n) break;
            out = n;
        }
        memcpy(out + out_len, chunk, chunk_len);
        out_len += chunk_len;
        out[out_len] = '\0';
    }
    pclose(sfp);

    if (out_len == 0) {
        free(out);
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_response"));
        json_object_object_add(j_response, "networks", j_networks);
        json_object *j_fd_empty = json_object_new_object();
        json_object_object_add(j_fd_empty, "networks", json_object_new_string("Array of network objects found by scan"));
        json_object_object_add(j_response, "field_descriptions", j_fd_empty);
        send_json_response(transport, j_response);
        return;
    }

    // Parse JSON output from ubus
    json_object *j_scan = NULL;
    j_scan = json_tokener_parse(out);
    free(out);
    if (!j_scan) {
        if (device) free(device);
        json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Failed to parse ubus iwinfo JSON output"));
        send_json_response(transport, j_response);
        return;
    }

    json_object *j_results = NULL;
    if (json_object_object_get_ex(j_scan, "results", &j_results) && json_object_is_type(j_results, json_type_array)) {
        size_t n = json_object_array_length(j_results);
        for (size_t i = 0; i < n; i++) {
            json_object *entry = json_object_array_get_idx(j_results, i);
            if (!entry || !json_object_is_type(entry, json_type_object)) continue;

            json_object *j_net = json_object_new_object();
            json_object *tmp = NULL;

            if (json_object_object_get_ex(entry, "ssid", &tmp) && json_object_is_type(tmp, json_type_string))
                json_object_object_add(j_net, "ssid", json_object_new_string(json_object_get_string(tmp)));

            if (json_object_object_get_ex(entry, "bssid", &tmp) && json_object_is_type(tmp, json_type_string))
                json_object_object_add(j_net, "bssid", json_object_new_string(json_object_get_string(tmp)));

            if (json_object_object_get_ex(entry, "band", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "band", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "channel", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "channel", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "mhz", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "mhz", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "signal", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "signal_dbm", json_object_new_int(json_object_get_int(tmp)));

            if (json_object_object_get_ex(entry, "quality", &tmp) && json_object_is_type(tmp, json_type_int))
                json_object_object_add(j_net, "quality", json_object_new_int(json_object_get_int(tmp)));

            // encryption object
            json_object *j_enc = NULL;
            if (json_object_object_get_ex(entry, "encryption", &j_enc) && json_object_is_type(j_enc, json_type_object)) {
                json_object *j_enc_out = json_object_new_object();
                json_object *jen = NULL;
                if (json_object_object_get_ex(j_enc, "enabled", &jen) && json_object_is_type(jen, json_type_boolean))
                    json_object_object_add(j_enc_out, "enabled", json_object_new_boolean(json_object_get_boolean(jen)));

                // wpa array
                if (json_object_object_get_ex(j_enc, "wpa", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "wpa", json_object_get(jen));
                }

                if (json_object_object_get_ex(j_enc, "authentication", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "authentication", json_object_get(jen));
                }

                if (json_object_object_get_ex(j_enc, "ciphers", &jen) && json_object_is_type(jen, json_type_array)) {
                    json_object_object_add(j_enc_out, "ciphers", json_object_get(jen));
                }

                json_object_object_add(j_net, "encryption", j_enc_out);
            }

            json_object_array_add(j_networks, j_net);
        }
    }

    json_object_put(j_scan);

    json_object_object_add(j_response, "type", json_object_new_string("scan_wifi_response"));
    json_object_object_add(j_response, "networks", j_networks);
    /* Describe fields */
    json_object *j_fd = json_object_new_object();
    json_object_object_add(j_fd, "networks", json_object_new_string("Array of network objects found by scan"));
    json_object_object_add(j_response, "field_descriptions", j_fd);
    send_json_response(transport, j_response);
    if (device) free(device);
}

/*
 * Production-ready implementation to configure a Wi-Fi client (STA) that
 * attaches to `wwan` (upstream via DHCP). This function performs the
 * following, safely and deterministically:
 * - ensures a `wwan` interface exists in /etc/config/network
 * - selects a radio dynamically via `ubus` (falls back to sensible default)
 * - removes any existing `mode='sta'` wifi-iface sections
 * - atomically creates a new wifi-iface section and sets properties
 * - optionally triggers a non-blocking `wifi reload`
 * - validates that `wwan` obtains an IP address
 *
 * Request JSON parameters (required):
 * - "ssid": SSID to join
 * Optional:
 * - "bssid": BSSID (MAC) of target AP
 * - "encryption": encryption type (e.g., psk2, sae, none)
 * - "key": PSK/password if required by encryption
 * - "band": "2g" or "5g" (preferred band; best-effort)
 * - "apply": boolean (default true) - whether to trigger wifi reload/apply
 */

static int ensure_wwan_interface(void) {
    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    if (uci_open_package("network", &ctx, &pkg) != 0) {
        return -1;
    }

    int exists = 0;
    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->e.name) continue;
        if (strcmp(sec->e.name, "wwan") == 0) {
            exists = 1;
            break;
        }
    }

    if (!exists) {
        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));
        char expr[] = "network.wwan=interface";
        if (uci_lookup_ptr(ctx, &ptr, expr, true) != UCI_OK || uci_set(ctx, &ptr) != UCI_OK) {
            uci_close_package(ctx, pkg);
            return -1;
        }
    }

    if (uci_set_option_with_ctx(ctx, "network", "wwan", "proto", "dhcp") != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    if (uci_save_commit_package_with_ctx(ctx, &pkg) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    uci_close_package(ctx, pkg);
    return 0;
}

static char *select_radio_by_band(const char *band_pref) {
    debug(LOG_DEBUG, "select_radio_by_band: start, band_pref=%s", band_pref ? band_pref : "(null)");
    // Try ubus call network.wireless status
    FILE *fp = popen("ubus call network.wireless status 2>/dev/null", "r");
    if (!fp) return NULL;
    size_t buf_size = 4096, len = 0; char *out = malloc(buf_size);
    if (!out) { pclose(fp); return NULL; }
    out[0] = '\0';
    char chunk[1024];
    while (fgets(chunk, sizeof(chunk), fp) != NULL) {
        size_t cl = strlen(chunk);
        if (len + cl + 1 > buf_size) {
            buf_size = (len + cl + 1) * 2;
            char *n = realloc(out, buf_size);
            if (!n) break;
            out = n;
        }
        memcpy(out + len, chunk, cl);
        len += cl; out[len] = '\0';
    }
    pclose(fp);
    if (len == 0) { free(out); return NULL; }

    json_object *j = json_tokener_parse(out);
    free(out);
    if (!j) return NULL;

    /* Only use strong signals to infer band:
     * 1) explicit `band`, 2) numeric `channel`, 3) `hwmode`.
     * Do NOT use broad htmode substring matching (e.g. VHT80 contains "HT"),
     * which can misclassify 5g radios as 2g.
     */
    json_object_object_foreach(j, key, val) {
        if (!json_object_is_type(val, json_type_object)) continue;

        json_object *j_config = NULL;
        if (json_object_object_get_ex(val, "config", &j_config) && json_object_is_type(j_config, json_type_object)) {
            // Check explicit band string first
            json_object *j_band = NULL;
            if (json_object_object_get_ex(j_config, "band", &j_band) && json_object_is_type(j_band, json_type_string)) {
                const char *band = json_object_get_string(j_band);
                if (band && strcmp(band_pref, band) == 0) {
                    debug(LOG_INFO, "select_radio_by_band: matched by config.band, band_pref=%s, radio=%s", band_pref, key);
                    char *res = strdup(key);
                    json_object_put(j);
                    return res;
                }
            }

            // Check channel (can be string or int)
            json_object *j_channel = NULL;
            if (json_object_object_get_ex(j_config, "channel", &j_channel)) {
                int ch = 0;
                if (json_object_is_type(j_channel, json_type_string)) {
                    ch = atoi(json_object_get_string(j_channel));
                } else if (json_object_is_type(j_channel, json_type_int)) {
                    ch = json_object_get_int(j_channel);
                }
                if (ch > 0) {
                    if (strcmp(band_pref, "5g") == 0 && ch > 14) {
                        debug(LOG_INFO, "select_radio_by_band: matched by channel, band_pref=%s, channel=%d, radio=%s", band_pref, ch, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                    if (strcmp(band_pref, "2g") == 0 && ch <= 14) {
                        debug(LOG_INFO, "select_radio_by_band: matched by channel, band_pref=%s, channel=%d, radio=%s", band_pref, ch, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                }
            }

            // hwmode fallback: 11a -> 5g, 11b/11g -> 2g
            json_object *j_hwmode = NULL;
            if (json_object_object_get_ex(j_config, "hwmode", &j_hwmode) && json_object_is_type(j_hwmode, json_type_string)) {
                const char *hw = json_object_get_string(j_hwmode);
                if (hw) {
                    if (strcmp(band_pref, "5g") == 0 && strstr(hw, "11a")) {
                        debug(LOG_INFO, "select_radio_by_band: matched by hwmode, band_pref=%s, hwmode=%s, radio=%s", band_pref, hw, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                    if (strcmp(band_pref, "2g") == 0 && (strstr(hw, "11b") || strstr(hw, "11g"))) {
                        debug(LOG_INFO, "select_radio_by_band: matched by hwmode, band_pref=%s, hwmode=%s, radio=%s", band_pref, hw, key);
                        char *res = strdup(key);
                        json_object_put(j);
                        return res;
                    }
                }
            }
        }
    }

    json_object_put(j);
    debug(LOG_WARNING, "select_radio_by_band: no matched radio for band_pref=%s", band_pref ? band_pref : "(null)");
    return NULL;
}

static int remove_existing_sta_iface(void) {
    struct uci_package *pkg = NULL;
    struct uci_context *ctx = NULL;
    if (uci_open_package("wireless", &ctx, &pkg) != 0) {
        return -1;
    }

    char sections[64][128];
    int section_count = 0;

    struct uci_element *e = NULL;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *sec = uci_to_section(e);
        if (!sec || !sec->type || strcmp(sec->type, "wifi-iface") != 0) {
            continue;
        }

        const char *mode = uci_lookup_option_string(ctx, sec, "mode");
        if (!mode || strcmp(mode, "sta") != 0) {
            continue;
        }

        if (!e->name || e->name[0] == '\0') {
            continue;
        }

        // Deduplicate
        int exists = 0;
        for (int i = 0; i < section_count; i++) {
            if (strcmp(sections[i], e->name) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists && section_count < (int)(sizeof(sections) / sizeof(sections[0]))) {
            strncpy(sections[section_count], e->name, sizeof(sections[section_count]) - 1);
            sections[section_count][sizeof(sections[section_count]) - 1] = '\0';
            section_count++;
        }
    }

    if (section_count == 0) {
        uci_close_package(ctx, pkg);
        return 0;
    }

    for (int i = 0; i < section_count; i++) {
        char path[256];
        int n = snprintf(path, sizeof(path), "wireless.%s", sections[i]);
        if (n <= 0 || n >= (int)sizeof(path)) {
            uci_close_package(ctx, pkg);
            return -1;
        }

        struct uci_ptr ptr;
        memset(&ptr, 0, sizeof(ptr));

        if (uci_lookup_ptr(ctx, &ptr, path, true) != UCI_OK || !ptr.s) {
            uci_close_package(ctx, pkg);
            return -1;
        }

        if (uci_delete(ctx, &ptr) != UCI_OK) {
            uci_close_package(ctx, pkg);
            return -1;
        }
    }

    /* Keep old behavior: only stage changes; commit remains caller-controlled. */
    if (uci_save_package_with_ctx(ctx, pkg) != 0) {
        uci_close_package(ctx, pkg);
        return -1;
    }

    uci_close_package(ctx, pkg);
    return 0;
}

static int verify_sta_connection(int timeout_seconds) {
    // Poll ubus for wwan status
    for (int i = 0; i < timeout_seconds; i++) {
        FILE *fp = popen("ubus call network.interface.wwan status 2>/dev/null", "r");
        if (!fp) { sleep(1); continue; }
        size_t buf_size = 2048, len = 0; char *out = malloc(buf_size);
        if (!out) { pclose(fp); sleep(1); continue; }
        out[0] = '\0'; char chunk[512];
        while (fgets(chunk, sizeof(chunk), fp) != NULL) {
            size_t cl = strlen(chunk);
            if (len + cl + 1 > buf_size) { buf_size = (len + cl + 1) * 2; char *n = realloc(out, buf_size); if (!n) break; out = n; }
            memcpy(out + len, chunk, cl); len += cl; out[len] = '\0';
        }
        pclose(fp);
        if (len == 0) { free(out); sleep(1); continue; }
        json_object *j = json_tokener_parse(out);
        free(out);
        if (!j) { sleep(1); continue; }
        json_object *j_up = NULL;
        if (json_object_object_get_ex(j, "up", &j_up) && json_object_is_type(j_up, json_type_boolean)) {
            int up = json_object_get_boolean(j_up);
            json_object_put(j);
            if (up) return 0;
            sleep(1);
            continue;
        }
        json_object_put(j);
        sleep(1);
    }
    return -1;
}

void handle_set_wifi_relay_request(json_object *j_req, api_transport_context_t *transport) {
    // Validate required SSID
    json_object *j_ssid = json_object_object_get(j_req, "ssid");
    if (!j_ssid || !json_object_is_type(j_ssid, json_type_string)) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Missing required 'ssid' parameter"));
        send_json_response(transport, j_err);
        return;
    }
    const char *ssid = json_object_get_string(j_ssid);

    // Optional params
    const char *bssid = NULL; json_object *j_bssid = json_object_object_get(j_req, "bssid");
    if (j_bssid && json_object_is_type(j_bssid, json_type_string)) bssid = json_object_get_string(j_bssid);

    const char *encryption = NULL; json_object *j_enc = json_object_object_get(j_req, "encryption");
    if (j_enc && json_object_is_type(j_enc, json_type_string)) encryption = json_object_get_string(j_enc);

    const char *key = NULL; json_object *j_key = json_object_object_get(j_req, "key");
    if (j_key && json_object_is_type(j_key, json_type_string)) key = json_object_get_string(j_key);

    const char *band = "2g"; json_object *j_band = json_object_object_get(j_req, "band");
    if (j_band && json_object_is_type(j_band, json_type_string)) {
        const char *b = json_object_get_string(j_band);
        if (b && (strcmp(b, "5g") == 0 || strcmp(b, "2g") == 0)) band = b;
    }

    int apply = 1; json_object *j_apply = json_object_object_get(j_req, "apply");
    if (j_apply && json_object_is_type(j_apply, json_type_boolean)) apply = json_object_get_boolean(j_apply);

    // Validate encryption/key semantics
    if (encryption && strcmp(encryption, "none") == 0 && key) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("'key' must not be provided when encryption is 'none'"));
        send_json_response(transport, j_err);
        return;
    }
    if (encryption && (strncmp(encryption, "psk", 3) == 0 || strcmp(encryption, "sae") == 0) && !key) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("'key' is required for WPA-PSK/SAE encryption"));
        send_json_response(transport, j_err);
        return;
    }

    // Ensure wwan exists
    if (ensure_wwan_interface() != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to ensure 'wwan' network interface"));
        send_json_response(transport, j_err);
        return;
    }

    // Select radio dynamically
    char *radio = select_radio_by_band(band);
    if (!radio) {
        // Fallback: reasonable names
        radio = strdup(strcmp(band, "5g") == 0 ? "radio1" : "radio0");
    }

    // Remove existing STA ifaces
    if (remove_existing_sta_iface() != 0) {
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to remove existing STA interfaces"));
        send_json_response(transport, j_err);
        return;
    }

    // Add new wifi-iface and configure with libuci
    char secbuf[128] = {0};
    struct uci_context *w_ctx = NULL;
    struct uci_package *w_pkg = NULL;
    if (uci_open_package("wireless", &w_ctx, &w_pkg) != 0) {
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to open wireless package"));
        send_json_response(transport, j_err);
        return;
    }

    struct uci_section *new_sec = NULL;
    if (uci_add_section(w_ctx, w_pkg, "wifi-iface", &new_sec) != UCI_OK || !new_sec || !new_sec->e.name) {
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to create wireless section"));
        send_json_response(transport, j_err);
        return;
    }

    strncpy(secbuf, new_sec->e.name, sizeof(secbuf) - 1);
    secbuf[sizeof(secbuf) - 1] = '\0';

    int set_failed = 0;
    if (uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "device", radio) != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "mode", "sta") != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "ssid", ssid) != 0) set_failed = 1;
    if (!set_failed && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "network", "wwan") != 0) set_failed = 1;
    if (!set_failed && bssid && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "bssid", bssid) != 0) set_failed = 1;
    if (!set_failed && encryption && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "encryption", encryption) != 0) set_failed = 1;
    if (!set_failed && key && uci_set_option_with_ctx(w_ctx, "wireless", secbuf, "key", key) != 0) set_failed = 1;

    if (set_failed) {
        if (secbuf[0]) {
            uci_delete_section_with_ctx(w_ctx, "wireless", secbuf);
            uci_save_package_with_ctx(w_ctx, w_pkg);
        }
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to apply wireless settings"));
        send_json_response(transport, j_err);
        return;
    }

    if (uci_save_commit_package_with_ctx(w_ctx, &w_pkg) != 0 || uci_commit_package_by_name("network") != 0) {
        if (secbuf[0]) {
            uci_delete_section_with_ctx(w_ctx, "wireless", secbuf);
            uci_save_commit_package_with_ctx(w_ctx, &w_pkg);
        }
        uci_close_package(w_ctx, w_pkg);
        free(radio);
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("set_wifi_sta_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to commit UCI changes"));
        send_json_response(transport, j_err);
        return;
    }

    uci_close_package(w_ctx, w_pkg);

    // Trigger wifi reload if requested (non-blocking)
    if (apply) {
        // spawn in background
        int wifi_ret = system("wifi reload >/dev/null 2>&1 &");
        if (wifi_ret != 0) debug(LOG_WARNING, "wifi reload background command failed (ret=%d)", wifi_ret);
    }

    // Verify connection (poll ubus for wwan up)
    int ok = verify_sta_connection(8); // wait up to 8s

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("set_wifi_sta_response"));
    if (ok == 0) {
        json_object_object_add(j_resp, "status", json_object_new_string("success"));
        json_object_object_add(j_resp, "message", json_object_new_string("STA configured and wwan is up"));
    } else {
        json_object_object_add(j_resp, "status", json_object_new_string("error"));
        json_object_object_add(j_resp, "message", json_object_new_string("STA configured but wwan did not come up within timeout"));
    }
    send_json_response(transport, j_resp);

    free(radio);
}

void handle_delete_wifi_relay_request(json_object *j_req, api_transport_context_t *transport) {
    int apply = 1;
    json_object *j_apply = json_object_object_get(j_req, "apply");
    if (j_apply && json_object_is_type(j_apply, json_type_boolean)) {
        apply = json_object_get_boolean(j_apply);
    }

    // Remove existing STA/relay interfaces
    if (remove_existing_sta_iface() != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("delete_wifi_relay_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to remove existing STA interfaces"));
        send_json_response(transport, j_err);
        return;
    }

    // Commit wireless changes
    if (uci_commit_package_by_name("wireless") != 0) {
        json_object *j_err = json_object_new_object();
        json_object_object_add(j_err, "type", json_object_new_string("delete_wifi_relay_error"));
        json_object_object_add(j_err, "error", json_object_new_string("Failed to commit wireless changes"));
        send_json_response(transport, j_err);
        return;
    }

    // Optionally apply runtime changes
    if (apply) {
        int wifi_ret = system("wifi reload >/dev/null 2>&1 &");
        if (wifi_ret != 0) {
            debug(LOG_WARNING, "delete_wifi_relay: wifi reload background command failed (ret=%d)", wifi_ret);
        }
    }

    json_object *j_resp = json_object_new_object();
    json_object_object_add(j_resp, "type", json_object_new_string("delete_wifi_relay_response"));
    json_object_object_add(j_resp, "status", json_object_new_string("success"));
    json_object_object_add(j_resp, "apply", json_object_new_boolean(apply));
    json_object_object_add(j_resp, "message", json_object_new_string("WiFi relay/STA configuration removed"));
    send_json_response(transport, j_resp);
}

void handle_set_wifi_info_request(json_object *j_req, api_transport_context_t *transport) {
    json_object *j_response = json_object_new_object();
    json_object *j_data;

    if (!json_object_object_get_ex(j_req, "data", &j_data)) {
        debug(LOG_ERR, "Set wifi info request missing 'data' field");
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string("Missing 'data' field"));
        send_json_response(transport, j_response);
        return;
    }

    int success = 1;
    char error_msg[256] = {0};

    // Process each radio device configuration
    json_object_object_foreach(j_data, radio_name, j_radio_config) {
        // Skip non-radio entries
        if (strstr(radio_name, "radio") != radio_name) {
            continue;
        }

        debug(LOG_INFO, "Configuring radio: %s", radio_name);

        // Configure radio device settings
        json_object *j_value;
        if (json_object_object_get_ex(j_radio_config, "channel", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.channel", radio_name);
            if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set channel for %s", radio_name);
            }
        }

        if (json_object_object_get_ex(j_radio_config, "htmode", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.htmode", radio_name);
            if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set htmode for %s", radio_name);
            }
        }

        if (json_object_object_get_ex(j_radio_config, "cell_density", &j_value)) {
            char config_path[128];
            snprintf(config_path, sizeof(config_path), "wireless.%s.cell_density", radio_name);
            char value_str[16];
            snprintf(value_str, sizeof(value_str), "%d", json_object_get_int(j_value));
            if (set_uci_config(config_path, value_str) != 0) {
                success = 0;
                snprintf(error_msg, sizeof(error_msg), "Failed to set cell_density for %s", radio_name);
            }
        }

        // Configure interfaces for this radio
        json_object *j_interfaces;
        if (json_object_object_get_ex(j_radio_config, "interfaces", &j_interfaces)) {
            int interface_count = json_object_array_length(j_interfaces);
            
            for (int i = 0; i < interface_count; i++) {
                json_object *j_interface = json_object_array_get_idx(j_interfaces, i);
                if (!j_interface) continue;

                json_object *j_iface_name;
                if (!json_object_object_get_ex(j_interface, "interface_name", &j_iface_name)) {
                    continue;
                }
                
                const char *interface_name = json_object_get_string(j_iface_name);
                debug(LOG_INFO, "Configuring interface: %s", interface_name);

                // Set device assignment
                char config_path[128];
                snprintf(config_path, sizeof(config_path), "wireless.%s.device", interface_name);
                if (set_uci_config(config_path, radio_name) != 0) {
                    success = 0;
                    snprintf(error_msg, sizeof(error_msg), "Failed to set device for interface %s", interface_name);
                    continue;
                }

                // Configure interface properties
                if (json_object_object_get_ex(j_interface, "mode", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.mode", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set mode for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "ssid", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.ssid", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set SSID for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "key", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.key", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set key for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "encryption", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.encryption", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set encryption for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "network", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.network", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set network for interface %s", interface_name);
                    }
                }

                if (json_object_object_get_ex(j_interface, "mesh_id", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.mesh_id", interface_name);
                    if (set_uci_config(config_path, json_object_get_string(j_value)) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set mesh_id for interface %s", interface_name);
                    }
                }



                if (json_object_object_get_ex(j_interface, "disabled", &j_value)) {
                    snprintf(config_path, sizeof(config_path), "wireless.%s.disabled", interface_name);
                    char value_str[16];
                    snprintf(value_str, sizeof(value_str), "%d", json_object_get_boolean(j_value) ? 1 : 0);
                    if (set_uci_config(config_path, value_str) != 0) {
                        success = 0;
                        snprintf(error_msg, sizeof(error_msg), "Failed to set disabled for interface %s", interface_name);
                    }
                }
            }
        }
    }



    if (success) {
        // Commit UCI changes
        if (commit_uci_changes() != 0) {
            success = 0;
            snprintf(error_msg, sizeof(error_msg), "Failed to commit configuration changes");
        }
    }

    if (success) {
        // Reload wifi to apply changes
        FILE *reload_fp = popen("wifi reload", "r");
        if (reload_fp == NULL) {
            debug(LOG_ERR, "Failed to run reload commands");
            json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
            json_object_object_add(j_response, "error", json_object_new_string("Failed to reload services"));
        } else {
            pclose(reload_fp);
            
            // Construct success response
            json_object *j_resp_data = json_object_new_object();
            json_object_object_add(j_resp_data, "status", json_object_new_string("success"));
            json_object_object_add(j_resp_data, "message", json_object_new_string("Wi-Fi configuration updated successfully"));
            json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_response"));
            json_object_object_add(j_response, "data", j_resp_data);
        }
    } else {
        // Construct error response
        json_object_object_add(j_response, "type", json_object_new_string("set_wifi_info_error"));
        json_object_object_add(j_response, "error", json_object_new_string(strlen(error_msg) > 0 ? error_msg : "Failed to update Wi-Fi configuration"));
    }

    const char *response_str = json_object_to_json_string(j_response);
    debug(LOG_INFO, "Sending Wi-Fi configuration response: %s", response_str);
    send_json_response(transport, j_response);
}
