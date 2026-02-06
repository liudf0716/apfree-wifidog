#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <json-c/json.h>

#include "client_snapshot.h"
#include "client_list.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "safe.h"
#include "util.h"
#include <errno.h>

#ifndef VERSION
#define VERSION "1.0.0"
#endif

#define SNAPSHOT_FILE "/etc/client_snapshot.json"

extern time_t started_time;

static bool
snapshot_enabled(void)
{
    return !is_portal_auth_disabled() && !is_bypass_mode();
}

static const char *
auth_type_to_string(client_auth_type_t auth_type)
{
    switch (auth_type) {
    case AUTH_TYPE_AUTH_SERVER:
        return "AUTH_SERVER";
    case AUTH_TYPE_LOCAL_PASS:
        return "LOCAL_PASS";
    case AUTH_TYPE_TRUSTED_MAC:
        return "TRUSTED_MAC";
    case AUTH_TYPE_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static client_auth_type_t
auth_type_from_string(const char *auth_type)
{
    if (!auth_type) return AUTH_TYPE_UNKNOWN;
    if (strcasecmp(auth_type, "AUTH_SERVER") == 0) return AUTH_TYPE_AUTH_SERVER;
    if (strcasecmp(auth_type, "LOCAL_PASS") == 0) return AUTH_TYPE_LOCAL_PASS;
    if (strcasecmp(auth_type, "TRUSTED_MAC") == 0) return AUTH_TYPE_TRUSTED_MAC;
    return AUTH_TYPE_UNKNOWN;
}

static char *
get_firmware_version(void)
{
    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *cleaned_version = NULL;

    fp = fopen("/etc/openwrt_version", "r");
    if (!fp) {
        debug(LOG_ERR, "Could not open /etc/openwrt_version: %s", strerror(errno));
        return safe_strdup("unknown");
    }

    read = getline(&line, &len, fp);
    if (read != -1) {
        // Remove trailing newlines and whitespace
        while (read > 0 && (line[read-1] == '\n' || line[read-1] == '\r' || line[read-1] == ' ')) {
            line[--read] = '\0';
        }
        
        if (read > 0) {
            cleaned_version = safe_strdup(line);
        }
    }

    free(line);
    fclose(fp);

    return cleaned_version ? cleaned_version : safe_strdup("unknown");
}

int client_snapshot_save(void)
{
    if (!snapshot_enabled()) {
        debug(LOG_DEBUG, "Snapshot is disabled, skip save");
        return 0;
    }

    debug(LOG_INFO, "Saving client snapshot to %s", SNAPSHOT_FILE);

    json_object *root = json_object_new_object();
    json_object *clients_array = json_object_new_array();
    json_object *trusted_array = json_object_new_array();

    // Save online clients
    LOCK_CLIENT_LIST();
    t_client *client = client_get_first_client();
    while (client) {
        json_object *c_obj = json_object_new_object();
        json_object_object_add(c_obj, "mac", json_object_new_string(client->mac));
        json_object_object_add(c_obj, "ip", json_object_new_string(client->ip ? client->ip : ""));
        json_object_object_add(c_obj, "ip6", json_object_new_string(client->ip6 ? client->ip6 : ""));
        json_object_object_add(c_obj, "token", json_object_new_string(client->token ? client->token : ""));
        json_object_object_add(c_obj, "first_login", json_object_new_int64(client->first_login));
        json_object_object_add(c_obj, "last_updated", json_object_new_int64(client->counters.last_updated));
        json_object_object_add(c_obj, "auth_type", json_object_new_string(auth_type_to_string(client->auth_type)));
        json_object_object_add(c_obj, "incoming_bytes", json_object_new_int64(client->counters.incoming_bytes));
        json_object_object_add(c_obj, "outgoing_bytes", json_object_new_int64(client->counters.outgoing_bytes));
        json_object_object_add(c_obj, "incoming_packets", json_object_new_int64(client->counters.incoming_packets));
        json_object_object_add(c_obj, "outgoing_packets", json_object_new_int64(client->counters.outgoing_packets));
        json_object_object_add(c_obj, "incoming_rate", json_object_new_int(client->counters.incoming_rate));
        json_object_object_add(c_obj, "outgoing_rate", json_object_new_int(client->counters.outgoing_rate));
        
        json_object *c6_obj = json_object_new_object();
        json_object_object_add(c6_obj, "incoming_bytes", json_object_new_int64(client->counters6.incoming_bytes));
        json_object_object_add(c6_obj, "outgoing_bytes", json_object_new_int64(client->counters6.outgoing_bytes));
        json_object_object_add(c6_obj, "incoming_packets", json_object_new_int64(client->counters6.incoming_packets));
        json_object_object_add(c6_obj, "outgoing_packets", json_object_new_int64(client->counters6.outgoing_packets));
        json_object_object_add(c6_obj, "incoming_rate", json_object_new_int(client->counters6.incoming_rate));
        json_object_object_add(c6_obj, "outgoing_rate", json_object_new_int(client->counters6.outgoing_rate));
        json_object_object_add(c6_obj, "last_updated", json_object_new_int64(client->counters6.last_updated));
        json_object_object_add(c_obj, "counters6", c6_obj);

        json_object_object_add(c_obj, "fw_connection_state", json_object_new_int(client->fw_connection_state));
        
        json_object_array_add(clients_array, c_obj);
        client = client->next;
    }
    UNLOCK_CLIENT_LIST();

    // Save trusted MACs
    LOCK_CONFIG();
    s_config *config = config_get_config();
    t_trusted_mac *tm = config->trustedmaclist;
    while (tm) {
        json_object *t_obj = json_object_new_object();
        json_object_object_add(t_obj, "mac", json_object_new_string(tm->mac));
        json_object_object_add(t_obj, "remaining_time", json_object_new_int64(tm->remaining_time));
        json_object_object_add(t_obj, "serial", json_object_new_string(tm->serial ? tm->serial : ""));
        json_object_object_add(t_obj, "first_time", json_object_new_int64(tm->first_time));
        
        json_object_array_add(trusted_array, t_obj);
        tm = tm->next;
    }
    UNLOCK_CONFIG();

    json_object_object_add(root, "online_clients", clients_array);
    json_object_object_add(root, "trustedmaclist", trusted_array);

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
    FILE *fp = fopen(SNAPSHOT_FILE, "w");
    if (fp) {
        fputs(json_str, fp);
        fclose(fp);
    } else {
        debug(LOG_ERR, "Failed to open snapshot file for writing: %s", SNAPSHOT_FILE);
        json_object_put(root);
        return -1;
    }

    json_object_put(root);
    return 0;
}

int client_snapshot_load(void)
{
    if (!snapshot_enabled()) {
        debug(LOG_DEBUG, "Snapshot is disabled, skip load");
        return 0;
    }

    debug(LOG_INFO, "Loading client snapshot from %s", SNAPSHOT_FILE);

    FILE *fp = fopen(SNAPSHOT_FILE, "r");
    if (!fp) {
        debug(LOG_INFO, "No snapshot file found.");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }
    if (fread(buffer, 1, size, fp) != size) {
        debug(LOG_ERR, "Failed to read snapshot file");
        fclose(fp);
        free(buffer);
        return -1;
    }
    buffer[size] = '\0';
    fclose(fp);

    json_object *root = json_tokener_parse(buffer);
    free(buffer);

    if (!root) {
        debug(LOG_ERR, "Failed to parse snapshot JSON");
        return -1;
    }

    // Load trusted MACs first
    json_object *trusted_array;
    if (json_object_object_get_ex(root, "trustedmaclist", &trusted_array)) {
        int len = json_object_array_length(trusted_array);
        for (int i = 0; i < len; i++) {
            json_object *t_obj = json_object_array_get_idx(trusted_array, i);
            const char *mac = json_object_get_string(json_object_object_get(t_obj, "mac"));
            uint32_t remaining_time = json_object_get_int64(json_object_object_get(t_obj, "remaining_time"));
            const char *serial = json_object_get_string(json_object_object_get(t_obj, "serial"));
            time_t first_time = json_object_get_int64(json_object_object_get(t_obj, "first_time"));
            
            // Add to config and firewall
            debug(LOG_INFO, "Restoring trusted MAC: %s", mac);
            add_mac_from_list(mac, remaining_time, safe_strdup(serial), TRUSTED_MAC, first_time);
            fw_add_trusted_mac(mac, remaining_time);
        }
    }

    // Load online clients
    json_object *clients_array;
    if (json_object_object_get_ex(root, "online_clients", &clients_array)) {
        int len = json_object_array_length(clients_array);
        for (int i = 0; i < len; i++) {
            json_object *c_obj = json_object_array_get_idx(clients_array, i);
            const char *mac = json_object_get_string(json_object_object_get(c_obj, "mac"));
            const char *ip = json_object_get_string(json_object_object_get(c_obj, "ip"));
            const char *ip6 = json_object_get_string(json_object_object_get(c_obj, "ip6"));
            const char *token = json_object_get_string(json_object_object_get(c_obj, "token"));
            int fw_state = json_object_get_int(json_object_object_get(c_obj, "fw_connection_state"));
            const char *auth_type_str = NULL;
            json_object *auth_type_obj = NULL;
            if (json_object_object_get_ex(c_obj, "auth_type", &auth_type_obj)) {
                auth_type_str = json_object_get_string(auth_type_obj);
            }

            debug(LOG_INFO, "Restoring online client: %s (%s)", mac, ip);
            
            LOCK_CLIENT_LIST();
            t_client *client = client_list_find_by_mac(mac);
            if (!client) {
                client = client_get_new();
                if (client) {
                    client->mac = safe_strdup(mac);
                    client->ip = safe_strdup(ip);
                    client->ip6 = safe_strdup(ip6);
                    client->token = safe_strdup(token);
                    client->first_login = json_object_get_int64(json_object_object_get(c_obj, "first_login"));
                    client->auth_type = auth_type_from_string(auth_type_str);
                    
                    client->counters.incoming_bytes = json_object_get_int64(json_object_object_get(c_obj, "incoming_bytes"));
                    client->counters.outgoing_bytes = json_object_get_int64(json_object_object_get(c_obj, "outgoing_bytes"));
                    client->counters.incoming_packets = json_object_get_int64(json_object_object_get(c_obj, "incoming_packets"));
                    client->counters.outgoing_packets = json_object_get_int64(json_object_object_get(c_obj, "outgoing_packets"));
                    client->counters.last_updated = json_object_get_int64(json_object_object_get(c_obj, "last_updated"));
                    client->counters.incoming_rate = json_object_get_int(json_object_object_get(c_obj, "incoming_rate"));
                    client->counters.outgoing_rate = json_object_get_int(json_object_object_get(c_obj, "outgoing_rate"));

                    json_object *c6_obj = NULL;
                    if (json_object_object_get_ex(c_obj, "counters6", &c6_obj)) {
                        client->counters6.incoming_bytes = json_object_get_int64(json_object_object_get(c6_obj, "incoming_bytes"));
                        client->counters6.outgoing_bytes = json_object_get_int64(json_object_object_get(c6_obj, "outgoing_bytes"));
                        client->counters6.incoming_packets = json_object_get_int64(json_object_object_get(c6_obj, "incoming_packets"));
                        client->counters6.outgoing_packets = json_object_get_int64(json_object_object_get(c6_obj, "outgoing_packets"));
                        client->counters6.incoming_rate = json_object_get_int(json_object_object_get(c6_obj, "incoming_rate"));
                        client->counters6.outgoing_rate = json_object_get_int(json_object_object_get(c6_obj, "outgoing_rate"));
                        client->counters6.last_updated = json_object_get_int64(json_object_object_get(c6_obj, "last_updated"));
                    }
                    
                    client->fw_connection_state = fw_state;
                    
                    client_list_insert_client(client);
                }
            }
            UNLOCK_CLIENT_LIST();

            // Apply firewall rule
            if (fw_state == FW_MARK_KNOWN) {
                fw_allow_ip_mac(ip, mac, fw_state);
            }
        }
    }

    json_object_put(root);
    return 0;
}

char *client_snapshot_dump_json(void)
{
    if (!snapshot_enabled()) {
        debug(LOG_DEBUG, "Snapshot is disabled, returning empty json");
        return safe_strdup("{}");
    }

    s_config *config = config_get_config();
    json_object *j_obj = json_object_new_object();
    json_object *j_array = json_object_new_array();
    uint32_t uptime = time(NULL) - started_time;
    char *firmware_version = get_firmware_version();
    char uptime_str[32] = {0};
    snprintf(uptime_str, sizeof(uptime_str), "%d", uptime);

    json_object_object_add(j_obj, "apfree version", json_object_new_string(VERSION));
    json_object_object_add(j_obj, "openwrt version", json_object_new_string(firmware_version));
    json_object_object_add(j_obj, "uptime", json_object_new_string(uptime_str));
    free(firmware_version);
    
    LOCK_CONFIG();
    t_trusted_mac *tmac = config->trustedmaclist;
    char remaining_time_str[32] = {0};
    while (tmac) {
        snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", tmac->remaining_time);
        json_object *j_user = json_object_new_object();
        json_object_object_add(j_user, "mac", json_object_new_string(tmac->mac));
        json_object_object_add(j_user, "serial", json_object_new_string(tmac->serial ? tmac->serial : ""));
        json_object_object_add(j_user, "remaining time", json_object_new_string(remaining_time_str));
        json_object_array_add(j_array, j_user);
        tmac = tmac->next;
        memset(remaining_time_str, 0, sizeof(remaining_time_str));
    }
    UNLOCK_CONFIG();
    
    json_object_object_add(j_obj, "online user", j_array);
    const char *json_str = json_object_to_json_string(j_obj);
    char *res = safe_strdup(json_str);
    json_object_put(j_obj);
    
    return res;
}

char *client_snapshot_query_status(const char *key, const char *gw_mac, const char *gw_address, query_choice_t choice)
{
    if (!key || !gw_mac || !gw_address) return NULL;

    if (!snapshot_enabled()) {
        json_object *j_status = json_object_new_object();
        json_object_object_add(j_status, "gw_mac", json_object_new_string(gw_mac));
        json_object_object_add(j_status, "gw_ip", json_object_new_string(gw_address));
        json_object_object_add(j_status, "c_mac", json_object_new_string(choice == QUERY_BY_MAC ? key : "unknown"));
        json_object_object_add(j_status, "c_ip", json_object_new_string(choice == QUERY_BY_IP ? key : "unknown"));
        json_object_object_add(j_status, "release", json_object_new_string("0"));
        const char *json_str = json_object_to_json_string(j_status);
        char *res = safe_strdup(json_str);
        json_object_put(j_status);
        return res;
    }

    s_config *config = config_get_config();
    json_object *j_status = json_object_new_object();
    int found = 0;

    LOCK_CONFIG();
    t_trusted_mac *tmac = config->trustedmaclist;
    while (tmac) {
        if ((choice == QUERY_BY_MAC && strcmp(tmac->mac, key) == 0) ||
            (choice == QUERY_BY_IP && tmac->ip && strcmp(tmac->ip, key) == 0)) {
            
            json_object_object_add(j_status, "gw_mac", json_object_new_string(gw_mac));
            json_object_object_add(j_status, "c_mac", json_object_new_string(tmac->mac));
            json_object_object_add(j_status, "c_ip", json_object_new_string(tmac->ip ? tmac->ip : "unknown"));
            json_object_object_add(j_status, "gw_ip", json_object_new_string(gw_address));
            json_object_object_add(j_status, "release", json_object_new_string("1"));
            
            char remaining_time_str[32];
            snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", tmac->remaining_time);
            json_object_object_add(j_status, "remaining_time", json_object_new_string(remaining_time_str));
            json_object_object_add(j_status, "serial", json_object_new_string(tmac->serial ? tmac->serial : ""));
            
            found = 1;
            break;
        }
        tmac = tmac->next;
    }
    UNLOCK_CONFIG();

    if (!found) {
        json_object_object_add(j_status, "gw_mac", json_object_new_string(gw_mac));
        json_object_object_add(j_status, "c_mac", json_object_new_string(choice == QUERY_BY_MAC ? key : "unknown"));
        json_object_object_add(j_status, "c_ip", json_object_new_string(choice == QUERY_BY_IP ? key : "unknown"));
        json_object_object_add(j_status, "gw_ip", json_object_new_string(gw_address));
        json_object_object_add(j_status, "release", json_object_new_string("0"));
    }

    const char *json_str = json_object_to_json_string(j_status);
    char *res = safe_strdup(json_str);
    json_object_put(j_status);
    return res;
}

bool client_snapshot_add_trusted_mac(const char *mac, uint32_t remaining_time, const char *serial)
{
	if (mac == NULL || !is_valid_mac(mac) || serial == NULL) {
		return false;
	}

	if (!snapshot_enabled()) {
		debug(LOG_DEBUG, "Snapshot is disabled, skip add trusted mac");
		return false;
	}
	
    add_mac_from_list(mac, remaining_time, safe_strdup(serial), TRUSTED_MAC, 0); // Note: add_mac_from_list handles list management and locking

    fw_update_trusted_mac(mac, remaining_time);
    client_snapshot_save();
	return true;
}

bool client_snapshot_remove_trusted_mac(const char *mac)
{
	if (mac == NULL || !is_valid_mac(mac)) {
		return false;
	}

	if (!snapshot_enabled()) {
		debug(LOG_DEBUG, "Snapshot is disabled, skip remove trusted mac");
		return false;
	}
	
	remove_mac_from_list(mac, TRUSTED_MAC);
    fw_del_trusted_mac(mac);
    client_snapshot_save();
	return true;
}
