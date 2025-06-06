// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <pthread.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "auth.h"
#include "debug.h"
#include "firewall.h"
#include "fw_vpp.h"

/**
 * @brief Updates firewall counters by processing VPP statistics
 * 
 * This function retrieves client statistics from VPP's redirect mechanism using 
 * 'vppctl show redirect auth users json' command and updates the client list with
 * traffic information.
 * 
 * @return 0 on success, -1 on failure
 */
int
vpp_fw_counters_update()
{
    debug(LOG_DEBUG, "vpp_fw_counters_update start");

    if (!is_bypass_mode()) {
        debug(LOG_INFO, "Not in bypass mode, skipping vpp counters update");
        return 0;
    }

    LOCK_CLIENT_LIST();
    
    // Reset client list online status
    reset_client_list();

    // Execute vppctl command and redirect output to temporary file
    const char *cmd = "stdbuf -oL sudo /usr/bin/vppctl show redirect auth users json > /tmp/auth-user.json 2>&1";
    execute(cmd, 0);

    // Open the temporary file
    FILE *fp = fopen("/tmp/auth-user.json", "r");
    if (!fp) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Failed to open /tmp/auth-user.json: %s", strerror(errno));
        return -1;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Allocate buffer
    char *buf = malloc(file_size + 1);
    if (!buf) {
        fclose(fp);
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Memory allocation failed");
        return -1;
    }

    // Read file content
    size_t bytes_read = fread(buf, 1, file_size, fp);
    fclose(fp);
    unlink("/tmp/auth-user.json");  // Delete temporary file

    if (bytes_read != (size_t)file_size) {
        free(buf);
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Failed to read file: %s", strerror(errno));
        return -1;
    }

    buf[file_size] = '\0';
    debug(LOG_DEBUG, "VPP output: %s", buf);

    // Parse JSON array (handling potential invalid JSON)
    json_object *jobj = json_tokener_parse(buf);
    free(buf);
    
    if (!jobj) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Failed to parse JSON output");
        return -1;
    }

    // Process each client entry
    if (json_object_is_type(jobj, json_type_array)) {
        int array_len = json_object_array_length(jobj);
        debug(LOG_DEBUG, "Processing %d client entries", array_len);
        
        for (int i = 0; i < array_len; i++) {
            json_object *client_obj = json_object_array_get_idx(jobj, i);
            if (!client_obj) continue;

            // Extract IP address
            json_object *ip_obj = NULL;
            if (!json_object_object_get_ex(client_obj, "ip", &ip_obj)) continue;
            const char *ip = json_object_get_string(ip_obj);
            if (!ip) continue;

            // Find client by IP
            t_client *client = client_list_find_by_ip(ip);
            if (!client) {
                debug(LOG_DEBUG, "Client with IP %s not found in client list", ip);
                continue;
            }

            // Extract and update outgoing stats
            json_object *outgoing_obj = NULL;
            if (json_object_object_get_ex(client_obj, "outgoing", &outgoing_obj)) {
                json_object *packets_obj = NULL, *bytes_obj = NULL, *rate_obj = NULL;
                
                if (json_object_object_get_ex(outgoing_obj, "packets", &packets_obj) && 
                    json_object_object_get_ex(outgoing_obj, "bytes", &bytes_obj) &&
                    json_object_object_get_ex(outgoing_obj, "rate", &rate_obj)) {
                    
                    uint64_t packets = json_object_get_int64(packets_obj);
                    uint64_t bytes = json_object_get_int64(bytes_obj);
                    uint32_t rate = json_object_get_int(rate_obj);
                    
                    client->counters.outgoing_bytes = bytes;
                    client->counters.outgoing_packets = packets;
                    client->counters.outgoing_rate = rate;
                }
            }

            // Extract and update incoming stats
            json_object *incoming_obj = NULL;
            if (json_object_object_get_ex(client_obj, "incoming", &incoming_obj)) {
                json_object *packets_obj = NULL, *bytes_obj = NULL, *rate_obj = NULL;
                
                if (json_object_object_get_ex(incoming_obj, "packets", &packets_obj) && 
                    json_object_object_get_ex(incoming_obj, "bytes", &bytes_obj) &&
                    json_object_object_get_ex(incoming_obj, "rate", &rate_obj)) {
                    
                    uint64_t packets = json_object_get_int64(packets_obj);
                    uint64_t bytes = json_object_get_int64(bytes_obj);
                    uint32_t rate = json_object_get_int(rate_obj);
                    
                    client->counters.incoming_bytes = bytes;
                    client->counters.incoming_packets = packets;
                    client->counters.incoming_rate = rate;
                }
            }

            // Get client name if not already set
            if (!client->name) {
                get_client_name(client);
            }

            // Determine if client is on wired connection (if not already determined)
            if (client->wired == -1) {
                client->wired = br_is_device_wired(client->mac);
            }

            // Update timestamp and online status
            client->counters.last_updated = time(NULL);
            client->is_online = 1;

            debug(LOG_DEBUG, "Updated counters for client: %s, IP: %s, MAC: %s",
                client->name ? client->name : "unknown", client->ip, client->mac);
        }
    }
    
    json_object_put(jobj);
    UNLOCK_CLIENT_LIST();
    debug(LOG_DEBUG, "vpp_fw_counters_update completed");
    return 0;
}

int 
vpp_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    if (!ip) {
        debug(LOG_ERR, "Invalid parameters: ip is NULL");
        return -1;
    }

    const char *action;
    switch(type) {
        case FW_ACCESS_ALLOW:
            action = "";
            break;
        case FW_ACCESS_DENY:
            action = "del";
            break;
        default:
            debug(LOG_ERR, "Invalid firewall access type: %d", type);
            return -1;
    }

    char cmd[256] = {0};
    int ret = snprintf(cmd, sizeof(cmd), "stdbuf -oL sudo /usr/bin/vppctl redirect set auth user %s %s", ip, action);
    if (ret < 0 || ret >= sizeof(cmd)) {
        debug(LOG_ERR, "Command buffer overflow");
        return -1;
    }
    debug(LOG_INFO, "Executing VPP command: %s", cmd);
    return execute(cmd, 0);
}