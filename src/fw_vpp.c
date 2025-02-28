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

    // Execute vppctl command to get statistics in JSON format
    const char *cmd = "vppctl show redirect auth users json";
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Failed to execute command: %s", cmd);
        return -1;
    }

    // Read command output
    char *buf = NULL;
    size_t total_len = 0;
    size_t chunk_size = 4096;
    
    while (1) {
        char *new_buf = realloc(buf, total_len + chunk_size);
        if (!new_buf) {
            free(buf);
            pclose(fp);
            UNLOCK_CLIENT_LIST();
            debug(LOG_ERR, "Memory allocation failed");
            return -1;
        }
        
        buf = new_buf;
        size_t bytes_read = fread(buf + total_len, 1, chunk_size, fp);
        total_len += bytes_read;

        if (bytes_read < chunk_size) {
            if (feof(fp)) {
                break;
            }
            if (ferror(fp)) {
                free(buf);
                pclose(fp);
                UNLOCK_CLIENT_LIST();
                debug(LOG_ERR, "Error reading command output: %s", strerror(errno));
                return -1;
            }
        }
    }

    pclose(fp);

    // Ensure null termination
    char *final_buf = realloc(buf, total_len + 1);
    if (!final_buf) {
        free(buf);
        UNLOCK_CLIENT_LIST();
        debug(LOG_ERR, "Final buffer allocation failed");
        return -1;
    }
    buf = final_buf;
    buf[total_len] = '\0';

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
                json_object *packets_obj = NULL, *bytes_obj = NULL;
                
                if (json_object_object_get_ex(outgoing_obj, "packets", &packets_obj) && 
                    json_object_object_get_ex(outgoing_obj, "bytes", &bytes_obj)) {
                    
                    uint64_t packets = json_object_get_int64(packets_obj);
                    uint64_t bytes = json_object_get_int64(bytes_obj);
                    
                    // Save previous outgoing count and update with new values
                    client->counters.outgoing_history = client->counters.outgoing;
                    client->counters.outgoing = bytes;
                    client->counters.outgoing_packets = packets;
                }
            }

            // Extract and update incoming stats
            json_object *incoming_obj = NULL;
            if (json_object_object_get_ex(client_obj, "incoming", &incoming_obj)) {
                json_object *packets_obj = NULL, *bytes_obj = NULL;
                
                if (json_object_object_get_ex(incoming_obj, "packets", &packets_obj) && 
                    json_object_object_get_ex(incoming_obj, "bytes", &bytes_obj)) {
                    
                    uint64_t packets = json_object_get_int64(packets_obj);
                    uint64_t bytes = json_object_get_int64(bytes_obj);
                    
                    // Save previous incoming count and update with new values
                    client->counters.incoming_history = client->counters.incoming;
                    client->counters.incoming = bytes;
                    client->counters.incoming_packets = packets;
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