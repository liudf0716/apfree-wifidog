// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <json-c/json.h>
#include <uci.h>

#include "common.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"
#include "util.h"
#include "firewall.h"
#include "wd_util.h"
#include "version.h"
#include "bypass_user.h"

extern time_t started_time;

void
remove_mac_from_list(const char *mac, mac_choice_t which)
{
    s_config *config = config_get_config();
	t_trusted_mac *p = NULL, *p1 = NULL;
	switch(which) {
	case TRUSTED_MAC:
		p = config->trustedmaclist;
		p1 = p;
		break;
	case UNTRUSTED_MAC:
		p = config->mac_blacklist;
		p1 = p;
		break;
	case TRUSTED_LOCAL_MAC:
		p = config->trusted_local_maclist;
		p1 = p;
		break;
	case ROAM_MAC:
		p = config->roam_maclist;
		p1 = p;
		break;
	default:
		return;
	}
	
	if (p == NULL) {
		return;
	}
	
	debug(LOG_DEBUG, "Remove MAC address [%s] to  mac list [%d]", mac, which);
	
	LOCK_CONFIG();

	while(p) {
		if(strcmp(p->mac, mac) == 0) {
			break;
		}
		p1 = p;
		p = p->next;
	}

	if(p) {
		switch(which) {
		case TRUSTED_MAC:
            debug(LOG_DEBUG, "Removing trusted MAC [%s]", mac);
			if(p == config->trustedmaclist)
				config->trustedmaclist = p->next;
			else
				p1->next = p->next;
			break;
		case UNTRUSTED_MAC:
            debug(LOG_ERR, "forbid here");
			if(p == config->mac_blacklist)
				config->mac_blacklist = p->next;
			else
				p1->next = p->next;
			break;
		case TRUSTED_LOCAL_MAC:
            debug(LOG_ERR, "forbid here");
			if(p == config->trusted_local_maclist)
				config->trusted_local_maclist = p->next;
			else
				p1->next = p->next;
			break;
		case ROAM_MAC:
            debug(LOG_ERR, "forbid here");
			if(p == config->roam_maclist)
				config->roam_maclist = p->next;
			else
				p1->next = p->next;
			break;
		}	
		free(p->mac);
		if(p->ip) free(p->ip);
		free(p);
	} else {
        debug(LOG_ERR, "MAC address [%s] not found in mac list [%d]", mac, which);
    }

	UNLOCK_CONFIG();
}

static char *
get_user_ip_by_mac(const char *mac)
{
    FILE *proc = NULL;
    char ip[16] = {0};
    char mac_addr[18] = {0};
    char *reply = NULL;
    s_config *config = config_get_config();

    if (!(proc = fopen(config->arp_table_path, "r"))) {
        return NULL;
    }

    while (!feof(proc) && fgetc(proc) != '\n') ;

    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fA-F0-9:] %*s %*s", ip, mac_addr) == 2)) {
        if (strcmp(mac_addr, mac) == 0) {
            if(reply) {
                free(reply);
                reply = NULL;
            }
            reply = safe_strdup(ip);
        }
    }

    fclose(proc);

    debug(LOG_DEBUG, "IP address for MAC [%s] is [%s]", mac, reply?reply:"not found");

    return reply;
}

static char *
get_user_mac_by_ip(const char *c_ip)
{
    FILE *proc = NULL;
    char ip[16] = {0};
    char mac_addr[18] = {0};
    char *reply = NULL;
    s_config *config = config_get_config();

    if (!(proc = fopen(config->arp_table_path, "r"))) {
        return NULL;
    }

    while (!feof(proc) && fgetc(proc) != '\n') ;

    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fA-F0-9:] %*s %*s", ip, mac_addr) == 2)) {
        if (strcmp(ip, c_ip) == 0) {
            if(reply) {
                free(reply);
                reply = NULL;
            }
            reply = safe_strdup(mac_addr);
        }
    }

    fclose(proc);

    debug(LOG_DEBUG, "MAC address for IP [%s] is [%s]", ip, reply?reply:"not found");

    return reply;
}

t_trusted_mac *
add_mac_from_list(const char *mac, const uint32_t remaining_time, const char *serial, mac_choice_t which)
{
    s_config *config = config_get_config();
	t_trusted_mac *pret = NULL, *p = NULL;

	debug(LOG_DEBUG, "Adding MAC address [%s] to  mac list [%d]", mac, which);

    char *ip = get_user_ip_by_mac(mac);
    if (ip == NULL) {
        debug(LOG_ERR, "Could not find IP address for MAC [%s]", mac);
    }

	LOCK_CONFIG();

	switch (which) {
	case TRUSTED_MAC:
		if (config->trustedmaclist == NULL) {
			config->trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
			config->trustedmaclist->mac = safe_strdup(mac);
            config->trustedmaclist->ip = ip;
			config->trustedmaclist->remaining_time = remaining_time?remaining_time:1;
			config->trustedmaclist->serial = serial?safe_strdup(serial):NULL;
            config->trustedmaclist->first_time = time(NULL);
			config->trustedmaclist->next = NULL;
			pret = config->trustedmaclist;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->trustedmaclist;
		}
		break;
	case UNTRUSTED_MAC:
		if (config->mac_blacklist == NULL) {
			config->mac_blacklist = safe_malloc(sizeof(t_untrusted_mac));
			config->mac_blacklist->mac = safe_strdup(mac);
			config->mac_blacklist->next = NULL;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->mac_blacklist;
		}
		break;
	case TRUSTED_LOCAL_MAC:
		if (config->trusted_local_maclist == NULL) {
			config->trusted_local_maclist = safe_malloc(sizeof(t_trusted_mac));
			config->trusted_local_maclist->mac = safe_strdup(mac);
			config->trusted_local_maclist->next = NULL;
			pret = config->trusted_local_maclist;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->trusted_local_maclist;
		}
		break;
	case ROAM_MAC: //deprecated
		break;
	}
	
	
	int skipmac;
	/* Advance to the last entry */
	skipmac = 0;
	while (p != NULL) {
		if (0 == strcmp(p->mac, mac)) {
			skipmac = 1;
            if (p->remaining_time != remaining_time) {
                p->remaining_time = remaining_time;
            }
            break;
		}
		p = p->next;
	}
	if (!skipmac) {
		p = safe_malloc(sizeof(t_trusted_mac));
		p->mac = safe_strdup(mac);
        p->ip = ip;
		p->remaining_time = remaining_time?remaining_time:1;
        p->first_time = time(NULL);
		p->serial = serial?safe_strdup(serial):NULL;
		switch (which) {
		case TRUSTED_MAC:
			p->next = config->trustedmaclist;
			config->trustedmaclist = p;
			pret = p;
			break;
		case UNTRUSTED_MAC:
            debug(LOG_ERR, "Forbid here");
			p->next = config->mac_blacklist;
			config->mac_blacklist = p;
			pret = p;
			break;
		case TRUSTED_LOCAL_MAC:
            debug(LOG_ERR, "Forbid here");
			p->next = config->trusted_local_maclist;
			config->trusted_local_maclist = p;
			pret = p;
			break;
		case ROAM_MAC: //deprecated
			break;
		}
		
	} else {
		debug(LOG_ERR, "MAC address [%s] already on mac list.  ", mac);
	}

	UNLOCK_CONFIG();
	return pret;
}

bool
add_bypass_user(const char *mac, const uint32_t remaining_time, const char *serial)
{
	if (mac == NULL || !is_valid_mac(mac) || serial == NULL) {
		return false;
	}
	
    add_mac_from_list(mac, remaining_time, serial, TRUSTED_MAC);
    fw_update_trusted_mac(mac, remaining_time);
	return true;
}

bool
remove_bypass_user(const char *mac)
{
	if (mac == NULL || !is_valid_mac(mac)) {
		return false;
	}
	
	remove_mac_from_list(mac, TRUSTED_MAC);
    fw_del_trusted_mac(mac);
	return true;
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

char *
dump_bypass_user_list_json()
{
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

#define BYPASS_USER_LIST_PATH "/etc/bypass_user_list.json"

void
save_bypass_user_list()
{
    if (is_user_reload_enabled() == false) {
        debug(LOG_INFO, "User reload is disabled");
        return;
    }

    FILE *fp = fopen(BYPASS_USER_LIST_PATH, "w");
    if (!fp) {
        debug(LOG_ERR, "Could not open file %s for writing: %s", BYPASS_USER_LIST_PATH, strerror(errno));
        return;
    }

    s_config *config = config_get_config();
    json_object *j_obj = json_object_new_object();
    json_object *j_array = json_object_new_array();
    char remaining_time_str[32] = {0};
    char first_time_str[32] = {0};
    time_t cur_time = time(NULL);
    
    LOCK_CONFIG();
    
    t_trusted_mac *tmac = config->trustedmaclist;
    while (tmac) {
        json_object *j_user = json_object_new_object();
        
        // Validate and calculate times
        time_t first_time = tmac->first_time;
        int past_time = (int)(cur_time - first_time);
        if (past_time < 0) {
            debug(LOG_WARNING, "Invalid past_time detected for MAC %s, adjusting to 0", tmac->mac);
            past_time = 0;
        }
        
        // Calculate remaining time with bounds checking
        int remain_time = tmac->remaining_time - past_time;
        remain_time = (remain_time <= 0) ? 1 : remain_time;
        
        // Format time strings with error checking
        if (snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", remain_time) < 0 ||
            snprintf(first_time_str, sizeof(first_time_str), "%ld", (long)tmac->first_time) < 0) {
            debug(LOG_ERR, "Error formatting time strings for MAC %s", tmac->mac);
            continue;
        }
        
        // Add validated fields to JSON object
        json_object_object_add(j_user, "mac", 
            json_object_new_string(tmac->mac ? tmac->mac : ""));
        json_object_object_add(j_user, "serial", 
            json_object_new_string(tmac->serial ? tmac->serial : ""));
        json_object_object_add(j_user, "time", 
            json_object_new_string(remaining_time_str));
        json_object_object_add(j_user, "first_time", 
            json_object_new_string(first_time_str));
        
        json_object_array_add(j_array, j_user);
        
        // Clear the time string buffers for next iteration
        memset(remaining_time_str, 0, sizeof(remaining_time_str));
        memset(first_time_str, 0, sizeof(first_time_str));
        
        tmac = tmac->next;
    }
    
    UNLOCK_CONFIG();
    
    json_object_object_add(j_obj, "user", j_array);
    
    const char *json_str = json_object_to_json_string_ext(j_obj, JSON_C_TO_STRING_PRETTY);
    fprintf(fp, "%s\n", json_str);
    
    fclose(fp);
    json_object_put(j_obj);
}

#define LOAD_BYPASS_USER_SHELL "/shareWifi/wifiDogReload.sh"
void
load_bypass_user_list()
{
    if (access(LOAD_BYPASS_USER_SHELL, F_OK) == 0) {
        char cmd[256] = {0};
        snprintf(cmd, sizeof(cmd), "/bin/sh %s", LOAD_BYPASS_USER_SHELL);
        execute(cmd, 0);
        return;
    }

    if (is_user_reload_enabled() == false) {
        debug(LOG_INFO, "User reload is disabled");
        return;
    }

    FILE *fp = fopen(BYPASS_USER_LIST_PATH, "r");
    if (!fp) {
        debug(LOG_ERR, "Could not open file %s for reading: %s", BYPASS_USER_LIST_PATH, strerror(errno));
        return;
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read entire file
    char *file_content = safe_malloc(file_size + 1);
    size_t bytes_read = fread(file_content, 1, file_size, fp);
    fclose(fp);

    if (bytes_read != (size_t)file_size) {
        debug(LOG_ERR, "Failed to read entire file: expected %ld bytes but got %zu", file_size, bytes_read);
        free(file_content);
        return;
    }
    file_content[file_size] = '\0';

    // Parse JSON
    json_object *j_obj = json_tokener_parse(file_content);
    free(file_content);

    if (!j_obj) {
        debug(LOG_ERR, "Failed to parse JSON content");
        return;
    }

    json_object *j_array = json_object_object_get(j_obj, "user");
    if (j_array && json_object_is_type(j_array, json_type_array)) {
        for (size_t i = 0; i < json_object_array_length(j_array); i++) {
            json_object *j_user = json_object_array_get_idx(j_array, i);
            if (!j_user || !json_object_is_type(j_user, json_type_object)) {
                debug(LOG_WARNING, "Invalid user entry at index %zu", i);
                continue;
            }

            // Extract JSON objects
            json_object *j_mac = json_object_object_get(j_user, "mac");
            json_object *j_serial = json_object_object_get(j_user, "serial");
            json_object *j_time = json_object_object_get(j_user, "time");
            json_object *j_first_time = json_object_object_get(j_user, "first_time");

            // Validate required fields exist and are strings
            if (!j_mac || !j_serial || !j_time || 
                !json_object_is_type(j_mac, json_type_string) ||
                !json_object_is_type(j_serial, json_type_string) ||
                !json_object_is_type(j_time, json_type_string)) {
                debug(LOG_WARNING, "Missing or invalid required fields in user entry");
                continue;
            }

            // Get string values
            const char *mac = json_object_get_string(j_mac);
            const char *serial = json_object_get_string(j_serial);
            const char *time_str = json_object_get_string(j_time);

            // Validate MAC address
            if (!mac || !is_valid_mac(mac)) {
                debug(LOG_WARNING, "Invalid MAC address: %s", mac ? mac : "null");
                continue;
            }

            // Parse time values
            char *endptr;
            time_t cur_time = time(NULL);
            uint32_t time_val = (uint32_t)strtoul(time_str, &endptr, 10);
            if (*endptr != '\0') {
                debug(LOG_WARNING, "Invalid time value: %s", time_str);
                continue;
            }

            // Handle first_time if present
            time_t first_time = 0;
            if (j_first_time && json_object_is_type(j_first_time, json_type_string)) {
                const char *first_time_str = json_object_get_string(j_first_time);
                first_time = (time_t)strtoul(first_time_str, &endptr, 10);
                if (*endptr != '\0') {
                    debug(LOG_WARNING, "Invalid first_time value: %s", first_time_str);
                    first_time = 0;
                }
            }

            // Calculate remaining time with bounds checking
            int remain_time = (int)(time_val - (cur_time - first_time));
            remain_time = (remain_time <= 0) ? 1 : remain_time;
            debug(LOG_DEBUG, "cur_time: %ld, first_time: %ld, time_val: %d, remain_time: %d", 
                  (long)cur_time, (long)first_time, time_val, remain_time);

            // Add user to trusted MAC list
            if (!add_mac_from_list(mac, remain_time, serial, TRUSTED_MAC)) {
                debug(LOG_ERR, "Failed to add MAC %s to trusted list", mac);
            }
        }
    }

    json_object_put(j_obj);

    fw_set_trusted_maclist();
}

static char *
get_release_value(const char *mac, const char *value) 
{
    if (!mac || !value) {
        debug(LOG_WARNING, "Invalid input: mac or value is NULL");
        return NULL;
    }

    if (!is_valid_mac(mac)) {
        debug(LOG_WARNING, "Invalid MAC address: %s", mac);
        return NULL;
    }

    // Convert MAC to UCI key format
    char key[13] = {0};
    for (size_t i = 0, j = 0; i < strlen(mac) && j < sizeof(key); i++) {
        if (mac[i] != ':') {
            key[j++] = mac[i];
        }
    }
    key[12] = '\0';

    struct uci_context *ctx = NULL;
    struct uci_package *pkg = NULL;
    struct uci_section *sec = NULL;
    struct uci_element *elem = NULL;
    char *result = NULL;

    // Initialize UCI context
    ctx = uci_alloc_context();
    if (!ctx) {
        debug(LOG_WARNING, "Failed to allocate UCI context");
        return NULL;
    }

    // Set config directory to /tmp/config
    if (uci_set_confdir(ctx, "/tmp/config") != UCI_OK) {
        debug(LOG_WARNING, "Failed to set UCI config directory");
        goto cleanup;
    }

    // Load the release package
    if (uci_load(ctx, "release", &pkg) != UCI_OK) {
        debug(LOG_WARNING, "Failed to load UCI package 'release'");
        goto cleanup;
    }

    // Find the section with our key
    uci_foreach_element(&pkg->sections, elem) {
        sec = uci_to_section(elem);
        if (strcmp(sec->e.name, key) == 0) {
            const char *opt_value = uci_lookup_option_string(ctx, sec, value);
            if (opt_value) {
                result = safe_strdup(opt_value);
            }
            break;
        }
    }

cleanup:
    if (ctx) {
        uci_free_context(ctx);
    }

    return result;
}


static void 
add_user_status_to_json(json_object *j_status, const t_trusted_mac *tmac,
                        const char *gw_mac, const char *gw_address) 
{
    if (!j_status || !tmac || !gw_mac || !gw_address) {
        debug(LOG_WARNING, "Invalid input to add_user_status_to_json");
        return;
    }

    char remaining_time_str[32] = {0};

    // Add static values to JSON
    json_object_object_add(j_status, "gw_mac", json_object_new_string(gw_mac));
    json_object_object_add(j_status, "c_mac", json_object_new_string(tmac->mac));
    json_object_object_add(j_status, "c_ip", json_object_new_string(tmac->ip));
    json_object_object_add(j_status, "gw_ip", json_object_new_string(gw_address));
    json_object_object_add(j_status, "release", json_object_new_string("1"));

    if (!tmac->serial) {
        char *v_time = get_release_value(tmac->mac, "time");
        char *v_serial = get_release_value(tmac->mac, "serial");

        if (!v_time || !v_serial) {
            debug(LOG_WARNING, "Failed to retrieve time or serial for mac '%s'", tmac->mac);
            free(v_time);
            free(v_serial);
            return;
        }

        // Calculate remaining time
        time_t release_time = (time_t)atol(v_time);
        time_t cur_time = time(NULL);
        uint32_t remain_time;

        if (release_time <= cur_time) {
            debug(LOG_WARNING, "Release time expired for MAC '%s' (release: %ld, current: %ld)", 
                  tmac->mac, release_time, cur_time);
            remain_time = 0;
        } else {
            remain_time = (uint32_t)(release_time - cur_time);
            debug(LOG_DEBUG, "Remaining time for MAC '%s': %d seconds", tmac->mac, remain_time);
        }

        snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", remain_time);
        json_object_object_add(j_status, "remaining_time", json_object_new_string(remaining_time_str));
        json_object_object_add(j_status, "serial", json_object_new_string(v_serial));

        // Free allocated memory
        free(v_time);
        free(v_serial);
    } else {
        // Use pre-existing values
        snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", tmac->remaining_time);
        json_object_object_add(j_status, "remaining_time", json_object_new_string(remaining_time_str));

        json_object_object_add(j_status, "serial", json_object_new_string(tmac->serial));
    }
}

static void 
add_not_found_status(json_object *j_status, const char *mac, const char *ip, const char *gw_mac, const char *gw_address)
{
    json_object_object_add(j_status, "gw_mac", json_object_new_string(gw_mac));
    json_object_object_add(j_status, "c_mac", json_object_new_string(mac));
    json_object_object_add(j_status, "c_ip", json_object_new_string(ip));
    json_object_object_add(j_status, "gw_ip", json_object_new_string(gw_address));
    json_object_object_add(j_status, "release", json_object_new_string("0"));
}

char *
query_bypass_user_status(const char *key, const char *gw_mac, const char *gw_address, query_choice_t choice)
{
    if (!key || !gw_mac || !gw_address) {
        return NULL;
    }

    if ((choice == QUERY_BY_IP && !is_valid_ip(key)) || 
        (choice == QUERY_BY_MAC && !is_valid_mac(key))) {
        return NULL;
    }

    s_config *config = config_get_config();
    json_object *j_status = json_object_new_object();
    int found = 0;

    LOCK_CONFIG();

    t_trusted_mac *tmac = config->trustedmaclist;
    while (tmac) {
        if ((choice == QUERY_BY_MAC && strcmp(tmac->mac, key) == 0) ||
            (choice == QUERY_BY_IP && tmac->ip && strcmp(tmac->ip, key) == 0)) {
            
            if (!tmac->ip && choice == QUERY_BY_MAC) {
                tmac->ip = get_user_ip_by_mac(key);
                if (!tmac->ip) tmac->ip = safe_strdup("unknown");
            } else if (!tmac->mac && choice == QUERY_BY_IP) {
                tmac->mac = get_user_mac_by_ip(key);
                if (!tmac->mac) tmac->mac = safe_strdup("unknown");
            }
            
            add_user_status_to_json(j_status, tmac, gw_mac, gw_address);
            found = 1;
            break;
        }
        tmac = tmac->next;
    }

    UNLOCK_CONFIG();

    if (!found) {
        if (choice == QUERY_BY_MAC) {
            char *ip = get_user_ip_by_mac(key);
            if (!ip) ip = safe_strdup("unknown");
            add_not_found_status(j_status, key, ip, gw_mac, gw_address);
            free(ip);
        } else {
            char *mac = get_user_mac_by_ip(key);
            if (!mac) mac = safe_strdup("unknown");
            add_not_found_status(j_status, mac, key, gw_mac, gw_address);
            free(mac);
        }
    }

    const char *json_str = json_object_to_json_string(j_status);
    char *res = safe_strdup(json_str);
    
    json_object_put(j_status);
    
    return res;
}
