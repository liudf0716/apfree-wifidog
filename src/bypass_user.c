
#include <json-c/json.h>

#include "common.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"
#include "util.h"
#include "firewall.h"
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
            fw_del_trusted_mac(mac);
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
add_mac_from_list(const char *mac, const uint16_t remaining_time, const char *serial, mac_choice_t which)
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
			config->trustedmaclist->remaining_time = remaining_time?remaining_time:UINT16_MAX;
			config->trustedmaclist->serial = serial?safe_strdup(serial):NULL;
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
		p->remaining_time = remaining_time?remaining_time:UINT16_MAX;
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
add_bypass_user(const char *mac, const uint16_t remaining_time, const char *serial)
{
	if (mac == NULL || !is_valid_mac(mac) || serial == NULL) {
		return false;
	}
	if (add_mac_from_list(mac, remaining_time, serial, TRUSTED_MAC) == NULL) {
		return false;
	}

	return true;
}

bool
remove_bypass_user(const char *mac)
{
	if (mac == NULL || !is_valid_mac(mac)) {
		return false;
	}
	
	remove_mac_from_list(mac, TRUSTED_MAC);
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

static void
add_user_status_to_json(json_object *j_status, const t_trusted_mac *tmac, 
                        const char *gw_mac, const char *gw_address)
{
    char remaining_time_str[32] = {0};
    
    json_object_object_add(j_status, "gw mac", json_object_new_string(gw_mac));
    json_object_object_add(j_status, "c mac", json_object_new_string(tmac->mac));
    json_object_object_add(j_status, "c ip", json_object_new_string(tmac->ip));
    json_object_object_add(j_status, "gw ip", json_object_new_string(gw_address));
    json_object_object_add(j_status, "release", json_object_new_string("1"));
    snprintf(remaining_time_str, sizeof(remaining_time_str), "%d", tmac->remaining_time);
    json_object_object_add(j_status, "remaining time", json_object_new_string(remaining_time_str));
    json_object_object_add(j_status, "serial", json_object_new_string(tmac->serial ? tmac->serial : ""));
}

static void 
add_not_found_status(json_object *j_status, const char *mac, const char *ip, const char *gw_mac, const char *gw_address)
{
    json_object_object_add(j_status, "gw mac", json_object_new_string(gw_mac));
    json_object_object_add(j_status, "c mac", json_object_new_string(mac));
    json_object_object_add(j_status, "c ip", json_object_new_string(ip));
    json_object_object_add(j_status, "gw ip", json_object_new_string(gw_address));
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
            add_not_found_status(j_status, key, ip, gw_mac, gw_address);
            free(ip);
        } else {
            char *mac = get_user_mac_by_ip(key);
            add_not_found_status(j_status, mac, key, gw_mac, gw_address);
            free(mac);
        }
    }

    const char *json_str = json_object_to_json_string(j_status);
    char *res = safe_strdup(json_str);
    
    json_object_put(j_status);
    
    return res;
}
