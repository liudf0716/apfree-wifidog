
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>

#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>

#include <json-c/json.h>

#include <dirent.h>
#include <linux/if_bridge.h>

#include "wd_util.h"
#include "gateway.h"
#include "commandline.h"
#include "client_list.h"
#include "ping_thread.h"
#include "conf.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "firewall.h"
#include "version.h"

#define LOCK_GHBN() do { \
	debug(LOG_DEBUG, "Locking wd_gethostbyname()"); \
	pthread_mutex_lock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() locked"); \
} while (0)

#define UNLOCK_GHBN() do { \
	debug(LOG_DEBUG, "Unlocking wd_gethostbyname()"); \
	pthread_mutex_unlock(&ghbn_mutex); \
	debug(LOG_DEBUG, "wd_gethostbyname() unlocked"); \
} while (0)

#ifdef __ANDROID__
#define WD_SHELL_PATH "/system/bin/sh"
#else
#define WD_SHELL_PATH "/bin/sh"
#endif

extern time_t started_time;

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long served_this_session = 0;

/** @brief Mutex to protect gethostbyname since not reentrant */
static pthread_mutex_t ghbn_mutex = PTHREAD_MUTEX_INITIALIZER;

struct evdns_cb_param {
	struct event_base	*base;
	void	*data;
};

void
mark_online()
{
    int before = is_online();
    time(&last_online_time);
    int after = is_online();        /* XXX is_online() looks at last_online_time... */
	
    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

void
mark_offline_time() 
{
    int before = is_online();
    time(&last_offline_time);
    int after = is_online();
	
    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }
}
 
void
mark_offline()
{
    int before = is_online();
    time(&last_offline_time);
    int after = is_online();
		  
    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If we're offline it definately means the auth server is offline */
    mark_auth_offline();

}

int
is_online()
{
    if (last_online_time == 0 || (last_offline_time - last_online_time) >= (config_get_config()->checkinterval * 2 - 10)) {
        /* We're probably offline */
        return (0);
    } else {
        /* We're probably online */
        return (1);
    }
}

void
mark_auth_online()
{
    int before = is_auth_online();
    time(&last_auth_online_time);
    int after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If auth server is online it means we're definately online */
    mark_online();

}

void
mark_auth_offline()
{
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_offline_time);
    after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

int
is_auth_online()
{
	s_config *config = config_get_config();
	if (config->auth_server_mode == AUTH_MODE_LOCAL) {
		debug(LOG_DEBUG, "Auth server is in local mode, always returning online");
		return 1;
	}

	if (!is_online()) {
        /* If we're not online auth is definately not online :) */
        return (0);
    } else if ((last_auth_online_time == 0) || 
			   (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* Auth is  probably offline */
        return (0);
    } else {
        /* Auth is probably online */
        return (1);
    }
}

char *
mqtt_get_status_text()
{
	time_t uptime = 0;
	unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
	struct json_object *jstatus = json_object_new_object();
	struct sys_info info;
	memset(&info, 0, sizeof(info));
		
	get_sys_info(&info);

	json_object_object_add(jstatus, "sys_uptime", json_object_new_int(info.sys_uptime));
	json_object_object_add(jstatus, "sys_memfree", json_object_new_int(info.sys_memfree));
	json_object_object_add(jstatus, "nf_conntrack_count", json_object_new_int(info.nf_conntrack_count));
	json_object_object_add(jstatus, "cpu_usage", json_object_new_double(info.cpu_usage));
	json_object_object_add(jstatus, "sys_load", json_object_new_double(info.sys_load));
	json_object_object_add(jstatus, "boad_type", 
	json_object_new_string(g_type?g_type:"null"));
	json_object_object_add(jstatus, "boad_name", 
	json_object_new_string(g_name?g_name:"null"));

	uptime = time(NULL) - started_time;
	days = (unsigned int)uptime / (24 * 60 * 60);
	uptime -= days * (24 * 60 * 60);
	hours = (unsigned int)uptime / (60 * 60);
	uptime -= hours * (60 * 60);
	minutes = (unsigned int)uptime / 60;
	uptime -= minutes * 60;
	seconds = (unsigned int)uptime;
	char wifidog_uptime[128] = {0};
	snprintf(wifidog_uptime, 128, "%dD %dH %dM %dS", days, hours, minutes, seconds);

	json_object_object_add(jstatus, "wifidog_version", json_object_new_string(VERSION));
	json_object_object_add(jstatus, "wifidog_uptime", json_object_new_string(wifidog_uptime));
	json_object_object_add(jstatus, "auth_server", json_object_new_int(is_auth_online()));
    
	t_client *sublist = NULL, *current = NULL;

	LOCK_CLIENT_LIST();
	int count = client_list_dup(&sublist);
	UNLOCK_CLIENT_LIST();
	json_object_object_add(jstatus, "online_client_count", json_object_new_int(count));

	current = sublist;

	int active_count = 0;
	struct json_object *jclients = NULL;
	while (current != NULL) {
		if (!jclients)
			jclients = json_object_new_array();
		struct json_object *jclient = json_object_new_object();
		json_object_object_add(jclient, "status", json_object_new_int(current->is_online));
		json_object_object_add(jclient, "ip", json_object_new_string(current->ip));
		json_object_object_add(jclient, "mac", json_object_new_string(current->mac));
		json_object_object_add(jclient, "token", json_object_new_string(current->token));
		json_object_object_add(jclient, "name", 
			json_object_new_string(current->name != NULL?current->name:"null"));
		json_object_object_add(jclient, "first_login", json_object_new_int64(current->first_login));
		json_object_object_add(jclient, "downloaded", 
			json_object_new_int64(current->counters.incoming));
		json_object_object_add(jclient, "uploaded",
			json_object_new_int64(current->counters.outgoing));

		json_object_array_add(jclients, jclient);

		if(current->is_online)
			active_count++;
		current = current->next;
	}

	client_list_destroy(sublist);
	if (jclients)
		json_object_object_add(jstatus, "clients", jclients);

	json_object_object_add(jstatus, "active_client_count", json_object_new_int(active_count));
	char *retStr = safe_strdup(json_object_to_json_string(jstatus));
	json_object_put(jstatus);
	return retStr;
}

/**
 * @brief Generates a detailed status report of the apfree wifidog system
 * 
 * This function creates a comprehensive text report including:
 * - WiFiDog version
 * - System uptime
 * - Restart status
 * - Internet and auth server connectivity status
 * - Number of clients served
 * - Currently connected clients with their details:
 *   - IP and MAC addresses
 *   - Authentication tokens
 *   - Login times
 *   - Data transfer statistics
 * - Offline client information
 * - Trusted MAC addresses
 * - Authentication server details
 *
 * The status information is built using an evbuffer and converted to a string.
 *
 * @return A dynamically allocated string containing the status report.
 *         The caller is responsible for freeing this memory.
 * @note The returned string must be freed by the caller using free()
 */
/*
 * @return A string containing human-readable status text. MUST BE free()d by caller
 */
char *
get_status_text()
{
	struct evbuffer *evb = evbuffer_new();
	s_config *config;
	t_auth_serv *auth_server;
	t_client *sublist, *current;
	int count, active_count;
	time_t uptime = 0;
	unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
	t_trusted_mac *p;
	t_offline_client *oc_list;
	char *status_text;

	evbuffer_add_printf(evb, "apfree wifidog status\n\n");

	uptime = time(NULL) - started_time;
	days = (unsigned int)uptime / (24 * 60 * 60);
	uptime -= days * (24 * 60 * 60);
	hours = (unsigned int)uptime / (60 * 60);
	uptime -= hours * (60 * 60);
	minutes = (unsigned int)uptime / 60;
	uptime -= minutes * 60;
	seconds = (unsigned int)uptime;

	evbuffer_add_printf(evb, "Version: " VERSION "\n");
	evbuffer_add_printf(evb, "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
	evbuffer_add_printf(evb, "Has been restarted: %s%s%d%s\n", 
		restart_orig_pid ? "yes (from PID " : "no",
		restart_orig_pid ? "" : "",
		restart_orig_pid,
		restart_orig_pid ? ")" : "");

	evbuffer_add_printf(evb, "Internet Connectivity: %s\n", (is_online()? "yes" : "no"));
	evbuffer_add_printf(evb, "Auth server reachable: %s\n", (is_auth_online()? "yes" : "no"));
	evbuffer_add_printf(evb, "Clients served this session: %lu\n\n", served_this_session);

	LOCK_CLIENT_LIST();
	count = client_list_dup(&sublist);
	UNLOCK_CLIENT_LIST();

	current = sublist;
	evbuffer_add_printf(evb, "%d clients connected.\n", count);

	count = 1;
	active_count = 0;
	while (current != NULL) {
		evbuffer_add_printf(evb, "\nClient %d status [%d]\n", count, current->is_online);
		evbuffer_add_printf(evb, "  IP: %s MAC: %s\n", current->ip, current->mac);
		evbuffer_add_printf(evb, "  Token: %s\n", current->token);
		evbuffer_add_printf(evb, "  First Login: %lld\n", (long long)current->first_login);
		evbuffer_add_printf(evb, "  Online Time: %lld\n", (long long)(time(NULL) - current->first_login));
		evbuffer_add_printf(evb, "  Name: %s\n", current->name != NULL?current->name:"null");
		evbuffer_add_printf(evb, "  Downloaded: %llu\n  Uploaded: %llu\n", 
			current->counters.incoming, current->counters.outgoing);
		count++;
		if(current->is_online)
			active_count++;
		current = current->next;
	}

	client_list_destroy(sublist);

	evbuffer_add_printf(evb, "%d client %d active.\n", count-1, active_count);

	LOCK_OFFLINE_CLIENT_LIST();
	evbuffer_add_printf(evb, "%d clients unconnected.\n", offline_client_number());
	oc_list = client_get_first_offline_client();
	while(oc_list != NULL) {    
		evbuffer_add_printf(evb, "  IP: %s MAC: %s Last Login: %lld Hit Counts: %d Client Type: %d Temp Passed: %d\n", 
			oc_list->ip, oc_list->mac, (long long)oc_list->last_login,
			oc_list->hit_counts, oc_list->client_type, oc_list->temp_passed);
		oc_list = oc_list->next;
	}
	UNLOCK_OFFLINE_CLIENT_LIST();

	config = config_get_config();

	LOCK_CONFIG();

	if (config->trustedmaclist != NULL) {
		evbuffer_add_printf(evb, "\nTrusted MAC addresses:\n");
		for (p = config->trustedmaclist; p != NULL; p = p->next) {
			evbuffer_add_printf(evb, "  %s\n", p->mac);
		}
	}

	evbuffer_add_printf(evb, "\nAuthentication servers:\n");
	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		evbuffer_add_printf(evb, "  Host: %s (%s)\n", 
			auth_server->authserv_hostname, auth_server->last_ip);
	}

	UNLOCK_CONFIG();

	status_text = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return status_text;
}

char *
get_client_status_json()
{
	struct json_object *jstatus = json_object_new_object();
	t_client *sublist = NULL, *current = NULL;
	int count = 0, active_count = 0;

	LOCK_CLIENT_LIST();
	count = client_list_dup(&sublist);
	UNLOCK_CLIENT_LIST();

	current = sublist;
	struct json_object *jclients = NULL;
	while (current != NULL) {
		if (!jclients)
			jclients = json_object_new_array();
		struct json_object *jclient = json_object_new_object();
		json_object_object_add(jclient, "status", json_object_new_int(current->is_online));
		json_object_object_add(jclient, "ip", json_object_new_string(current->ip));
		json_object_object_add(jclient, "mac", json_object_new_string(current->mac));
		json_object_object_add(jclient, "token", json_object_new_string(current->token));
		json_object_object_add(jclient, "name", 
			json_object_new_string(current->name != NULL?current->name:"null"));
		json_object_object_add(jclient, "first_login", json_object_new_int64(current->first_login));
		json_object_object_add(jclient, "online_time", 
			json_object_new_int64(time(NULL) - current->first_login));
		json_object_object_add(jclient, "downloaded", 
			json_object_new_int64(current->counters.incoming));
		json_object_object_add(jclient, "uploaded",
			json_object_new_int64(current->counters.outgoing));

		json_object_array_add(jclients, jclient);

		if(current->is_online)
			active_count++;
		current = current->next;
	}

	client_list_destroy(sublist);
	if (jclients)
		json_object_object_add(jstatus, "clients", jclients);

	json_object_object_add(jstatus, "online_client_count", json_object_new_int(count));
	json_object_object_add(jstatus, "active_client_count", json_object_new_int(active_count));
	char *retStr = safe_strdup(json_object_to_json_string(jstatus));
	json_object_put(jstatus);
	return retStr;
}

char *
get_auth_status_json()
{
	struct json_object *jstatus = json_object_new_object();
	t_auth_serv *auth_server;
	s_config *config = config_get_config();

	json_object_object_add(jstatus, "auth_online", json_object_new_int(is_auth_online()));

	struct json_object *jauth_servers = json_object_new_array();
	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		struct json_object *jauth_server = json_object_new_object();
		json_object_object_add(jauth_server, "host", json_object_new_string(auth_server->authserv_hostname));
		json_object_object_add(jauth_server, "ip", json_object_new_string(auth_server->last_ip));
		json_object_array_add(jauth_servers, jauth_server);
	}

	json_object_object_add(jstatus, "auth_servers", jauth_servers);
	char *retStr = safe_strdup(json_object_to_json_string(jstatus));
	json_object_put(jstatus);
	return retStr;
}

char *
get_wifidogx_json()
{
	struct json_object *jstatus = json_object_new_object();
	// wifidogx's uptime
	time_t uptime = time(NULL) - started_time;

	json_object_object_add(jstatus, "uptime", json_object_new_int64(uptime));
	json_object_object_add(jstatus, "is_internet_connected", json_object_new_int(is_online()));
	json_object_object_add(jstatus, "is_auth_server_connected", json_object_new_int(is_auth_online()));
	json_object_object_add(jstatus, "wifidogx_version", json_object_new_string(VERSION));
	json_object_object_add(jstatus, "auth_server_mode", json_object_new_int(config_get_config()->auth_server_mode));

	char *retStr = safe_strdup(json_object_to_json_string(jstatus));
	json_object_put(jstatus);
	return retStr;
}


/**
 * @brief Get serialized string of trusted IP addresses from the iplist domain
 *   
 * This function retrieves the list of trusted IP addresses stored under the special 
 * "iplist" domain in the domain_trusted configuration and serializes them into a 
 * comma-separated string.
 *
 * @return A newly allocated string containing comma-separated IP addresses,
 *         NULL if no IPs are found or on error.
 *         The caller is responsible for freeing the returned string.
 */
char *
get_serialize_iplist()
{
	s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted *iplist = NULL;
	struct evbuffer *evb = NULL;
	int first_ip = 1;

	if (!config || !config->domains_trusted) {
		return NULL;
	}

	LOCK_DOMAIN();

	// Find the special "iplist" domain entry
	for (domain_trusted = config->domains_trusted; 
		 domain_trusted != NULL; 
		 domain_trusted = domain_trusted->next) {
		if (strcmp(domain_trusted->domain, "iplist") == 0) {
			break;
		}
	}

	if (!domain_trusted || !domain_trusted->ips_trusted) {
		UNLOCK_DOMAIN();
		debug(LOG_DEBUG, "No iplist found");
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		UNLOCK_DOMAIN();
		return NULL;
	}

	// Build comma-separated string of IP addresses 
	for (iplist = domain_trusted->ips_trusted; iplist != NULL; iplist = iplist->next) {
		if (first_ip) {
			evbuffer_add_printf(evb, "%s", iplist->ip);
			first_ip = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", iplist->ip);
		}
	}

	UNLOCK_DOMAIN();

	char *retStr = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return retStr;
}

/**
 * @brief Serializes trusted domains into a comma-separated string
 *
 * This function gets the list of trusted domains from the configuration
 * and serializes them into a comma-separated string. It skips the special
 * "iplist" domain entry.
 *
 * @return A newly allocated string containing comma-separated domain names,
 *         NULL if no domains are found or on error.
 *         The caller is responsible for freeing the returned string.
 */
char *
get_serialize_trusted_domains()
{
	s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	struct evbuffer *evb = NULL;
	int first_domain = 1;

	if (!config || !config->domains_trusted) {
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	LOCK_DOMAIN();

	// Build comma-separated string of domain names
	for (domain_trusted = config->domains_trusted; 
		 domain_trusted != NULL; 
		 domain_trusted = domain_trusted->next) {
		
		// Skip special iplist domain
		if (strcmp(domain_trusted->domain, "iplist") == 0) {
			continue;
		}

		if (first_domain) {
			evbuffer_add_printf(evb, "%s", domain_trusted->domain);
			first_domain = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", domain_trusted->domain);
		}
	}

	UNLOCK_DOMAIN();

	char *retStr = evb_2_string(evb, NULL); 
	evbuffer_free(evb);
	return retStr;
}

/**
 * @brief Serialize trusted pan domains into a comma-separated string
 * 
 * This function gets all trusted pan domains from the configuration and 
 * serializes them into a comma-separated string format.
 *
 * @return A newly allocated string containing comma-separated domain names.
 *         NULL if no pan domains exist or on error. 
 *         The caller is responsible for freeing the returned string.
 */
char *
get_serialize_trusted_pan_domains()
{
	s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	struct evbuffer *evb = NULL;
	int first_domain = 1;

	if (!config || !config->pan_domains_trusted) {
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	LOCK_DOMAIN();

	// Build comma-separated string of domain names
	for (domain_trusted = config->pan_domains_trusted; 
		 domain_trusted != NULL; 
		 domain_trusted = domain_trusted->next) {
		
		if (first_domain) {
			evbuffer_add_printf(evb, "%s", domain_trusted->domain);
			first_domain = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", domain_trusted->domain);
		}
	}

	UNLOCK_DOMAIN();

	char *retStr = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return first_domain ? NULL : retStr;
}

/**
 * @brief Get serialized string of trusted pan domains
 *
 * This function retrieves the list of trusted pan domains from the configuration 
 * and serializes them into a comma-separated string format.
 *
 * @return A newly allocated string containing comma-separated domain names,
 *         NULL if no pan domains exist or on error.
 *         The caller is responsible for freeing the returned string.
 */
char *
mqtt_get_trusted_pan_domains_text()
{
	s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	struct evbuffer *evb = NULL;
	int first = 1;

	if (!config || !config->pan_domains_trusted) {
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	LOCK_DOMAIN();

	// Build comma-separated string of domain names
	for (domain_trusted = config->pan_domains_trusted; 
		 domain_trusted != NULL; 
		 domain_trusted = domain_trusted->next) {
		
		if (first) {
			evbuffer_add_printf(evb, "%s", domain_trusted->domain);
			first = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", domain_trusted->domain);
		}
	}

	UNLOCK_DOMAIN();

	char *retStr = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return first ? NULL : retStr;
}

/**
 * @brief Get JSON formatted string containing trusted domains and their IP addresses
 * 
 * This function retrieves all trusted domains and their associated IP addresses from
 * the configuration and formats them as a JSON array. Each domain is represented as
 * an object with the domain name as key and comma-separated IP list as value.
 *
 * @return A newly allocated string containing the JSON array, or NULL if no trusted
 *         domains exist. The caller must free this string.
 */
char *
mqtt_get_trusted_domains_text()
{
	s_config *config = config_get_config();
	if (config->domains_trusted == NULL)
		return NULL;

	struct json_object *jarray = json_object_new_array();
	
	LOCK_DOMAIN();
	
	for (t_domain_trusted *domain = config->domains_trusted; domain != NULL; domain = domain->next) {
		struct evbuffer *evb = evbuffer_new();
		int first = 1;
		struct json_object *jobj = json_object_new_object();
		
		// Build comma-separated IP list
		for (t_ip_trusted *ip = domain->ips_trusted; ip != NULL; ip = ip->next) {
			if (first) {
				evbuffer_add_printf(evb, "%s", ip->ip);
				first = 0;
			} else {
				evbuffer_add_printf(evb, ",%s", ip->ip);
			}
		}

		// Get IP list as string
		char *iplist = evb_2_string(evb, NULL);
		evbuffer_free(evb);

		// Add domain and its IPs to JSON object
		json_object_object_add(jobj, domain->domain, 
			json_object_new_string(first ? "NULL" : iplist));
		json_object_array_add(jarray, jobj);
		
		if (iplist)
			free(iplist);
	}
	
	UNLOCK_DOMAIN();

	char *retStr = safe_strdup(json_object_to_json_string(jarray));
	json_object_put(jarray);

	return retStr;
}

/**
 * @brief Get JSON formatted string containing IP addresses from the iplist domain
 * 
 * This function looks for a special domain named "iplist" in the trusted domains
 * configuration and returns its IP addresses as a JSON array with a single object.
 * The IPs are formatted as a comma-separated string.
 *
 * @return A newly allocated string containing the JSON array, or NULL if no iplist
 *         domain exists. The caller must free this string.
 */
char *
mqtt_get_trusted_iplist_text()
{
	s_config *config = config_get_config();
	if (config->domains_trusted == NULL)
		return NULL;

	t_domain_trusted *domain = NULL;
	
	LOCK_DOMAIN();
	
	// Find the special "iplist" domain
	for (domain = config->domains_trusted; 
		 domain != NULL && strcmp(domain->domain, "iplist") != 0; 
		 domain = domain->next);

	if (domain == NULL) {
		UNLOCK_DOMAIN();
		return NULL;
	}

	struct evbuffer *evb = evbuffer_new();
	int first = 1;

	// Build comma-separated IP list
	for (t_ip_trusted *ip = domain->ips_trusted; ip != NULL; ip = ip->next) {
		if (first) {
			evbuffer_add_printf(evb, "%s", ip->ip);
			first = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", ip->ip);
		}
	}

	// Create JSON structure
	char *iplist = evb_2_string(evb, NULL);
	struct json_object *jobj = json_object_new_object();
	struct json_object *jarray = json_object_new_array();
	json_object_object_add(jobj, domain->domain,
		json_object_new_string(first ? "NULL" : iplist));
	json_object_array_add(jarray, jobj);

	evbuffer_free(evb);
	if (iplist)
		free(iplist);

	UNLOCK_DOMAIN();

	char *retStr = safe_strdup(json_object_to_json_string(jarray));
	json_object_put(jarray);

	return retStr;
}

/**
 * @brief Get a formatted text representation of trusted domains and their IP addresses
 *
 * This function retrieves the list of trusted domains from the configuration and
 * formats them as a text string. For each domain, it includes:
 * - The domain name
 * - All associated IP addresses
 *
 * The output is formatted with newlines and indentation for readability.
 *
 * @return Newly allocated string containing the formatted domains and IPs.
 *         Must be freed by caller using free().
 *         Returns NULL if no trusted domains exist or on memory allocation failure.
 */
char *
get_trusted_domains_text(void)
{
	struct evbuffer *evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	s_config *config = config_get_config();
	if (!config || !config->domains_trusted) {
		evbuffer_free(evb);
		return NULL;
	}

	t_domain_trusted *domain_trusted;
	t_ip_trusted *ip_trusted;

	evbuffer_add_printf(evb, "\nTrusted domains and its ip:\n");

	LOCK_DOMAIN();

	for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		evbuffer_add_printf(evb, "\nDomain: %s\n", domain_trusted->domain);
		
		for (ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
			evbuffer_add_printf(evb, "  %s\n", ip_trusted->ip);
		}
	}

	UNLOCK_DOMAIN();

	char *result = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return result;
}

/**
 * @brief Gets a text representation of trusted pan domains and their IP addresses
 *
 * This function formats a string containing all trusted pan (wildcard) domains 
 * and their associated IP addresses from the configuration. For each domain:
 * - Lists the domain name
 * - If the domain has associated IPs, lists each IP address indented
 * - Otherwise just shows the domain name
 * 
 * The output is formatted with newlines and indentation for readability.
 *
 * @return A newly allocated string containing the formatted domains and IPs.
 *         Must be freed by caller using free().
 *         Returns NULL if no trusted pan domains exist or on memory allocation failure.
 */
char *
get_trusted_pan_domains_text(void)
{
	struct evbuffer *evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	s_config *config = config_get_config();
	if (!config || !config->pan_domains_trusted) {
		evbuffer_free(evb);
		return NULL;
	}

	evbuffer_add_printf(evb, "\nTrusted wildcard domains:\n");

	LOCK_DOMAIN();

	t_domain_trusted *domain_trusted;
	for (domain_trusted = config->pan_domains_trusted; 
		 domain_trusted != NULL; 
		 domain_trusted = domain_trusted->next) {
		
		evbuffer_add_printf(evb, " %s ", domain_trusted->domain);
		
		t_ip_trusted *ip_trusted = domain_trusted->ips_trusted;
		if (ip_trusted) {
			evbuffer_add_printf(evb, "with ip:\n");
			for (; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
				char ip[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, &ip_trusted->uip, ip, INET_ADDRSTRLEN);
				evbuffer_add_printf(evb, "  %s\n", ip);
			}
		} else {
			evbuffer_add_printf(evb, "\n");
		}
	}

	UNLOCK_DOMAIN();

	char *result = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return result;
}

/**
 * @brief Get serialized MAC address list for MQTT messaging
 * 
 * @param which Type of MAC list to serialize (TRUSTED_MAC, UNTRUSTED_MAC, etc)
 * @return Newly allocated string containing comma-separated MAC addresses,
 *         NULL if list is empty. Caller must free the returned string.
 */
char *
mqtt_get_serialize_maclist(int which) 
{
	return get_serialize_maclist(which);
}

/**
 * @brief Serialize a MAC address list into a comma-separated string
 *
 * This function takes a type of MAC list (trusted, untrusted, etc) and
 * creates a comma-separated string of all MAC addresses in that list.
 * Used for exporting MAC lists in a compact format.
 *
 * @param which Type of MAC list to serialize:
 *        TRUSTED_MAC - Global trusted MAC list
 *        UNTRUSTED_MAC - MAC blacklist
 *        TRUSTED_LOCAL_MAC - Local network trusted MACs  
 *        ROAM_MAC - Roaming MAC addresses
 * @return Newly allocated string with comma-separated MACs, NULL if list empty
 *         Caller must free the returned string
 */
char * 
get_serialize_maclist(int which)
{
	s_config *config = config_get_config();
	t_trusted_mac *maclist = NULL;
	struct evbuffer *evb = NULL;
	char *retstr = NULL;
	int first = 1;

	// Get the requested MAC list
	switch(which) {
		case TRUSTED_MAC:
			maclist = config->trustedmaclist;
			break; 
		case UNTRUSTED_MAC:
			maclist = config->mac_blacklist;
			break;
		case TRUSTED_LOCAL_MAC:
			maclist = config->trusted_local_maclist;
			break;
		case ROAM_MAC:
			maclist = config->roam_maclist;
			break;
		default:
			return NULL;
	}

	if (!maclist) {
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	LOCK_CONFIG();

	// Build comma-separated list
	while (maclist) {
		if (first) {
			evbuffer_add_printf(evb, "%s", maclist->mac);
			first = 0;
		} else {
			evbuffer_add_printf(evb, ",%s", maclist->mac);
		}
		maclist = maclist->next;
	}

	UNLOCK_CONFIG();

	if (!first) { // If we added any MACs
		retstr = evb_2_string(evb, NULL);
	}

	evbuffer_free(evb);
	return retstr;
}

/**
 * @brief Get formatted text representation of a MAC address list
 *
 * This function generates a human-readable text report of the requested MAC list type.
 * The output includes a header identifying the list type and the MAC addresses
 * formatted in columns.
 *
 * @param which Type of MAC list to display:
 *        TRUSTED_MAC - Global trusted MAC list
 *        UNTRUSTED_MAC - MAC blacklist  
 *        TRUSTED_LOCAL_MAC - Local network trusted MACs
 *        ROAM_MAC - Roaming MAC addresses
 * @return Newly allocated string containing the formatted text,
 *         NULL if list is empty. Caller must free the returned string.
 */
static char *
get_maclist_text(int which)
{
	s_config *config = config_get_config();
	t_trusted_mac *maclist = NULL;
	struct evbuffer *evb = NULL;
	char *header = NULL;
	int count = 0;

	// Set header and get MAC list based on type
	switch(which) {
		case TRUSTED_MAC:
			header = "\nTrusted mac list:\n";
			maclist = config->trustedmaclist;
			break;
		case UNTRUSTED_MAC:
			header = "\nUntrusted mac list:\n";
			maclist = config->mac_blacklist;
			break;
		case TRUSTED_LOCAL_MAC:
			header = "\nTrusted local mac list:\n";
			maclist = config->trusted_local_maclist;
			break;
		case ROAM_MAC:
			header = "\nRoam mac list:\n";
			maclist = config->roam_maclist;
			break;
		default:
			return NULL;
	}

	if (!maclist) {
		return NULL;
	}

	evb = evbuffer_new();
	if (!evb) {
		return NULL;
	}

	evbuffer_add_printf(evb, "%s", header);

	LOCK_CONFIG();

	// Format MAC addresses in columns of 4
	while (maclist) {
		evbuffer_add_printf(evb, " %s ", maclist->mac);
		count++;
		if (count == 4) {
			evbuffer_add_printf(evb, "\n");
			count = 0;
		}
		maclist = maclist->next;
	}

	// Add final newline if needed
	if (count != 0) {
		evbuffer_add_printf(evb, "\n");
	}

	UNLOCK_CONFIG();

	char *retstr = evb_2_string(evb, NULL);
	evbuffer_free(evb);
	return retstr;
}

char *
get_roam_maclist_text()
{
	return get_maclist_text(ROAM_MAC);
}

char *
get_trusted_maclist_text()
{
	return get_maclist_text(TRUSTED_MAC);
}

char *
get_trusted_local_maclist_text()
{
	return get_maclist_text(TRUSTED_LOCAL_MAC);
}

char *
get_untrusted_maclist_text()
{
	return get_maclist_text(UNTRUSTED_MAC);
}

void
trim_newline(char *line)
{
	if(line&&line[strlen(line)-1] == '\n')
		line[strlen(line)-1] = '\0';
}

static int 
get_portno(const char *brname, const char *ifname)
{
#define MAX_PORTS	1024
    int i;
    int ifindex = if_nametoindex(ifname);
    int ifindices[MAX_PORTS];
    unsigned long args[4] = { BRCTL_GET_PORT_LIST,
                  (unsigned long)ifindices, MAX_PORTS, 0 };
    struct ifreq ifr;
    int br_socket_fd = -1;

    if (ifindex <= 0)
        goto error;

    if ((br_socket_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
    	goto error;

    memset(ifindices, 0, sizeof(ifindices));
    strncpy(ifr.ifr_name, brname, IFNAMSIZ);
    ifr.ifr_data = (char *) &args;

    if (ioctl(br_socket_fd, SIOCDEVPRIVATE, &ifr) < 0) {
        goto error;
    }

    close(br_socket_fd);
    
    for (i = 0; i < MAX_PORTS; i++) {
        if (ifindices[i] == ifindex)
            return i;
    }

    debug(LOG_INFO, "%s is not a in bridge %s\n", ifname, brname);
 error:
 	if (br_socket_fd > 0) close(br_socket_fd);
    return -1;
}

/*
 * 1: wired; 0: not wired
 */
static int
is_br_port_no_wired(const char *brname, int port_no)
{
	int i, count;
    struct dirent **namelist;
    char path[SYSFS_PATH_MAX] = {0};
    int nret = 0;
	
    snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brif", brname);
    count = scandir(path, &namelist, 0, alphasort);
    if (count < 0) {
    	debug(LOG_ERR, "cant scandir %s", path);
		return nret;
    }
	
	for (i = 0; i < count; i++) {
        if (namelist[i]->d_name[0] == '.'
            && (namelist[i]->d_name[1] == '\0'
            || (namelist[i]->d_name[1] == '.'
                && namelist[i]->d_name[2] == '\0')))
            continue;

        if (!memcmp(namelist[i]->d_name, "eth", 3) && 
			port_no == get_portno(brname, namelist[i]->d_name)) {
			nret = 1;
			break;
		}
    }
    for (i = 0; i < count; i++)
        free(namelist[i]);
    free(namelist);
	
	return nret;
}

// if -1; not find mac; else find mac's port_no
static int 
br_read_fdb(const char *bridge, 
        unsigned long offset, int num, const uint8_t *mac_addr, int *port_no)
{
    FILE *f;
    int i, n = 0;
    struct __fdb_entry fe[num];
    char path[SYSFS_PATH_MAX] = {0};

    /* open /sys/class/net/brXXX/brforward */
    snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brforward", bridge);
    f = fopen(path, "r");
    if (f) {
        fseek(f, offset*sizeof(struct __fdb_entry), SEEK_SET);
        n = fread(fe, sizeof(struct __fdb_entry), num, f);
        fclose(f);
    } 

    for (i = 0; i < n; i++) {
    	const struct __fdb_entry *f = &fe[i];
    	debug(LOG_DEBUG, "[%d] %02X:%02X:%02X:%02X:%02X:%02X == %02X:%02X:%02X:%02X:%02X:%02X", i,
				mac_addr[0], mac_addr[1], mac_addr[2], 
			  	mac_addr[3], mac_addr[4], mac_addr[5],
			  	f->mac_addr[0], f->mac_addr[1], f->mac_addr[2], 
			  	f->mac_addr[3], f->mac_addr[4], f->mac_addr[5]);
		if (!memcmp(mac_addr, f->mac_addr, 6)) {
			*port_no = f->port_no;
			return -1;
		}
    }

    return n;
}

static int
mac_str_2_byte(const char *mac, uint8_t *mac_addr)
{
	if( 6 == sscanf( mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	    			&mac_addr[0], &mac_addr[1], 
	    			&mac_addr[2], &mac_addr[3], 
	    			&mac_addr[4], &mac_addr[5] )) {
	    return 0;
	} else{
		debug(LOG_INFO, "mac %s to byte array failed", mac);
		return 1;
	}
}

/*
 * -1: error; >0: sucess
 */
static int
get_device_br_port_no(const char *mac, const char *bridge)
{
#define	CHUNK	128
	uint8_t mac_addr[6] = {0};
	
	if (mac_str_2_byte(mac, mac_addr))
		return -1;

    int offset = 0;	
    int port_no = -1;
	for (;;) {
        port_no = -1;
        int n = br_read_fdb(bridge, offset, CHUNK, mac_addr, &port_no);
        if (port_no > 0) {
            break;
        }

        if (n <= 0) {       
           	break;
        }

        offset += n;
	}

	return port_no;
}

/*
 * 1: wired; 0: wireless
 */
int
is_device_wired_intern(const char *mac, const char *bridge)
{
	int port_no = 0;
	if ((port_no = get_device_br_port_no(mac, bridge)) > 0) {	
		return is_br_port_no_wired(bridge, port_no);
	} 

	debug(LOG_INFO, "can not find mac %s port_no", mac);
	return 0;
}

/*
 * 1: wired; 0: wireless
 */
int
br_is_device_wired(const char *mac){
	if (is_valid_mac(mac)) {
		t_gateway_setting *gw = get_gateway_settings();
		while (gw) {
			if (is_device_wired_intern(mac, gw->gw_interface)) {
				debug(LOG_DEBUG,"mac %s check in bridge %s is wired", mac, gw->gw_interface);
				return 1;
			}
			gw = gw->next;
		}
	}

	return 0;
}

/*
 * val can be ip or domain
 * 1: is online; 0: is unreachable
 */
int
is_device_online(const char *val)
{
	char cmd[256] = {0};
	FILE *fd = NULL;

	if(val == NULL || strlen(val) < 4)
		return 0;
	
	snprintf(cmd, 256, "/usr/sbin/wdping %s", val);
	if((fd = popen(cmd, "r")) != NULL) {
		char result[4] = {0};
		char *pret = fgets(result, 3, fd);
		pclose(fd);
		if (!pret) return 0;
		if(result[0] == '1')
			return 1;
	}

	return 0;
}

// if olen is not NULL, set it rlen value
char *evb_2_string(struct evbuffer *evb, int *olen) 
{
	int rlen = evbuffer_get_length(evb);
	char *str = (char *)safe_malloc(rlen+1);
	memset(str, 0, rlen+1);
	evbuffer_copyout(evb, str, rlen);
	if (olen)
		*olen = rlen;
	return str;
}

void evdns_add_trusted_domain_ip_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	t_domain_trusted *p = ptr;
	
    if (errcode) {
		debug(LOG_INFO, "parse domain %s , error: %s", p->domain, evutil_gai_strerror(errcode));
		return;
	}
	
	struct evutil_addrinfo *ai;
	char hostname[HTTP_IP_ADDR_LEN];
	for (ai = addr; ai; ai = ai->ai_next) {           
		const char *s = NULL;
		
		memset(hostname, 0, HTTP_IP_ADDR_LEN);
		if (ai->ai_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)ai->ai_addr;
			s = evutil_inet_ntop(AF_INET, &sin->sin_addr, hostname, HTTP_IP_ADDR_LEN);
		} else if (ai->ai_family == AF_INET6) {
			//do nothing
			continue;
		}

		if (!s) {
			continue;
		}

		t_ip_trusted *ipt = NULL;
		debug(LOG_DEBUG, "parse domain (%s) ip (%s)", p->domain, s);
		if(!p->ips_trusted) {
			ipt = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
			memset(ipt, 0, sizeof(t_ip_trusted));
			strncpy(ipt->ip, hostname, HTTP_IP_ADDR_LEN); 
			ipt->next = NULL;
			p->ips_trusted = ipt;
		} else {
			ipt = p->ips_trusted;
			while(ipt) {
				if(strcmp(ipt->ip, hostname) == 0)
					break;
				ipt = ipt->next;
			}

			if(ipt == NULL) {
				ipt = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
				memset(ipt, 0, sizeof(t_ip_trusted));
				strncpy(ipt->ip, hostname, HTTP_IP_ADDR_LEN);
				ipt->next = p->ips_trusted;
				p->ips_trusted = ipt; 
			}
		}
		    
	} 

	if (addr)
		evutil_freeaddrinfo(addr);
}

static void 
thread_evdns_parse_trusted_domain_2_ip(void *arg)
{
	trusted_domain_t which = *(trusted_domain_t *)arg;
	s_config *config = config_get_config();
	t_domain_trusted *p = NULL;
	free(arg);

	if(which == INNER_TRUSTED_DOMAIN)
		p = config->inner_domains_trusted;
	else if (which == USER_TRUSTED_DOMAIN)
		p = config->domains_trusted;
	else 
		return;

	if (!p) {
		debug(LOG_DEBUG, "parsed [%s] domain list is empty", which == INNER_TRUSTED_DOMAIN ? "inner" : "user");
		return;
	}

	struct event_base *base = event_base_new();
    if (!base) {
        return;    
    }
    struct evdns_base *dnsbase = evdns_base_new(base, EVDNS_BASE_DISABLE_WHEN_INACTIVE);
    if (!dnsbase) {
        event_base_free(base);
        return;
    }

	evdns_base_set_option(dnsbase, "timeout", config_get_config()->dns_timeout);
	evdns_base_set_option(dnsbase, "randomize-case", "0");//TurnOff DNS-0x20 encoding
	if (is_openwrt_platform())
		evdns_base_nameserver_ip_add(dnsbase, "127.0.0.1");//LocalDNS
	else
		evdns_base_nameserver_ip_add(dnsbase, "1.1.1.1");//custom DNS

	struct evutil_addrinfo hints;
	LOCK_DOMAIN();
	while(p && p->domain) {		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = EVUTIL_AI_CANONNAME;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		
		// if add domains and delete domain immediately, it will cause core dump
		// don't know how to avoid it, so just ignore it
		// TODO: need to find a better way to avoid it
		evdns_getaddrinfo( dnsbase, p->domain, NULL ,
			  &hints, evdns_add_trusted_domain_ip_cb, p);
		
		p = p->next;
	}
	UNLOCK_DOMAIN();
	
	debug(LOG_INFO, "parse domain end, begin event_loop "); 
	event_base_dispatch(base);	

	// after parse domains' ip, refresh the rule
	if(which == INNER_TRUSTED_DOMAIN)
		fw_refresh_inner_domains_trusted();
	else if (which == USER_TRUSTED_DOMAIN)
		fw_refresh_user_domains_trusted();
	
	
	evdns_base_free(dnsbase, 0);
    event_base_free(base);
}

void 
evdns_parse_trusted_domain_2_ip(trusted_domain_t which)
{ 
	pthread_t tid_evdns_parse;
	trusted_domain_t *type = malloc(sizeof(trusted_domain_t));
	*type = which;
    pthread_create(&tid_evdns_parse, NULL, (void *)thread_evdns_parse_trusted_domain_2_ip, type);
    pthread_detach(tid_evdns_parse);
}

int
uci_del_value(const char *c_filename, const char *section, const char *name)
{
	// TODO
	return 0;
}

int
uci_set_value(const char *c_filename, const char *section, const char *name, const char *value)
{
	// TODO
	return 0;
}

int
uci_get_value(const char *c_filename, const char *name, char *value, int v_len)
{
	// TODO
	return 0;
}

/** Fork a child and execute a shell command, the parent
 * process waits for the child to return and returns the child's exit()
 * value.
 * @return Return code of the command
 */
int
execute(const char *cmd_line, int quiet)
{
    int pid, status, rc;
	sighandler_t old_handler;
 

    const char *new_argv[4];
    new_argv[0] = WD_SHELL_PATH;
    new_argv[1] = "-c";
    new_argv[2] = cmd_line;
    new_argv[3] = NULL;

   	old_handler = signal(SIGCHLD, SIG_DFL);	

    pid = fork();
    if (pid == 0) {             /* for the child process:         */
        /* We don't want to see any errors if quiet flag is on */
        if (quiet)
            close(2);
        if (execvp(WD_SHELL_PATH, (char *const *)new_argv) == -1) { /* execute the command  */
            debug(LOG_ERR, "execvp(): %s", strerror(errno));
        } else {
            debug(LOG_ERR, "execvp() failed");
        }
        exit(1);
    }

    /* for the parent:      */
    debug(LOG_DEBUG, "Waiting for PID %d to exit", pid);
    rc = waitpid(pid, &status, 0);
    debug(LOG_DEBUG, "Process PID %d exited", rc);
 	
	signal(SIGCHLD, old_handler);
   
    if (-1 == rc) {
        debug(LOG_ERR, "waitpid() failed (%s)", strerror(errno));
        return 1; /* waitpid failed. */
    }

    if (WIFEXITED(status)) {
        return (WEXITSTATUS(status));
    } else {
        /* If we get here, child did not exit cleanly. Will return non-zero exit code to caller*/
        debug(LOG_DEBUG, "Child may have been killed.");
        return 1;
    }
}

struct in_addr *
wd_gethostbyname(const char *name)
{
    struct hostent *he = NULL;
    struct in_addr *addr = NULL;
    struct in_addr *in_addr_temp = NULL;

    /* XXX Calling function is reponsible for free() */

    addr = safe_malloc(sizeof(*addr));

    LOCK_GHBN();

    he = gethostbyname(name);

    if (he == NULL) {
        free(addr);
        UNLOCK_GHBN();
        return NULL;
    }

    in_addr_temp = (struct in_addr *)he->h_addr_list[0];
    addr->s_addr = in_addr_temp->s_addr;

    UNLOCK_GHBN();

    return addr;
}

char *
get_iface_ip(const char *ifname)
{
    struct ifreq if_data;
    struct in_addr in;
    char *ip_str;
    int sockd;
    u_int32_t ip;

    /* Create a socket */
    if ((sockd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug(LOG_ERR, "socket(): %s", strerror(errno));
        return NULL;
    }

    /* Get IP of internal interface */
    strncpy(if_data.ifr_name, ifname, 15);
    if_data.ifr_name[15] = '\0';

    /* Get the IP address */
    if (ioctl(sockd, SIOCGIFADDR, &if_data) < 0) {
        debug(LOG_ERR, "ioctl(): SIOCGIFADDR %s", strerror(errno));
        close(sockd);
        return NULL;
    }
    memcpy((void *)&ip, (void *)&if_data.ifr_addr.sa_data + 2, 4);
    in.s_addr = ip;
	
    close(sockd);
	ip_str = safe_malloc(HTTP_IP_ADDR_LEN);
	if(inet_ntop(AF_INET, &in, ip_str, HTTP_IP_ADDR_LEN))
    	return ip_str;
	
	free(ip_str);	
	return NULL;
}

char *
get_iface_ip6(const char *ifname)
{
	struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[INET6_ADDRSTRLEN] = {0};
    char *ip6_address = NULL;

    // Get the list of network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return NULL;
    }

    // Loop through the list of interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        // We only want IPv6 addresses
        if (family == AF_INET6) {
            if (strcmp(ifa->ifa_name, ifname) == 0) {
				void *addr = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
				if (inet_ntop(AF_INET6, addr, host, INET6_ADDRSTRLEN) != NULL) {
					ip6_address = safe_strdup(host);
					break;
				}
			}
        }
    }

    freeifaddrs(ifaddr);
    return ip6_address;
}

char *
get_iface_mac(const char *ifname)
{
    int r, s;
    struct ifreq ifr;
    char *hwaddr, mac[13];

    strncpy(ifr.ifr_name, ifname, 15);
    ifr.ifr_name[15] = '\0';

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == s) {
        debug(LOG_ERR, "get_iface_mac socket: %s", strerror(errno));
        return NULL;
    }

    r = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (r == -1) {
        debug(LOG_ERR, "get_iface_mac ioctl(SIOCGIFHWADDR): %s", strerror(errno));
        close(s);
        return NULL;
    }

    hwaddr = ifr.ifr_hwaddr.sa_data;
    close(s);
    snprintf(mac, sizeof(mac), "%02X%02X%02X%02X%02X%02X",
             hwaddr[0] & 0xFF,
             hwaddr[1] & 0xFF, hwaddr[2] & 0xFF, hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);

    return safe_strdup(mac);
}

char *
get_ext_iface(void)
{
    FILE *input;
    char *device, *gw;
    int i = 1;
    int keep_detecting = 1;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;
    device = (char *)safe_malloc(16);   /* XXX Why 16? */
    gw = (char *)safe_malloc(16);
    debug(LOG_DEBUG, "get_ext_iface(): Autodectecting the external interface from routing table");
    while (keep_detecting) {
        input = fopen("/proc/net/route", "r");
        if (NULL == input) {
            debug(LOG_ERR, "Could not open /proc/net/route (%s).", strerror(errno));
            free(gw);
            free(device);
            return NULL;
        }
        while (!feof(input)) {
            /* XXX scanf(3) is unsafe, risks overrun */
            if ((fscanf(input, "%15s %15s %*s %*s %*s %*s %*s %*s %*s %*s %*s\n", device, gw) == 2)
                && strcmp(gw, "00000000") == 0) {
                free(gw);
                debug(LOG_INFO, "get_ext_iface(): Detected %s as the default interface after trying %d", device, i);
                fclose(input);
                return device;
            }
        }
        fclose(input);
        debug(LOG_ERR,
              "get_ext_iface(): Failed to detect the external interface after try %d (maybe the interface is not up yet?).  Retry limit: %d",
              i, NUM_EXT_INTERFACE_DETECT_RETRY);
        /* Sleep for EXT_INTERFACE_DETECT_RETRY_INTERVAL seconds */
        timeout.tv_sec = time(NULL) + EXT_INTERFACE_DETECT_RETRY_INTERVAL;
        timeout.tv_nsec = 0;
        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);
        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);   /* XXX need to possibly add this thread to termination_handler */
        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
        //for (i=1; i<=NUM_EXT_INTERFACE_DETECT_RETRY; i++) {
        if (NUM_EXT_INTERFACE_DETECT_RETRY != 0 && i > NUM_EXT_INTERFACE_DETECT_RETRY) {
            keep_detecting = 0;
        }
        i++;
    }
    debug(LOG_ERR, "get_ext_iface(): Failed to detect the external interface after %d tries, aborting", i);
    exit(1);                    /* XXX Should this be termination handler? */
    free(device);
    free(gw);
    return NULL;
}

static int 
ndp_get_mac(const char *dev_name, const char *i_ip, char *o_mac) 
{
    int sockfd;
    struct sockaddr_in6 dest;
    struct icmp6_hdr icmp6_hdr;
    struct msghdr msg;
    struct iovec iov;
    char buf[1024] = {0};
    struct in6_addr target_addr;
    struct nd_neighbor_advert *na;
    struct nd_opt_hdr *opt;
    ssize_t len;

    // Create raw socket for ICMPv6
    sockfd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (sockfd < 0) {
		debug(LOG_ERR, "socket(): %s", strerror(errno));
        return 0;
    }

    // Set up destination address
    memset(&dest, 0, sizeof(dest));
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, i_ip, &dest.sin6_addr);

    // Set up ICMPv6 Neighbor Solicitation header
    memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
    icmp6_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    icmp6_hdr.icmp6_code = 0;
    icmp6_hdr.icmp6_cksum = 0;

    // Set up target address
    inet_pton(AF_INET6, i_ip, &target_addr);

    // Set up message header
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dest;
    msg.msg_namelen = sizeof(dest);
    iov.iov_base = &icmp6_hdr;
    iov.iov_len = sizeof(icmp6_hdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // Send Neighbor Solicitation message
    if (sendmsg(sockfd, &msg, 0) < 0) {
		debug(LOG_ERR, "sendmsg(): %s", strerror(errno));
        close(sockfd);
        return 0;
    }

    // Receive Neighbor Advertisement message
    while (1) {
        len = recv(sockfd, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv");
            close(sockfd);
            return 0;
        }

        // Parse Neighbor Advertisement message
        na = (struct nd_neighbor_advert *)(buf + sizeof(struct ip6_hdr));
        if (na->nd_na_hdr.icmp6_type == ND_NEIGHBOR_ADVERT) {
            opt = (struct nd_opt_hdr *)(na + 1);
            if (opt->nd_opt_type == ND_OPT_TARGET_LINKADDR) {
                unsigned char *mac = (unsigned char *)(opt + 1);
                snprintf(o_mac, MAC_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                close(sockfd);
                return 1;
            }
        }
    }

    close(sockfd);
    return 0;
}

/**
 * @brief get client's mac from its ip
 * @return 0 failed or 1 success
 * 
 */ 
int 
arp_get_mac(const char *dev_name, const char *i_ip, char *o_mac) 
{
	int s;
    struct arpreq arpreq;
    struct sockaddr_in *sin;
	
	if (!dev_name || !i_ip || !o_mac)
		return 0;
	
	if (is_valid_ip6(i_ip)) {
		return ndp_get_mac(dev_name, i_ip, o_mac);
	}

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s <= 0) {
		return 0;
	}
	
	memset(&arpreq, 0, sizeof(arpreq));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
	if (is_valid_ip(i_ip)) {
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = inet_addr(i_ip);
	} else {
		close(s);
		return 0;
	}

	strcpy(arpreq.arp_dev, dev_name);
	if (ioctl(s, SIOCGARP, &arpreq) < 0) {
		close(s);
		return 0;
	}
	close(s);
	if (arpreq.arp_flags & ATF_COM) {
        unsigned char *eap = (unsigned char *) &arpreq.arp_ha.sa_data[0];
        snprintf(o_mac, MAC_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x",
                eap[0], eap[1], eap[2], eap[3], eap[4], eap[5]);
        return 1;
    } 
	
	return 0;
}

int
br_arp_get_mac(t_gateway_setting *gw_settings, const char *i_ip, char *o_mac)
{
	if (!gw_settings || !i_ip || !o_mac)
		return 0;

	if (arp_get_mac(gw_settings->gw_interface, i_ip, o_mac))
		return 1;
	return 0;
}

int
get_ifname_by_address(const char *address,  char *ifname)
{
	char command[256] = {0};
	FILE *fp = NULL;

	if (!address || !ifname)
		return 0;

	int is_ipv6 = is_valid_ip6(address);
	if (is_ipv6) {
		snprintf(command, sizeof(command), "ip -6 route get %s | grep dev | awk '{print $6}'", address);
	} else {
		snprintf(command, sizeof(command), "ip route get %s | grep dev | awk '{print $3}'", address);
	}

	fp = popen(command, "r");
	if (!fp) {
		debug(LOG_ERR, "popen(): %s", strerror(errno));
		return 0;
	}

	if (fgets(ifname, IFNAMSIZ, fp) == NULL) {
		pclose(fp);
		return 0;
	}

	trim_newline(ifname);
	pclose(fp);
	return 1;
}

t_gateway_setting *
get_gateway_setting_by_ifname(const char *ifname)
{
	if (!ifname)
		return NULL;

	t_gateway_setting *gw = get_gateway_settings();
	while (gw) {
		if (strcmp(gw->gw_interface, ifname) == 0)
			return gw;
		gw = gw->next;
	}
	return NULL;
}

t_gateway_setting *
get_gateway_setting_by_id(const char *gw_id)
{
	if (!gw_id)
		return NULL;

	t_gateway_setting *gw = get_gateway_settings();
	while (gw) {
		if (strcmp(gw->gw_id, gw_id) == 0)
			return gw;
		gw = gw->next;
	}
	return NULL;
}

static t_gateway_setting *
get_gateway_setting_by_ipv4(const char *ip)
{
	if (!ip)
		return NULL;
	
	// convert ip to uint32_t
	uint32_t ip_int = inet_addr(ip);
	if (ip_int == INADDR_NONE)
		return NULL;
	ip_int = ntohl(ip_int);
	t_gateway_setting *gw = get_gateway_settings();
	while (gw) {
		if ((gw->ip_v4 & gw->mask_v4) == (ip_int & gw->mask_v4))
			return gw;
		gw = gw->next;
	}
	return NULL;
}

static t_gateway_setting *
get_gateway_setting_by_ipv6(const char *ipv6)
{
	if (!ipv6)
		return NULL;

	return get_gateway_settings(); // TODO;
}

t_gateway_setting *
get_gateway_setting_by_addr(const char *addr, int type)
{
	if (type ==1) { // ipv4
		return get_gateway_setting_by_ipv4(addr);
	} else if (type == 2) { // ipv6
		return get_gateway_setting_by_ipv6(addr);
	}

	return NULL;
}

/**
 * @brief generate cert for apfree-wifidog
 * first, generate ca cert
 * second, generate server cert
 * the ca cert will save in filename DEFAULT_CA_CRT_FILE
 * the server cert will save in filename config->svr_crt_file
 * the server key will save in filename config->svr_key_file
*/
void
init_apfree_wifidog_cert()
{
	s_config *config = config_get_config();
	// generate ca cert
	if (access(config->https_server->ca_crt_file, F_OK) != 0) {
		// generate ca cert
		char cmd[256] = {0};
		snprintf(cmd, sizeof(cmd), "openssl req -new -x509 -days 3650 -nodes -out %s -keyout %s -subj \"/C=CN/ST=Beijing/L=Beijing/O=apfree/CN=apfree.com\"", config->https_server->ca_crt_file, DEFAULT_CA_KEY_FILE);
		system(cmd);
	}
	// generate server cert
	if (access(config->https_server->svr_crt_file, F_OK) != 0) {
		char cmd[256] = {0};
		snprintf(cmd, sizeof(cmd), "openssl req -new -nodes -out %s -keyout %s -subj \"/C=CN/ST=Beijing/L=Beijing/O=apfree/CN=apfree.com\"", DEFAULT_SVR_CRT_REQ_FILE, config->https_server->svr_key_file);
		system(cmd);
		snprintf(cmd, sizeof(cmd), "openssl x509 -req -days 3650 -in %s -CA %s -CAkey %s -set_serial 01 -out %s", DEFAULT_SVR_CRT_REQ_FILE, DEFAULT_CA_CRT_FILE, DEFAULT_CA_KEY_FILE, config->https_server->svr_crt_file);
		system(cmd);
	}
}

/**
 * @brief get device's name from dnsmasq's dhcp.leases file 
 */
void
get_client_name(t_client *client)
{
	char cmd[256] = {0};
	FILE *f_dhcp = NULL;

	snprintf(cmd, 256, "cat /tmp/dhcp.leases |grep %s|cut -d' ' -f 4", client->ip);

	debug(LOG_INFO, "get_client_name [%s]", cmd);
	if((f_dhcp = popen(cmd, "r")) != NULL) {
		char name[32] = {0};
		if (fgets(name, 31,  f_dhcp)) {
			trim_newline(name);
			client->name = safe_strdup(name);
		}
		pclose(f_dhcp);
		debug(LOG_INFO, "get_client_name [%s]", name);
	}
}

bool
is_openwrt_platform(void)
{
	if (access("/etc/openwrt_release", F_OK) == 0)
		return true;
	return false;
}