/* vim: set et sw=4 sts=4 ts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/**
  @file wd_util.c
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
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

#include <uci.h>
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
#include "pstring.h"
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

/*
 * @return A string containing human-readable status text. MUST BE free()d by caller
 */
char *
get_status_text()
{
	pstr_t *pstr = pstr_new();
	s_config *config;
	t_auth_serv *auth_server;
	t_client *sublist, *current;
	int count, active_count;
	time_t uptime = 0;
	unsigned int days = 0, hours = 0, minutes = 0, seconds = 0;
	t_trusted_mac *p;
	t_offline_client *oc_list;

	pstr_cat(pstr, "WiFiDog status\n\n");

	uptime = time(NULL) - started_time;
	days = (unsigned int)uptime / (24 * 60 * 60);
	uptime -= days * (24 * 60 * 60);
	hours = (unsigned int)uptime / (60 * 60);
	uptime -= hours * (60 * 60);
	minutes = (unsigned int)uptime / 60;
	uptime -= minutes * 60;
	seconds = (unsigned int)uptime;

	pstr_cat(pstr, "Version: " VERSION "\n");
	pstr_append_sprintf(pstr, "Uptime: %ud %uh %um %us\n", days, hours, minutes, seconds);
	pstr_cat(pstr, "Has been restarted: ");

	if (restart_orig_pid) {
		pstr_append_sprintf(pstr, "yes (from PID %d)\n", restart_orig_pid);
	} else {
		pstr_cat(pstr, "no\n");
	}

	pstr_append_sprintf(pstr, "Internet Connectivity: %s\n", (is_online()? "yes" : "no"));
	pstr_append_sprintf(pstr, "Auth server reachable: %s\n", (is_auth_online()? "yes" : "no"));
	pstr_append_sprintf(pstr, "Clients served this session: %lu\n\n", served_this_session);

	LOCK_CLIENT_LIST();

	count = client_list_dup(&sublist);

	UNLOCK_CLIENT_LIST();

	current = sublist;

	pstr_append_sprintf(pstr, "%d clients " "connected.\n", count);

	count = 1;
	active_count = 0;
	while (current != NULL) {
		pstr_append_sprintf(pstr, "\nClient %d status [%d]\n", count, current->is_online);
		pstr_append_sprintf(pstr, "  IP: %s MAC: %s\n", current->ip, current->mac);
		pstr_append_sprintf(pstr, "  Token: %s\n", current->token);
		pstr_append_sprintf(pstr, "  First Login: %lld\n", (long long)current->first_login);
		pstr_append_sprintf(pstr, "  Name: %s\n", current->name != NULL?current->name:"null");
		pstr_append_sprintf(pstr, "  Downloaded: %llu\n  Uploaded: %llu\n", current->counters.incoming,
			current->counters.outgoing);
		count++;
		if(current->is_online)
			active_count++;
		current = current->next;
	}

	client_list_destroy(sublist);

	pstr_append_sprintf(pstr, "%d client " " %d active .\n", count-1, active_count);

	LOCK_OFFLINE_CLIENT_LIST();
	pstr_append_sprintf(pstr, "%d clients " "unconnected.\n", offline_client_number());
	oc_list = client_get_first_offline_client();
	while(oc_list != NULL) {	
		pstr_append_sprintf(pstr, "  IP: %s MAC: %s Last Login: %lld Hit Counts: %d Client Type: %d Temp Passed: %d\n", 
			oc_list->ip, oc_list->mac, (long long)oc_list->last_login, 
			oc_list->hit_counts, oc_list->client_type, oc_list->temp_passed);
		oc_list = oc_list->next;
	}
	UNLOCK_OFFLINE_CLIENT_LIST();

	config = config_get_config();

	LOCK_CONFIG();

	if (config->trustedmaclist != NULL) {
		pstr_cat(pstr, "\nTrusted MAC addresses:\n");

		for (p = config->trustedmaclist; p != NULL; p = p->next) {
			pstr_append_sprintf(pstr, "  %s\n", p->mac);
		}
	}

	pstr_cat(pstr, "\nAuthentication servers:\n");

	for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
		pstr_append_sprintf(pstr, "  Host: %s (%s)\n", auth_server->authserv_hostname, auth_server->last_ip);
	}

	UNLOCK_CONFIG();

	return pstr_to_string(pstr);
}

char *
get_serialize_iplist()
{
		pstr_t *pstr = NULL;
		s_config *config = config_get_config();
		t_domain_trusted *domain_trusted = NULL;
		t_ip_trusted	*iplist = NULL;
		int line = 0;

		domain_trusted = config->domains_trusted;
		if(domain_trusted == NULL)
				return NULL;


		LOCK_DOMAIN();

		for (; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
				if(strcmp(domain_trusted->domain, "iplist") == 0) {
						break;
				}
		}

		if(domain_trusted != NULL)	
				iplist = domain_trusted->ips_trusted;
		else {
				UNLOCK_DOMAIN();
				debug(LOG_DEBUG, "no iplist ");
				return NULL;
		}

		pstr = pstr_new();

		for(; iplist != NULL; iplist = iplist->next, line++) {
				if(line == 0)
						pstr_append_sprintf(pstr, "%s", iplist->ip);
				else
						pstr_append_sprintf(pstr, ",%s", iplist->ip);	
		}

		UNLOCK_DOMAIN();	

		return pstr_to_string(pstr);

}

char *
get_serialize_trusted_domains()
{
	pstr_t *pstr = NULL;
    s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	int line = 0;

    config = config_get_config();
    
	domain_trusted = config->domains_trusted;
	if(domain_trusted == NULL)
		return NULL;

	pstr = pstr_new();

	LOCK_DOMAIN();
	
	for (; domain_trusted != NULL; domain_trusted = domain_trusted->next, line++) {
		if(strcmp(domain_trusted->domain, "iplist") == 0) {
			line--;
			continue;
		}
		if(line == 0)
        	pstr_append_sprintf(pstr, "%s", domain_trusted->domain);
		else
        	pstr_append_sprintf(pstr, ",%s", domain_trusted->domain);
	}
	UNLOCK_DOMAIN();	
    
	return pstr_to_string(pstr);

}

char *
get_serialize_trusted_pan_domains()
{
	pstr_t *pstr = NULL;
    s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	int line = 0;

    config = config_get_config();
    
	domain_trusted = config->pan_domains_trusted;
	if(domain_trusted == NULL)
		return NULL;

	pstr = pstr_new();

	LOCK_DOMAIN();
	
	for (; domain_trusted != NULL; domain_trusted = domain_trusted->next, line++) {
		if(line == 0)
        	pstr_append_sprintf(pstr, "%s", domain_trusted->domain);
		else
        	pstr_append_sprintf(pstr, ",%s", domain_trusted->domain);
	}

	UNLOCK_DOMAIN();	
    
	return line?pstr_to_string(pstr):NULL;

}

char *
mqtt_get_trusted_pan_domains_text()
{
	s_config *config;
	t_domain_trusted *domain_trusted = NULL;

    config = config_get_config();
    if (config->pan_domains_trusted == NULL)
    	return NULL;

    pstr_t *pstr = pstr_new();
    int first = 1;
	LOCK_DOMAIN();
	
	for (domain_trusted = config->pan_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        if (first) {
        	pstr_append_sprintf(pstr, "%s", domain_trusted->domain);
        	first = 0;
        } else 
        	pstr_append_sprintf(pstr, ",%s", domain_trusted->domain);
	}
	
	UNLOCK_DOMAIN();

	return first?NULL:pstr_to_string(pstr);
}

char *
mqtt_get_trusted_domains_text()
{
    s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted	*ip_trusted = NULL;

    config = config_get_config();
    if (config->domains_trusted == NULL)
    	return NULL;

    struct json_object *jarray = json_object_new_array();
	LOCK_DOMAIN();
	
	for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        pstr_t *pstr = pstr_new();
        int first = 1;
        struct json_object *jobj = json_object_new_object();
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
        	if (first) {
        		pstr_append_sprintf(pstr, "%s", ip_trusted->ip);
        		first = 0;
        	} else
        		pstr_append_sprintf(pstr, ",%s", ip_trusted->ip);
		}
		char *iplist = pstr_to_string(pstr);
		json_object_object_add(jobj, domain_trusted->domain, 
			json_object_new_string(first?"NULL":iplist));
		json_object_array_add(jarray, jobj);
		if (iplist)
			free(iplist);
	}
	
	UNLOCK_DOMAIN();

	char *retStr = safe_strdup(json_object_to_json_string(jarray));
    json_object_put(jarray);

	return retStr;
}

char *
mqtt_get_trusted_iplist_text()
{
	s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted	*ip_trusted = NULL;

	config = config_get_config();
	if (config->domains_trusted == NULL)
		return NULL;

	domain_trusted = config->domains_trusted;
	int first = 1;
	
	LOCK_DOMAIN();
	for (; (domain_trusted != NULL)&& (strcmp(domain_trusted->domain,"iplist") != 0); domain_trusted = domain_trusted->next) ;

	if(domain_trusted == NULL) {
		UNLOCK_DOMAIN();
		return NULL;
	}

	pstr_t *pstr = pstr_new();
	for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
		if (first) {
			  pstr_append_sprintf(pstr, "%s", ip_trusted->ip);
			  first = 0;
		 } else {
			  pstr_append_sprintf(pstr, ",%s", ip_trusted->ip);
		 }
	 }

	char *iplist = pstr_to_string(pstr);
	struct json_object *jobj = json_object_new_object();
	struct json_object *jarray = json_object_new_array();
	json_object_object_add(jobj, domain_trusted->domain, 
		json_object_new_string(first?"NULL":iplist));
	json_object_array_add(jarray, jobj);
	if (iplist)
		free(iplist);

	UNLOCK_DOMAIN();

	char *retStr = safe_strdup(json_object_to_json_string(jarray));
	json_object_put(jarray);

	return retStr;
}

char *
get_trusted_domains_text(void)
{
	pstr_t *pstr = pstr_new();
    s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted	*ip_trusted = NULL;
    
	pstr_cat(pstr, "\nTrusted domains and its ip:\n");

	LOCK_DOMAIN();
	
	for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        pstr_append_sprintf(pstr, "\nDomain: %s \n", domain_trusted->domain);
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
        	pstr_append_sprintf(pstr, "  %s \n", ip_trusted->ip);
		}
	}
	
	UNLOCK_DOMAIN();
    
	return pstr_to_string(pstr);
}

char *
get_trusted_pan_domains_text(void)
{
	pstr_t *pstr = pstr_new();
	s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;
	
	pstr_cat(pstr, "\nTrusted wildcard domains:\n");

	LOCK_DOMAIN();
	
	for (domain_trusted = config->pan_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		pstr_append_sprintf(pstr, " %s ", domain_trusted->domain);
		t_ip_trusted *ip_trusted = domain_trusted->ips_trusted;
		if(ip_trusted != NULL) {
			pstr_cat(pstr, "with ip:\n");
			for (; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
				// convert uip to string
				char ip[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, &ip_trusted->uip, ip, INET_ADDRSTRLEN);
				pstr_append_sprintf(pstr, "  %s\n", ip);
			}
		} else {
			pstr_cat(pstr, "\n");
		}
	}
	
	UNLOCK_DOMAIN();
	
	return pstr_to_string(pstr);
}

char *
mqtt_get_serialize_maclist(int which)
{
	return get_serialize_maclist(which);
}

char *
get_serialize_maclist(int which)
{
	pstr_t *pstr = NULL;
    s_config *config;
	t_trusted_mac *maclist = NULL;
	int line = 0;
    config = config_get_config();
	
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
	
	if(maclist != NULL)
		pstr = pstr_new();
	else
		return NULL;

	LOCK_CONFIG();
	
	
	for (; maclist != NULL; maclist = maclist->next, line++) {
		if(line == 0)
        	pstr_append_sprintf(pstr, "%s", maclist->mac);
		else	
        	pstr_append_sprintf(pstr, ",%s", maclist->mac);
	}
	
	UNLOCK_CONFIG();
    
	return line?pstr_to_string(pstr):NULL;

}

static char *
get_maclist_text(int which)
{
	pstr_t *pstr = NULL;
    s_config *config;
	t_trusted_mac *maclist = NULL;
	int line = 0;
    config = config_get_config();
    
	switch(which) {
	case TRUSTED_MAC:
		pstr = pstr_new();
		maclist = config->trustedmaclist; 
		pstr_cat(pstr, "\nTrusted mac list:\n");
		break;
	case UNTRUSTED_MAC:
		pstr = pstr_new();
		maclist = config->mac_blacklist;
		pstr_cat(pstr, "\nUntrusted mac list:\n");
		break;
	case TRUSTED_LOCAL_MAC:
		pstr = pstr_new();
		maclist = config->trusted_local_maclist;
		pstr_cat(pstr, "\nTrusted local mac list:\n");
		break;
	case ROAM_MAC:
		pstr = pstr_new();
		maclist = config->roam_maclist;
		pstr_cat(pstr, "\nRoam mac list:\n");
		break;
	default:
		return NULL;
	}
	
	LOCK_CONFIG();
	
	for (; maclist != NULL; maclist = maclist->next) {
        pstr_append_sprintf(pstr, " %s ", maclist->mac);
		line++;
		if(line == 4) {
			line = 0;
			pstr_append_sprintf(pstr, "\n");
		}
	}
	
	UNLOCK_CONFIG();
    
	return pstr_to_string(pstr);
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
		char *bridge = config_get_config()->gw_interface;
		debug(LOG_DEBUG,"mac %s check in bridge %s is wired", mac, bridge);
		return is_device_wired_intern(mac, bridge);
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
		debug(LOG_DEBUG, "parsed domain list is empty");
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
    // thanks to the following article
    // http://www.wuqiong.info/archives/13/
    evdns_base_set_option(dnsbase, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
    evdns_base_nameserver_ip_add(dnsbase, "180.76.76.76");//BaiduDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.5.5.5");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "223.6.6.6");//AliDNS
    evdns_base_nameserver_ip_add(dnsbase, "114.114.114.114");//114DNS
	
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
	int nret = 0;
	char uciOption[128] = {0};
	struct uci_context * ctx = uci_alloc_context(); 
    struct uci_ptr ptr; 
	if (!c_filename || !section || !name || !ctx)  
        return nret;  
    memset(&ptr, 0, sizeof(ptr));  
     
    snprintf(uciOption, sizeof(uciOption), "%s.@%s[0].%s", c_filename, section, name); 
    if(UCI_OK != uci_lookup_ptr(ctx, &ptr, uciOption, true)) {
		nret = 0;
		goto OUT;
	} 
	
	nret = uci_delete(ctx, &ptr);
	if (UCI_OK != nret) {
		nret = 0;
		goto OUT;
	}

	nret = uci_save(ctx, ptr.p);
	if (UCI_OK != nret) {
		nret = 0;
		goto OUT;
	}

	nret = uci_commit(ctx, &ptr.p, false);
	if (UCI_OK != nret) {
		nret = 0;
		goto OUT;
	}
	
	nret = 1;
OUT:
	if (!ctx) {
		uci_unload(ctx, ptr.p);  
    	uci_free_context(ctx);
	} 
	return nret;
}

int
uci_set_value(const char *c_filename, const char *section, const char *name, const char *value)
{
	int nret = 0;
	char uciOption[128] = {0};
	struct uci_context * ctx = uci_alloc_context(); 
    struct uci_ptr ptr; 
	if (!c_filename || !section || !name || !value || !ctx)  
        goto OUT;  
    memset(&ptr, 0, sizeof(ptr));  
     
    snprintf(uciOption, sizeof(uciOption), "%s.@%s[0].%s", c_filename, section, name); 
    if(UCI_OK != uci_lookup_ptr(ctx, &ptr, uciOption, true)) {
		nret = 0;
		goto OUT;
	}   
    ptr.value = value; 
    
    nret = uci_set(ctx, &ptr);  
    if (UCI_OK != nret){  
        nret = 0;
		goto OUT;
    } 
	
	nret = uci_save(ctx, ptr.p);
	if (UCI_OK != nret) {
		nret = 0;
		goto OUT;
	}

	nret = uci_commit(ctx, &ptr.p, false);
	if (UCI_OK != nret) {
		nret = 0;
		goto OUT;
	}
	
	nret = 1;
OUT:
	if (ctx) {
		uci_unload(ctx, ptr.p);  
    	uci_free_context(ctx);
	} 
	return nret;
}

int
uci_get_value(const char *c_filename, const char *name, char *value, int v_len)
{
	struct uci_context *uci = uci_alloc_context();  
    struct uci_package *pkg = NULL;    
    struct uci_element *e 	= NULL;
    const char * pValueData = NULL;  
  	int nret	= 0;
	
    if (!c_filename || !name || !value || !uci || UCI_OK != uci_load(uci, c_filename, &pkg))    
        goto OUT;  
    
    uci_foreach_element(&pkg->sections, e) {    
        struct uci_section *s = uci_to_section(e);    
        if ((pValueData = uci_lookup_option_string(uci, s, name))) {  
            strncpy(value, pValueData, v_len);
			nret = 1;
			break;
        }  
    }    
      
    uci_unload(uci, pkg);    
      
OUT:    
    if (uci) uci_free_context(uci);    
	return nret;
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

/**
 * @brief get client's mac from its ip
 * @return 0 failed or 1 success
 * 
 */ 
int 
arp_get_mac(const char *dev_name, const char *i_ip, char *o_mac) {
	int s;
    struct arpreq arpreq;
    struct sockaddr_in *sin;
	
	if (!dev_name || !i_ip || !o_mac)
		return 0;
	
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s <= 0) {
		return 0;
	}
	
	memset(&arpreq, 0, sizeof(arpreq));

    sin = (struct sockaddr_in *) &arpreq.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr(i_ip);

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
br_arp_get_mac(const char *i_ip, char *o_mac)
{
	s_config *config = config_get_config();

	return arp_get_mac(config->gw_interface, i_ip, o_mac);
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