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
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "gateway.h"
#include "commandline.h"
#include "client_list.h"
#include "conf.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "debug.h"
#include "pstring.h"
#include "version.h"

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long served_this_session = 0;

static int n_pending_requests = 0;
static struct event_base *base = NULL;

void
mark_online()
{
    int before;
    int after;

    before = is_online();
    time(&last_online_time);
    after = is_online();        /* XXX is_online() looks at last_online_time... */
	
    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

void
mark_offline_time() 
{
	int before;
    int after;

    before = is_online();
    time(&last_offline_time);
    after = is_online();
	
    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }
}
 
void
mark_offline()
{
    int before;
    int after;

    before = is_online();
    time(&last_offline_time);
    after = is_online();
		  
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
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_online_time);
    after = is_auth_online();

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
    } else if (last_auth_online_time == 0
               || (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* Auth is  probably offline */
        return (0);
    } else {
        /* Auth is probably online */
        return (1);
    }
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
	active_count = 1;
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

    pstr_append_sprintf(pstr, "%d client " " %d active .\n", count, active_count);

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

//>>>> liudf added 20151225
char *
get_serialize_iplist()
{
	pstr_t *pstr = NULL;
    s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted	*iplist = NULL;
	int line = 0;

    config = config_get_config();
    
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
    
	return pstr_to_string(pstr);

}

char *
get_trusted_domains_text()
{
	pstr_t *pstr = pstr_new();
    s_config *config;
	t_domain_trusted *domain_trusted = NULL;
	t_ip_trusted	*ip_trusted = NULL;

    config = config_get_config();
    
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
    
	return pstr_to_string(pstr);

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

/*
 * 1: wired; 0: wireless
 */
int
is_device_wired(const char *mac)
{
	FILE *fd = NULL;
	char szcmd[128] = {0}; 
	
	snprintf(szcmd, 128, "/usr/bin/ktpriv get_mac_source %s", mac);
	if((fd = popen(szcmd, "r"))) {
		char buf[8] = {0};
		fgets(buf, 7, fd);
		pclose(fd);
		if(buf[0] == '0')
			return 1;
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
		fgets(result, 3, fd);
		pclose(fd);
		if(result[0] == '1')
			return 1;
	}

	return 0;
}

// if olen is not NULL, set it rlen value
char *evb_2_string(struct evbuffer *evb, int *olen) 
{
	int rlen = evbuffer_get_length(evb);
	char *str = (char *)malloc(rlen+1);
	memset(str, 0, rlen+1);
	evbuffer_copyout(evb, str, rlen);
	if (olen)
		*olen = rlen;
	return str;
}

void evdns_add_trusted_domain_ip_cb(int errcode, struct evutil_addrinfo *addr, void *ptr)
{
	t_domain_trusted *p = ptr;
    if (!errcode) {
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
            }
            if (s) {
				t_ip_trusted *ipt = NULL;
				debug(LOG_DEBUG, "parse domain (%s) ip (%s)", p->domain, s);
				if(p->ips_trusted == NULL) {
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
        }
        evutil_freeaddrinfo(addr);
    }
	
    if (--n_pending_requests == 0)
        event_base_loopexit(base, NULL);
}

void evdns_parse_trusted_domain_2_ip(t_domain_trusted *p)
{
	struct evdns_base  *dnsbase 	= NULL;
	
	base = event_base_new();
    if (!base)
        return;
	
    dnsbase = evdns_base_new(base, 1);
    if (!dnsbase)
        return;
	
	struct evutil_addrinfo hints;
	
	LOCK_DOMAIN();
	
	while(p && p->domain) {		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_flags = EVUTIL_AI_CANONNAME;

		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		
		++n_pending_requests;
		
		evdns_getaddrinfo( dnsbase, p->domain, NULL ,
			  &hints, evdns_add_trusted_domain_ip_cb, p);
		
		p = p->next;
	}
	
	if (n_pending_requests)
		event_base_dispatch(base);
	
	UNLOCK_DOMAIN();
	
	evdns_base_free(dnsbase, 0);
    event_base_free(base);
}
//<<<< liudf added end
