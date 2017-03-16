/* vim: set et ts=4 sts=4 sw=4 : */
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

/** @file wd_util.h
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#ifndef _WD_UTIL_H_
#define _WD_UTIL_H_

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/buffer.h>

#include "conf.h"

/** How many times should we try detecting the interface with the default route
 * (in seconds).  If set to 0, it will keep retrying forever */
#define NUM_EXT_INTERFACE_DETECT_RETRY 0
/** How often should we try to detect the interface with the default route
 *  if it isn't up yet (interval in seconds) */
#define EXT_INTERFACE_DETECT_RETRY_INTERVAL 1

#define SYSFS_CLASS_NET "/sys/class/net/"
#define SYSFS_PATH_MAX  256

struct fdb_entry {       
    u_int8_t mac_addr[6];
    u_int16_t port_no;
    unsigned char is_local;
    struct timeval ageing_timer_value;
};     



/** @brief Client server this session. */
extern long served_this_session;

/** @brief Sets hint that an online action (dns/connect/etc using WAN) succeeded */
void mark_online(void);

/** @brief Sets hint that an online action (dns/connect/etc using WAN) failed */
void mark_offline(void);

void mark_offline_time(void);

/** @brief Returns a guess (true or false) on whether we're online or not based on previous calls to mark_online and mark_offline */
int is_online(void);

/** @brief Sets hint that an auth server online action succeeded */
void mark_auth_online(void);

/** @brief Sets hint that an auth server online action failed */
void mark_auth_offline(void);

/** @brief Returns a guess (true or false) on whether we're an auth server is online or not based on previous calls to mark_auth_online and mark_auth_offline */
int is_auth_online(void);

/** @brief Creates a human-readable paragraph of the status of wifidog */
char *get_status_text(void);

//>>> liudf added 20151225
char *mqtt_get_serialize_maclist(int);
char *get_serialize_maclist(int);
char *get_serialize_trusted_domains(void);
char *get_serialize_iplist(void);
char *mqtt_get_trusted_domains_text(void);
char *get_trusted_domains_text(void);
char *get_untrusted_maclist_text(void);
char *get_trusted_maclist_text(void);
char *get_roam_maclist_text(void);
char *get_serialize_trusted_pan_domains(void);
char *mqtt_get_trusted_pan_domains_text(void);

char *mqtt_get_status_text(void);

void trim_newline(char *);

/** @brief Is mac source is wired or not */
int is_device_wired(const char *);

/** @brief Is ip online or domain parsable */
int is_device_online(const char *);

void evdns_parse_trusted_domain_2_ip(t_domain_trusted *p);

void evdns_add_trusted_domain_ip_cb(int errcode, struct evutil_addrinfo *addr, void *ptr);

char *evb_2_string(struct evbuffer *, int *);

int uci_get_value(const char *, const char *, char *, int);

int uci_set_value(const char *, const char *, const char *, const char *);

int uci_del_value(const char *, const char *, const char *);
//<<< liudf added end

/** @brief Execute a shell command */
int execute(const char *, int);

/** @brief Thread safe gethostbyname */
struct in_addr *wd_gethostbyname(const char *);

/** @brief Get IP address of an interface */
char *get_iface_ip(const char *);

/** @brief Get MAC address of an interface */
char *get_iface_mac(const char *);

/** @brief Get interface name of default gateway */
char *get_ext_iface(void);
#endif /* _WD_UTIL_H_ */
