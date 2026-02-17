
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WD_UTIL_H_
#define _WD_UTIL_H_

#include "conf.h"
#include "client_list.h"

/*  arp_flags and at_flags field values */
#define ATF_INUSE   0x01    /* entry in use */
#define ATF_COM     0x02    /* completed entry (enaddr valid) */
#define ATF_PERM    0x04    /* permanent entry */
#define ATF_PUBL    0x08    /* publish entry (respond for other host) */
#define ATF_USETRAILERS 0x10    /* has requested trailers */
#define ATF_PROXY   0x20    /* Do PROXY arp */

#define MAC_LENGTH  18
#define IP_LENGTH   16

#define LOOKUP_URL_LENGTH	256
#define VENDOR_LENGTH		128

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
char *get_aw_uptime(void);
char *get_client_status_json(void);
char *get_auth_status_json(void);
char *get_wifidogx_json(void);

char *mqtt_get_serialize_maclist(int);

char *get_serialize_maclist(int);

char *get_serialize_trusted_domains(void);

char *get_serialize_iplist(void);

char *mqtt_get_trusted_domains_text(void);

char *mqtt_get_trusted_iplist_text(void);

char *get_trusted_domains_text(void);

char *get_trusted_wildcard_domains_text(void);

char *get_untrusted_maclist_text(void);

char *get_trusted_maclist_text(void);

char *get_trusted_local_maclist_text(void);

char *get_roam_maclist_text(void);

char *get_serialize_trusted_wildcard_domains(void);

char *mqtt_get_trusted_wildcard_domains_text(void);

void trim_newline(char *);

/** @brief Is mac source is wired or not */
int is_device_wired_intern(const char *, const char *);

int br_is_device_wired(const char *); // no popen impl

/** @brief Is ip online or domain parsable */
int is_device_online(const char *);

void evdns_parse_trusted_domain_2_ip(trusted_domain_t);

void evdns_add_trusted_domain_ip_cb(int, struct evutil_addrinfo *, void *);

char *evb_2_string(struct evbuffer *, int *);

int uci_get_value(const char *, const char *, const char *, char *, int);

int uci_set_value(const char *, const char *, const char *, const char *);

int uci_del_value(const char *, const char *, const char *);

int uci_add_list_value(const char *, const char *, const char *, const char *);

int uci_del_list_option(const char *, const char *, const char *);

int uci_add_list_value(const char *, const char *, const char *, const char *);

/** @brief Execute a shell command */
int execute(const char *, int);

/** @brief Thread safe gethostbyname */
struct in_addr *wd_gethostbyname(const char *);

/** @brief Get IP address of an interface */
char *get_iface_ip(const char *);
char *get_iface_ip6(const char *);

/** @brief Get MAC address of an interface */
char *get_iface_mac(const char *);

/** @brief Get interface name of default gateway */
char *get_ext_iface(void);

/** 1: success; 0: error*/
int arp_get_mac(const char *, const char *, char *);

int br_arp_get_mac(t_gateway_setting *, const char *, char *);

int get_ifname_by_address(const char *, char *);

t_gateway_setting *get_gateway_setting_by_ifname(const char *);
t_gateway_setting *get_gateway_setting_by_id(const char *);
t_gateway_setting *get_gateway_setting_by_addr(const char *, int);

/** @brief generate cert for apfree-wifidog */
void init_apfree_wifidog_cert();

void get_client_name(t_client *client);

bool is_openwrt_platform(void);

#endif /* _WD_UTIL_H_ */
