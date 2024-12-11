
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <pthread.h>

#include "common.h"

/** Configuration file paths */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "/etc/wifidog.conf"
#define DEFAULT_HTMLMSGFILE "/etc/wifidog-msg.html"
#define DEFAULT_REDIRECTFILE "/etc/wifidog-redir.html"
#define DEFAULT_INTERNET_OFFLINE_FILE "/etc/internet-offline.html"
#define DEFAULT_AUTHSERVER_OFFLINE_FILE "/etc/authserver-offline.html"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/wifidog.conf"
#define DEFAULT_HTMLMSGFILE SYSCONFDIR"/wifidog-msg.html"
#define DEFAULT_REDIRECTFILE SYSCONFDIR"/wifidog-redir.html"
#define DEFAULT_INTERNET_OFFLINE_FILE SYSCONFDIR"/internet-offline.html"
#define DEFAULT_AUTHSERVER_OFFLINE_FILE SYSCONFDIR"/authserver-offline.html"
#endif

/** Daemon configuration defaults */
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_WDCTL_SOCK "/tmp/wdctl.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/wifidog.sock"

/** Gateway configuration defaults */
#define DEFAULT_GATEWAYID NULL
#define DEFAULT_GATEWAYPORT 2060
#define DEFAULT_GATEWAY_HTTPS_PORT 8443
#define DEFAULT_HTTPDNAME "WiFiDog"
#define DEFAULT_HTTPDMAXCONN 10
#define DEFAULT_LOCAL_PORTAL "http://www.wifidogx.online"
#define DEFAULT_CLIENTTIMEOUT 5
#define DEFAULT_CHECKINTERVAL 60
#define DEFAULT_DELTATRAFFIC 0
#define DEFAULT_ARPTABLE "/proc/net/arp"
#define DEFAULT_EXT_IF	"wan"

/** Auth server configuration defaults */
#define DEFAULT_AUTHSERVPORT 80
#define DEFAULT_AUTHSERVSSLPORT 443
#define DEFAULT_AUTHSERVSSLAVAILABLE 0  /* 0 or 1 */
#define DEFAULT_AUTHSERVSSLPEERVER 1    /* 0 = Enable peer verification */
#define DEFAULT_AUTHSERVPATH "/wifidog/"
#define DEFAULT_AUTHSERVLOGINPATHFRAGMENT "login/?"
#define DEFAULT_AUTHSERVPORTALPATHFRAGMENT "portal/?"
#define DEFAULT_AUTHSERVMSGPATHFRAGMENT "gw_message?"
#define DEFAULT_AUTHSERVPINGPATHFRAGMENT "ping/?"
#define DEFAULT_AUTHSERVAUTHPATHFRAGMENT "auth/?"
#define DEFAULT_WSPATHFRAGMENT "/ws/wifidogx"

/** Certificate/key file paths */
#define DEFAULT_SVR_CRT_REQ_FILE "/tmp/apfree.csr"
#define DEFAULT_CA_KEY_FILE "/etc/apfree.ca.key"
#define DEFAULT_CA_CRT_FILE "/etc/apfree.ca"
#define DEFAULT_SVR_CRT_FILE "/etc/apfree.crt"
#define DEFAULT_SVR_KEY_FILE "/etc/apfree.key"
#define DEFAULT_WWW_PATH "/etc/www/"

/** Firewall rulesets */
#define FWRULESET_GLOBAL "global"
#define FWRULESET_VALIDATING_USERS "validating-users"
#define FWRULESET_KNOWN_USERS "known-users"
#define FWRULESET_AUTH_IS_DOWN "auth-is-down"
#define FWRULESET_UNKNOWN_USERS "unknown-users"
#define FWRULESET_LOCKED_USERS "locked-users"

/** HTML redirect content */
#define WIFIDOG_REDIR_HTML_CONTENT "setTimeout(function() {location.href = \"%s\";}, 10);"


/** Enumerations */
typedef enum trusted_domain_t_ {
	USER_TRUSTED_DOMAIN,
	INNER_TRUSTED_DOMAIN,
	TRUSTED_PAN_DOMAIN,
} trusted_domain_t;

typedef enum mac_choice_t_ {
	TRUSTED_MAC,
	UNTRUSTED_MAC,
	TRUSTED_LOCAL_MAC,
	ROAM_MAC
} mac_choice_t;

typedef enum ip_type_t_ {
	IP_TYPE_IPV4,
	IP_TYPE_IPV6
} ip_type_t;

typedef enum firewall_target_t_ {
	TARGET_DROP,
	TARGET_REJECT,
	TARGET_ACCEPT,
	TARGET_LOG,
	TARGET_ULOG
} t_firewall_target;

/** Mutex declarations */
extern pthread_mutex_t config_mutex;
extern pthread_mutex_t domains_mutex;

/** Basic structures */
typedef struct _ip_trusted_t {
	char ip[INET6_ADDRSTRLEN];
	union {
		struct in_addr ipv4;
		struct in6_addr ipv6;
	} uip;
	ip_type_t ip_type;
	struct _ip_trusted_t *next;
} t_ip_trusted;

/** Server related structures */
typedef struct _auth_serv_t {
	// Auth server properties
	char *authserv_hostname;
	char *authserv_path;
	char *authserv_login_script_path_fragment;
	char *authserv_portal_script_path_fragment;
	char *authserv_msg_script_path_fragment;
	char *authserv_ping_script_path_fragment;
	char *authserv_auth_script_path_fragment;
	char *authserv_ws_script_path_fragment;
	int authserv_http_port;
	int authserv_ssl_port;
	int authserv_use_ssl;
	
	// Connection related
	char *last_ip;
	t_ip_trusted *ips_auth_server;
	int authserv_fd;
	int authserv_fd_ref;
	int authserv_connect_timeout;
	
	struct _auth_serv_t *next;
} t_auth_serv;

/** Firewall related structures */
typedef struct _firewall_rule_t {
	t_firewall_target target;
	char *protocol;
	char *port;
	char *mask;
	int mask_is_ipset;
	struct _firewall_rule_t *next;
} t_firewall_rule;

typedef struct _firewall_ruleset_t {
	char *name;
	t_firewall_rule *rules;
	struct _firewall_ruleset_t *next;
} t_firewall_ruleset;

/** Trust related structures */
typedef struct _trusted_mac_t {
	char *mac;
	char *ip;
	int is_online;
	int remaining_time;
	struct _trusted_mac_t *next;
} t_trusted_mac;

typedef t_trusted_mac t_untrusted_mac;

typedef struct _domain_trusted_t {
	char *domain;
	t_ip_trusted *ips_trusted;
	int invalid;
	struct _domain_trusted_t *next;
} t_domain_trusted;

/** Server configuration structures */
typedef struct _https_server_t {
	char *ca_crt_file;
	char *svr_crt_file;
	char *svr_key_file;
} t_https_server;

typedef struct _http_server_t {
	char *base_path;
	short gw_http_port;
} t_http_server;

typedef struct _mqtt_server_t {
	char *hostname;
	char *username;
	char *password;
	char *cafile;
	char *crtfile;
	char *keyfile;
	short port;
} t_mqtt_server;

typedef struct _ws_server_t {
	char *hostname;
	char *path;
	unsigned short port;
	unsigned short use_ssl;
} t_ws_server;

typedef struct _gateway_setting_t {
	char *gw_id;
	char *gw_interface;
	char *gw_address_v4;
	char *gw_address_v6;
	char *gw_channel;
	int auth_mode;
	struct _gateway_setting_t *next;
} t_gateway_setting;

typedef struct _popular_server_t {
	char *hostname;
	struct _popular_server_t *next;
} t_popular_server;

/** Main configuration structure */
typedef struct {
	// File paths
	char *configfile;
	char *htmlmsgfile;
	char *wdctl_sock;
	char *internal_sock;
	char *pidfile;
	char *htmlredirfile;
	char *internet_offline_file;
	char *authserver_offline_file;
	char *local_portal;
	char *arp_table_path;
	
	// Network settings
	char *external_interface;
	char *device_id;
	uint16_t gw_port;
	uint16_t gw_https_port;
	int proxy_port;
	
	// Server configurations
	t_gateway_setting *gateway_settings;
	t_auth_serv *auth_servers;
	t_https_server *https_server;
	t_http_server *http_server;
	t_mqtt_server *mqtt_server;
	t_ws_server *ws_server;
	
	// Trust lists
	t_domain_trusted *pan_domains_trusted;
	t_domain_trusted *domains_trusted;
	t_domain_trusted *inner_domains_trusted;
	t_trusted_mac *trustedmaclist;
	t_trusted_mac *roam_maclist;
	t_trusted_mac *trusted_local_maclist;
	t_untrusted_mac *mac_blacklist;
	
	// Timing and traffic
	int deltatraffic;
	int clienttimeout;
	int checkinterval;
	int update_domain_interval;
	
	// Firewall
	t_firewall_ruleset *rulesets;
	t_popular_server *popular_servers;
	
	// Flags and modes
	int daemon;
	short wired_passed;
	short parse_checked;
	short js_redir;
	short no_auth;
	short work_mode;
	short bypass_apple_cna;
	short fw4_enable;
	short enable_dhcp_cpi;
	short enable_bypass_auth;
	short enable_dns_forward;
	short enable_del_conntrack;
	short auth_server_mode; /* 0, cloud auth mode; 1, cloud auth bypass mode; 2, local auth mod*/
	short enable_anti_nat; /* 1, enable anti nat */
	char *ttl_values; /* ttl values */
	char *anti_nat_permit_macs; /* anti nat permit mac */

	// Misc
	char *dns_timeout;
	char *dhcp_cpi_uri;
} s_config;

/** Configuration Access Functions */
s_config *config_get_config(void);
t_gateway_setting *get_gateway_settings(void);
t_ws_server *get_ws_server(void);
t_mqtt_server *get_mqtt_server(void);
int get_gateway_count(void);
const char *get_device_id(void);

/** Configuration Initialization and Management */
void config_init(void);
void config_init_override(void);
void config_read(void);
void config_validate(void);

/** Authentication Server Management */
t_auth_serv *get_auth_server(void);
void mark_auth_server_bad(t_auth_serv *);
t_firewall_rule *get_ruleset(const char *);

/** Trusted Domain Management */
t_domain_trusted *get_domains_trusted(void);
t_domain_trusted *__add_domain_common(const char *, trusted_domain_t);
t_domain_trusted *add_domain_common(const char *, trusted_domain_t);
t_domain_trusted *__add_user_trusted_domain(const char *);
t_domain_trusted *add_user_trusted_domain(const char *);
t_domain_trusted *__add_inner_trusted_domain(const char*);
t_domain_trusted *add_inner_trusted_domain(const char*);
t_domain_trusted *__del_domain_common(const char *, trusted_domain_t);
void del_domain_common(const char *, trusted_domain_t);

/** Domain String Parsing */
void parse_domain_string_common_action(const char *, trusted_domain_t, int);
void parse_domain_string_common(const char *, trusted_domain_t);
void parse_inner_trusted_domain_string(const char *);
void parse_user_trusted_domain_string(const char *);
void parse_trusted_pan_domain_string(const char *);
void parse_del_trusted_domain_string(const char *);
void parse_del_trusted_pan_domain_string(const char *);

/** Domain List Management */
void parse_common_trusted_domain_list(trusted_domain_t);
void parse_user_trusted_domain_list(void);
void parse_inner_trusted_domain_list(void);
void add_domain_ip_pair(const char *, trusted_domain_t);
void clear_trusted_domains_(void);
void clear_trusted_pan_domains(void);
void __clear_trusted_domains(void);
void __clear_trusted_domain_ip(t_ip_trusted *);

/** MAC Address Management */
void parse_roam_mac_list(const char *); 
void __clear_roam_mac_list();
void clear_roam_mac_list();
t_trusted_mac *get_roam_maclist();
int is_roaming(const char *);
int is_untrusted_mac(const char *);
int is_trusted_mac(const char *);
void parse_trusted_mac_list(const char *);
void parse_del_trusted_mac_list(const char *);
void __clear_trusted_mac_list(void);
void clear_trusted_mac_list(void);
t_trusted_mac *get_trusted_mac_by_ip(const char *);
void clear_dup_trusted_mac_list(t_trusted_mac *);
void add_mac(const char *, mac_choice_t);
void remove_mac(const char *, mac_choice_t);
void parse_mac_list(const char *, mac_choice_t);
void reset_trusted_mac_list(void);
int trusted_mac_list_dup(t_trusted_mac **);

/** Local MAC List Operations */
void parse_trusted_local_mac_list(const char *);
void parse_del_trusted_local_mac_list(const char *);
void __clear_trusted_local_mac_list(void);
void clear_trusted_local_mac_list(void);
t_trusted_mac *add_trusted_local_mac(const char *);
void parse_untrusted_mac_list(const char*);
void parse_del_untrusted_mac_list(const char *);
void __clear_untrusted_mac_list();
void clear_untrusted_mac_list();
void clear_dup_trusted_mac_list(t_trusted_mac *);
void reset_trusted_mac_list();
int trusted_mac_list_dup(t_trusted_mac **);

/** IP List Management */
void add_trusted_ip_list(const char *);
void __clear_trusted_iplist(void);
void clear_trusted_ip_list(void);
void del_trusted_ip_list(const char *);

// Global state variables
extern int g_online_clients;    // Total connected client count
extern char *g_version;         // Software version
extern char *g_type;            // Hardware type
extern char *g_name;            // Firmware name
extern char *g_ssid;            // Network SSID

// Domain locking macros
#define LOCK_DOMAIN() do { \
	debug(LOG_DEBUG, "Locking domain"); \
	pthread_mutex_lock(&domains_mutex); \
	debug(LOG_DEBUG, "Domains locked"); \
} while (0)

#define UNLOCK_DOMAIN() do { \
	debug(LOG_DEBUG, "Unlocking domain"); \
	pthread_mutex_unlock(&domains_mutex); \
	debug(LOG_DEBUG, "Domain unlocked"); \
} while (0)

// Configuration locking macros 
#define LOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Locking config"); \
	pthread_mutex_lock(&config_mutex); \
	debug(LOG_DEBUG, "Config locked"); \
} while (0)

#define UNLOCK_CONFIG() do { \
	debug(LOG_DEBUG, "Unlocking config"); \
	pthread_mutex_unlock(&config_mutex); \
	debug(LOG_DEBUG, "Config unlocked"); \
} while (0)

#endif                          /* _CONFIG_H_ */
