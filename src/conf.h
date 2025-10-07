
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <pthread.h>

#include "common.h"
#include "bypass_user.h"

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
#define DEFAULT_WDCTL_SOCK "/tmp/wdctlx.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/wifidogx.sock"

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
#define DEFAULT_TTL_VALUES	"64,128,255"

/** Firewall rulesets */
#define FWRULESET_GLOBAL "global"
#define FWRULESET_VALIDATING_USERS "validating-users"
#define FWRULESET_KNOWN_USERS "known-users"
#define FWRULESET_AUTH_IS_DOWN "auth-is-down"
#define FWRULESET_UNKNOWN_USERS "unknown-users"
#define FWRULESET_LOCKED_USERS "locked-users"

/** HTML redirect content */
#define WIFIDOG_REDIR_HTML_CONTENT "setTimeout(function() {location.href = \"%s\";}, 100);"


/** Enumerations */
typedef enum trusted_domain_t_ {
	USER_TRUSTED_DOMAIN,
	INNER_TRUSTED_DOMAIN,
	TRUSTED_WILDCARD_DOMAIN,
} trusted_domain_t;

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

typedef enum auth_server_mode_t_ {
	AUTH_MODE_CLOUD = 0,
	AUTH_MODE_BYPASS,
	AUTH_MODE_LOCAL
} t_auth_server_mode;

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
	char 		*hostname;
	char 		*path;
	uint16_t 	port;
	uint16_t 	use_ssl;
} t_ws_server;

typedef struct _device_info_t {
	char 		*ap_device_id;
	char 		*ap_mac_address;
	char 		*ap_longitude;
	char 		*ap_latitude;
	char 		*location_id;
} t_device_info;

typedef struct _gateway_setting_t {
	char 		*gw_id;
	char 		*gw_interface;
	char 		*gw_address_v4;
	char 		*gw_address_v6;
	char 		*gw_channel;
	int 		auth_mode;
	uint32_t	ip_v4;
	uint32_t	mask_v4;
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
	int  is_custom_auth_offline_file;
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
	t_device_info *device_info;
	
	// Trust lists
	t_domain_trusted *wildcard_domains_trusted;
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
	
	// popular servers
	t_popular_server *popular_servers;
	
	// Flags and modes
	int daemon;
	short wired_passed;
	short parse_checked;
	short js_redir;
	short bypass_apple_cna;
	short fw4_enable;
	short enable_bypass_auth;
	short enable_del_conntrack;
	short auth_server_mode; /* 0, cloud auth mode; 1, cloud auth bypass mode; 2, local auth mod*/
	short enable_anti_nat; /* 1, enable anti nat */
	short enable_smart_qos; /* 1, enable smart qos */
	short enable_user_reload; /* 1, enable user reload */
	short disable_portal_auth; /* 1, disable portal authentication */
	char *ttl_values; /* ttl values */
	char *anti_nat_permit_macs; /* anti nat permit mac */

	// Misc
	char *dns_timeout;
} s_config;

/** Configuration Access Functions */
s_config *config_get_config(void);
t_gateway_setting *get_gateway_settings(void);
t_ws_server *get_ws_server(void);
t_mqtt_server *get_mqtt_server(void);
t_device_info *get_device_info(void);
int get_gateway_count(void);
const char *get_device_id(void);

/** Configuration Initialization and Management */
void config_init(void);
void config_read(void);
void config_validate(void);
void free_gateway_settings_list(t_gateway_setting *list_head);
void free_auth_servers_list(t_auth_serv *list_head);
void free_popular_servers_list(t_popular_server *list_head);
void free_domain_trusted_list(t_domain_trusted *list_head);
void free_trusted_mac_list(t_trusted_mac *list_head);
void free_ip_trusted_list(t_ip_trusted *list_head);
void config_cleanup(void);

/** Authentication Server Management */
t_auth_serv *get_auth_server(void);
void mark_auth_server_bad(t_auth_serv *);

/** Domain String Parsing */
void parse_user_trusted_domain_string(const char *);
void parse_trusted_wildcard_domain_string(const char *);
void parse_del_trusted_domain_string(const char *);
void parse_del_trusted_wildcard_domain_string(const char *);

/** Domain List Management */
void parse_user_trusted_domain_list(void);
void parse_inner_trusted_domain_list(void);
void add_domain_ip_pair(const char *, trusted_domain_t);
void clear_trusted_domains(void);
void clear_trusted_wildcard_domains(void);
t_domain_trusted *get_trusted_domains(void);
t_domain_trusted *get_trusted_wildcard_domains(void);
void add_trusted_wildcard_domains(const char *domains);

/** Roam MAC List operation */
void parse_roam_mac_list(const char *); 
void clear_roam_mac_list();
t_trusted_mac *get_roam_maclist();

/** Trusted MAC List Operations */
bool is_trusted_mac(const char *);
void parse_trusted_mac_list(const char *);
void parse_del_trusted_mac_list(const char *);
void clear_trusted_mac_list(void);
void add_mac(const char *, mac_choice_t);
void remove_mac(const char *, mac_choice_t);

/** Local MAC List Operations */
void parse_trusted_local_mac_list(const char *);
void parse_del_trusted_local_mac_list(const char *);
void clear_trusted_local_mac_list(void);
t_trusted_mac *add_trusted_local_mac(const char *);

/** Untrusted MAC List Operations */
void parse_untrusted_mac_list(const char*);
void parse_del_untrusted_mac_list(const char *);
void clear_untrusted_mac_list();

/** IP List Management */
void add_trusted_ip_list(const char *);
void clear_trusted_ip_list(void);
void del_trusted_ip_list(const char *);

bool is_bypass_mode(void);
bool is_local_auth_mode(void);
bool is_cloud_mode(void);
bool is_custom_auth_offline_page(void);
bool is_user_reload_enabled(void);
bool is_portal_auth_disabled(void);

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
