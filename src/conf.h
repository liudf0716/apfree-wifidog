/* vim: set et sw=4 ts=4 sts=4 : */
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

/* $Id$ */
/** @file conf.h
    @brief Config file parsing
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _CONFIG_H_
#define _CONFIG_H_

/*@{*/
/** Defines */

/** Defaults configuration values */
#ifndef SYSCONFDIR
#define DEFAULT_CONFIGFILE "/etc/wifidog.conf"
#define DEFAULT_HTMLMSGFILE "/etc/wifidog-msg.html"
#define DEFAULT_REDIRECTFILE "/etc/wifidog-redir.html"
#else
#define DEFAULT_CONFIGFILE SYSCONFDIR"/wifidog.conf"
#define DEFAULT_HTMLMSGFILE SYSCONFDIR"/wifidog-msg.html"
#define DEFAULT_REDIRECTFILE SYSCONFDIR"/wifidog-redir.html"
#endif
#define DEFAULT_DAEMON 1
#define DEFAULT_DEBUGLEVEL LOG_INFO
#define DEFAULT_HTTPDMAXCONN 10
#define DEFAULT_GATEWAYID NULL
#define DEFAULT_GATEWAYPORT 2060
#define DEFAULT_HTTPDNAME "WiFiDog"
#define DEFAULT_CLIENTTIMEOUT 5
#define DEFAULT_CHECKINTERVAL 60
#define DEFAULT_LOG_SYSLOG 0
#define DEFAULT_SYSLOG_FACILITY LOG_DAEMON
#define DEFAULT_WDCTL_SOCK "/tmp/wdctl.sock"
#define DEFAULT_INTERNAL_SOCK "/tmp/wifidog.sock"
#define DEFAULT_AUTHSERVPORT 80
#define DEFAULT_AUTHSERVSSLPORT 443
/** Note that DEFAULT_AUTHSERVSSLAVAILABLE must be 0 or 1, even if the config file syntax is yes or no */
#define DEFAULT_AUTHSERVSSLAVAILABLE 0
/** Note:  The path must be prefixed by /, and must be suffixed /.  Put / for the server root.*/
#define DEFAULT_AUTHSERVPATH "/wifidog/"
#define DEFAULT_AUTHSERVLOGINPATHFRAGMENT "login/?"
#define DEFAULT_AUTHSERVPORTALPATHFRAGMENT "portal/?"
#define DEFAULT_AUTHSERVMSGPATHFRAGMENT "gw_message?"
#define DEFAULT_AUTHSERVPINGPATHFRAGMENT "ping/?"
#define DEFAULT_AUTHSERVAUTHPATHFRAGMENT "auth/?"
#define DEFAULT_AUTHSERVSSLCERTPATH "/etc/ssl/certs/"
/** Note that DEFAULT_AUTHSERVSSLNOPEERVER must be 0 or 1, even if the config file syntax is yes or no */
#define DEFAULT_AUTHSERVSSLPEERVER 1    /* 0 means: Enable peer verification */
#define DEFAULT_DELTATRAFFIC 0    /* 0 means: Enable peer verification */
#define DEFAULT_ARPTABLE "/proc/net/arp"
#define DEFAULT_AUTHSERVSSLSNI 0  /* 0 means: Disable SNI */
/*@}*/

/*@{*/
/** Defines for firewall rule sets. */
#define FWRULESET_GLOBAL "global"
#define FWRULESET_VALIDATING_USERS "validating-users"
#define FWRULESET_KNOWN_USERS "known-users"
#define FWRULESET_AUTH_IS_DOWN "auth-is-down"
#define FWRULESET_UNKNOWN_USERS "unknown-users"
#define FWRULESET_LOCKED_USERS "locked-users"
/*@}*/


typedef enum trusted_domain_t_ {
	USER_TRUSTED_DOMAIN,
	INNER_TRUSTED_DOMAIN
} trusted_domain_t;

typedef enum mac_choice_t_ {
	TRUSTED_MAC,
	UNTRUSTED_MAC,
	ROAM_MAC
} mac_choice_t;
//<<< liudf added end

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
extern pthread_mutex_t config_mutex;

/**
 * Information about the authentication server
 */
typedef struct _auth_serv_t {
    char *authserv_hostname;    /**< @brief Hostname of the central server */
    char *authserv_path;        /**< @brief Path where wifidog resides */
    char *authserv_login_script_path_fragment;  /**< @brief This is the script the user will be sent to for login. */
    char *authserv_portal_script_path_fragment; /**< @brief This is the script the user will be sent to after a successfull login. */
    char *authserv_msg_script_path_fragment;    /**< @brief This is the script the user will be sent to upon error to read a readable message. */
    char *authserv_ping_script_path_fragment;   /**< @brief This is the ping heartbeating script. */
    char *authserv_auth_script_path_fragment;   /**< @brief This is the script that talks the wifidog gateway protocol. */
    int authserv_http_port;     /**< @brief Http port the central server
				     listens on */
    int authserv_ssl_port;      /**< @brief Https port the central server
				     listens on */
    int authserv_use_ssl;       /**< @brief Use SSL or not */
    char *last_ip;      /**< @brief Last ip used by authserver */
    struct _auth_serv_t *next;
} t_auth_serv;

/**
 * Firewall targets
 */
typedef enum {
    TARGET_DROP,
    TARGET_REJECT,
    TARGET_ACCEPT,
    TARGET_LOG,
    TARGET_ULOG
} t_firewall_target;

/**
 * Firewall rules
 */
typedef struct _firewall_rule_t {
    t_firewall_target target;   /**< @brief t_firewall_target */
    char *protocol;             /**< @brief tcp, udp, etc ... */
    char *port;                 /**< @brief Port to block/allow */
    char *mask;                 /**< @brief Mask for the rule *destination* */
    int mask_is_ipset; /**< @brief *destination* is ipset  */
    struct _firewall_rule_t *next;
} t_firewall_rule;

/**
 * Firewall rulesets
 */
typedef struct _firewall_ruleset_t {
    char *name;
    t_firewall_rule *rules;
    struct _firewall_ruleset_t *next;
} t_firewall_ruleset;

/**
 * Trusted MAC Addresses
 */
typedef struct _trusted_mac_t {
    char *mac;
    struct _trusted_mac_t *next;
} t_trusted_mac;

typedef t_trusted_mac	t_untrusted_mac;

/**
 * Popular Servers
 */
typedef struct _popular_server_t {
    char *hostname;
    struct _popular_server_t *next;
} t_popular_server;

/**
 * liudf added 20151223
 * trust domains and trust ip
 *
 */
#define	HTTP_IP_ADDR_LEN	17
typedef struct _ip_trusted_t {
	char	ip[HTTP_IP_ADDR_LEN];
	struct _ip_trusted_t *next;
} t_ip_trusted;

typedef struct _domain_trusted_t {
	char *domain;
	t_ip_trusted	*ips_trusted;
	struct _domain_trusted_t *next;
} t_domain_trusted;

// <<<< liudf added end

/**
 * Configuration structure
 */
typedef struct {
    char *configfile;       /**< @brief name of the config file */
    char *htmlmsgfile;          /**< @brief name of the HTML file used for messages */
    char *wdctl_sock;           /**< @brief wdctl path to socket */
    char *internal_sock;                /**< @brief internal path to socket */
    int deltatraffic;   /**< @brief reset each user's traffic (Outgoing and Incoming) value after each Auth operation. */
    int daemon;                 /**< @brief if daemon > 0, use daemon mode */
    char *pidfile;            /**< @brief pid file path of wifidog */
    char *external_interface;   /**< @brief External network interface name for
				     firewall rules */
    char *gw_id;                /**< @brief ID of the Gateway, sent to central
				     server */
    char *gw_interface;         /**< @brief Interface we will accept connections on */
    char *gw_address;           /**< @brief Internal IP address for our web
				     server */
    int gw_port;                /**< @brief Port the webserver will run on */

    t_auth_serv *auth_servers;  /**< @brief Auth servers list */
    char *httpdname;            /**< @brief Name the web server will return when
				     replying to a request */
    int httpdmaxconn;           /**< @brief Used by libhttpd, not sure what it
				     does */
    char *httpdrealm;           /**< @brief HTTP Authentication realm */
    char *httpdusername;        /**< @brief Username for HTTP authentication */
    char *httpdpassword;        /**< @brief Password for HTTP authentication */
    int clienttimeout;          /**< @brief How many CheckIntervals before a client
				     must be re-authenticated */
    int checkinterval;          /**< @brief Frequency the the client timeout check
				     thread will run. */
    int proxy_port;             /**< @brief Transparent proxy port (0 to disable) */
    char *ssl_certs;            /**< @brief Path to SSL certs for auth server
		verification */
    int ssl_verify;             /**< @brief boolean, whether to enable
		auth server certificate verification */
    char *ssl_cipher_list;  /**< @brief List of SSL ciphers allowed. Optional. */
    int ssl_use_sni;            /**< @brief boolean, whether to enable
    auth server for server name indication, the TLS extension */
    t_firewall_ruleset *rulesets;       /**< @brief firewall rules */
    t_trusted_mac *trustedmaclist; /**< @brief list of trusted macs */
    char *arp_table_path; /**< @brief Path to custom ARP table, formatted
        like /proc/net/arp */
    t_popular_server *popular_servers; /**< @brief list of popular servers */
	
	// liudf 20151223 added
	// trusted domain
	t_domain_trusted *domains_trusted; /** domains list, seperate with comma*/
	t_domain_trusted *inner_domains_trusted; /** inner domains list, user cannot configure*/
	t_trusted_mac	*roam_maclist; /** roam mac list*/
	t_untrusted_mac	*mac_blacklist; /** blacklist mac*/
	char 	*htmlredirfile;
	short	js_filter; /** boolean, whether to enable javascript filter url request*/
	short	pool_mode;
	short	thread_number;
	short	queue_size;
} s_config;

/** @brief Get the current gateway configuration */
s_config *config_get_config(void);

/** @brief Initialise the conf system */
void config_init(void);

/** @brief Initialize the variables we override with the command line*/
void config_init_override(void);

/** @brief Reads the configuration file */
void config_read(const char *filename);

/** @brief Check that the configuration is valid */
void config_validate(void);

/** @brief Get the active auth server */
t_auth_serv *get_auth_server(void);

/** @brief Bump server to bottom of the list */
void mark_auth_server_bad(t_auth_serv *);

/** @brief Fetch a firewall rule set. */
t_firewall_rule *get_ruleset(const char *);

// >>>>>liudf added 20151224
/** @brief Get domains_trusted of config */
t_domain_trusted *get_domains_trusted(void);

t_domain_trusted *__add_domain_common(const char *, trusted_domain_t);
t_domain_trusted *add_domain_common(const char *, trusted_domain_t);

t_domain_trusted *__add_user_trusted_domain(const char *);
t_domain_trusted *add_user_trusted_domain(const char *);

t_domain_trusted *__add_inner_trusted_domain(const char*);
t_domain_trusted *add_inner_trusted_domain(const char*);

t_domain_trusted *__add_domain_common(const char *, trusted_domain_t);
t_domain_trusted *add_domain_common(const char *, trusted_domain_t);

void parse_domain_string_common(const char *, trusted_domain_t);

void parse_inner_trusted_domain_string(const char *);

void parse_user_trusted_domain_string(const char *);

/** @brief parse domain's ip and add ip to domain's ip list*/
void parse_trusted_domain_2_ip(t_domain_trusted *p);

/** @brief parse ip from trusted domain list and filled its ip*/
void parse_common_trusted_domain_list(trusted_domain_t);

void parse_user_trusted_domain_list();

void parse_inner_trusted_domain_list();

/** @brief add domain ip pair to inner or user trusted domain list */
void add_domain_ip_pair(const char *, trusted_domain_t);
/** @brief  Clear domains_trusted of config safely */
void clear_trusted_domains(void); 

/** @brief  Clear domains_trusted of config  */
void __clear_trusted_domains(void);


/** @brief  */
void __fix_weixin_http_dns_ip(void);


/** @brief parse roam mac list, for wdctl use*/
void parse_roam_mac_list(const char *); 

void __clear_roam_mac_list();

void clear_roam_mac_list();

t_trusted_mac *get_roam_maclist();

int is_roaming(const char *mac);

// trustedmaclist operation, for wdctl use
void parse_trusted_mac_list(const char *);

void __clear_trusted_mac_list();

void clear_trusted_mac_list();

// mac blacklist operation, for wdctl use
void parse_untrusted_mac_list(const char*);

void __clear_untrusted_mac_list();

void clear_untrusted_mac_list();

// common api
void add_mac(const char *, mac_choice_t );

void parse_mac_list(const char *, mac_choice_t);

// online clients
int 	g_online_clients;
char 	*g_version;
char	*g_type; // hardware type
char	*g_name; // firmware name
char	*g_channel_path;
char	*g_ssid;
// <<< liudf added end

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
