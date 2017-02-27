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
/** @file conf.c
  @brief Config file parsing
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2007 Benoit Grégoire, Technologies Coeus inc.
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#include <pthread.h>

#include <string.h>
#include <ctype.h>

#include <netdb.h>
#include <arpa/inet.h>

#include <setjmp.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "simple_http.h"
#include "ezxml.h"
#include "util.h"
#include "wd_util.h"


//>>> liudf added 20160114
const char	*g_inner_trusted_domains = "www.kunteng.org,cloud.kunteng.org,mqtt.kunteng.org,log1.kunteng.org";

/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

// liudf added 20160409
// Mutex for trusted domains; used by domains parese releated 
pthread_mutex_t domains_mutex = PTHREAD_MUTEX_INITIALIZER;

/** @internal
 * A flag.  If set to 1, there are missing or empty mandatory parameters in the config
 */
static int missing_parms;

/** @internal
 The different configuration options */
typedef enum {
    oBadOption,
    oDaemon,
    oDebugLevel,
    oExternalInterface,
    oGatewayID,
    oGatewayInterface,
    oGatewayAddress,
    oGatewayPort,
    oDeltaTraffic,
    oAuthServer,
    oAuthServHostname,
    oAuthServSSLAvailable,
    oAuthServSSLPort,
    oAuthServHTTPPort,
    oAuthServPath,
	oAuthServConnectTimeout,
    oAuthServLoginScriptPathFragment,
    oAuthServPortalScriptPathFragment,
    oAuthServMsgScriptPathFragment,
    oAuthServPingScriptPathFragment,
    oAuthServAuthScriptPathFragment,
    oHTTPDMaxConn,
    oHTTPDName,
    oHTTPDRealm,
    oHTTPDUsername,
    oHTTPDPassword,
    oClientTimeout,
    oCheckInterval,
    oWdctlSocket,
    oSyslogFacility,
    oFirewallRule,
    oFirewallRuleSet,
    oTrustedMACList,
    oPopularServers,
    oHtmlMessageFile,
    oProxyPort,
    oSSLPeerVerification,
    oSSLCertPath,
    oSSLAllowedCipherList,
    oSSLUseSNI,
	
	// >>>>liudf added 20151224
	oTrustedPanDomains,
	oTrustedDomains,
	oInnerTrustedDomains,
	oUntrustedMACList,
	oJsFilter,
	oPoolMode,
	oThreadNumber,
	oQueueSize,
	oWiredPassed,
	oParseChecked,
	oTrustedIpList,
	oNoAuth,
	oGatewayHttpsPort,
	oWorkMode,
    oUpdateDomainInterval,
	// <<< liudf added end
} OpCodes;

/** @internal
 The config file keywords for the different configuration options */
static const struct {
    const char *name;
    OpCodes opcode;
} keywords[] = {
    {
    "deltatraffic", oDeltaTraffic}, {
    "daemon", oDaemon}, {
    "debuglevel", oDebugLevel}, {
    "externalinterface", oExternalInterface}, {
    "gatewayid", oGatewayID}, {
    "gatewayinterface", oGatewayInterface}, {
    "gatewayaddress", oGatewayAddress}, {
    "gatewayport", oGatewayPort}, {
    "authserver", oAuthServer}, {
    "httpdmaxconn", oHTTPDMaxConn}, {
    "httpdname", oHTTPDName}, {
    "httpdrealm", oHTTPDRealm}, {
    "httpdusername", oHTTPDUsername}, {
    "httpdpassword", oHTTPDPassword}, {
    "clienttimeout", oClientTimeout}, {
    "checkinterval", oCheckInterval}, {
    "syslogfacility", oSyslogFacility}, {
    "wdctlsocket", oWdctlSocket}, {
    "hostname", oAuthServHostname}, {
    "sslavailable", oAuthServSSLAvailable}, {
    "sslport", oAuthServSSLPort}, {
    "httpport", oAuthServHTTPPort}, {
    "path", oAuthServPath}, {
	"connectTimeout", oAuthServConnectTimeout}, {
    "loginscriptpathfragment", oAuthServLoginScriptPathFragment}, {
    "portalscriptpathfragment", oAuthServPortalScriptPathFragment}, {
    "msgscriptpathfragment", oAuthServMsgScriptPathFragment}, {
    "pingscriptpathfragment", oAuthServPingScriptPathFragment}, {
    "authscriptpathfragment", oAuthServAuthScriptPathFragment}, {
    "firewallruleset", oFirewallRuleSet}, {
    "firewallrule", oFirewallRule}, {
    "trustedmaclist", oTrustedMACList}, {
    "popularservers", oPopularServers}, {
    "htmlmessagefile", oHtmlMessageFile}, {
    "proxyport", oProxyPort}, {
    "sslpeerverification", oSSLPeerVerification}, {
    "sslcertpath", oSSLCertPath}, {
    "sslallowedcipherlist", oSSLAllowedCipherList}, {
    "sslusesni", oSSLUseSNI}, {
	
	//>>>>> liudf added 20151224
	"trustedPanDomains", oTrustedPanDomains}, {
	"trustedDomains", oTrustedDomains}, {
	"untrustedmaclist", oUntrustedMACList}, {
	"jsFilter", oJsFilter}, {
	"poolMode", oPoolMode}, {
	"threadNumber", oThreadNumber}, {
	"queueSize", oQueueSize}, {
	"wiredPassed", oWiredPassed}, {
	"parseChecked", oParseChecked}, {
	"trustedIpList", oTrustedIpList}, {
	"noAuth", oNoAuth}, {
	"gatewayHttpsPort", oGatewayHttpsPort}, {
	"workMode", oWorkMode}, {
    "updateDomainInterval", oUpdateDomainInterval}, {
	// <<<< liudf added end
NULL, oBadOption},};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static int _parse_firewall_rule(const char *, char *);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);
static void parse_popular_servers(const char *);
static void validate_popular_servers(void);
static void add_popular_server(const char *);

static OpCodes config_parse_token(const char *, const char *, int);


/** Accessor for the current gateway configuration
@return:  A pointer to the current config.  The pointer isn't opaque, but should be treated as READ-ONLY
 */
s_config *
config_get_config(void)
{
    return &config;
}

/** Sets the default config parameters and initialises the configuration system */
void
config_init(void)
{
    debug(LOG_DEBUG, "Setting default config parameters");
    config.configfile = safe_strdup(DEFAULT_CONFIGFILE);
    config.htmlmsgfile = safe_strdup(DEFAULT_HTMLMSGFILE);
    config.httpdmaxconn = DEFAULT_HTTPDMAXCONN;
    config.external_interface = NULL;
    config.gw_id = DEFAULT_GATEWAYID;
    config.gw_interface = NULL;
    config.gw_address = NULL;
    config.gw_port = DEFAULT_GATEWAYPORT;
    config.auth_servers = NULL;
    config.httpdname = NULL;
    config.httpdrealm = DEFAULT_HTTPDNAME;
    config.httpdusername = NULL;
    config.httpdpassword = NULL;
    config.clienttimeout = DEFAULT_CLIENTTIMEOUT;
    config.checkinterval = DEFAULT_CHECKINTERVAL;
    config.daemon = -1;
    config.pidfile = NULL;
    config.wdctl_sock = safe_strdup(DEFAULT_WDCTL_SOCK);
    config.internal_sock = safe_strdup(DEFAULT_INTERNAL_SOCK);
    config.rulesets = NULL;
    config.trustedmaclist = NULL;
    config.popular_servers = NULL;
    config.proxy_port = 0;
    config.ssl_certs = safe_strdup(DEFAULT_AUTHSERVSSLCERTPATH);
    config.ssl_verify = DEFAULT_AUTHSERVSSLPEERVER;
    config.deltatraffic = DEFAULT_DELTATRAFFIC;
    config.ssl_cipher_list = NULL;
    config.arp_table_path = safe_strdup(DEFAULT_ARPTABLE);
    config.ssl_use_sni = DEFAULT_AUTHSERVSSLSNI;
	//>>> liudf 20160104 added
	config.htmlredirfile 			= safe_strdup(DEFAULT_REDIRECTFILE);
	config.internet_offline_file	= safe_strdup(DEFAULT_INTERNET_OFFLINE_FILE);
	config.authserver_offline_file	= safe_strdup(DEFAULT_AUTHSERVER_OFFLINE_FILE);
	config.js_filter 		= 1; // default enable it
	config.pool_mode		= 1;
	config.thread_number 	= 10; // only valid when poolMode == 1
	config.queue_size 		= 30; // only valid when poolMode == 1
	config.wired_passed		= 1; // default wired device no need login
	config.parse_checked	= 1; // before parse domain's ip; fping check it
	config.no_auth 			= 0; // 
	config.work_mode		= 0;
    config.update_domain_interval  = 0;
	
	t_https_server *https_server	= (t_https_server *)malloc(sizeof(t_https_server));
	memset(https_server, 0, sizeof(t_https_server));
	https_server->gw_https_port	= 8443;
	https_server->ca_crt_file	= safe_strdup(DEFAULT_CA_CRT_FILE);
	https_server->svr_crt_file	= safe_strdup(DEFAULT_SVR_CRT_FILE);
	https_server->svr_key_file	= safe_strdup(DEFAULT_SVR_KEY_FILE);
	
	config.https_server	= https_server;

    t_http_server *http_server  = (t_http_server *)malloc(sizeof(t_http_server));
    memset(http_server, 0, sizeof(t_http_server));
    http_server->gw_http_port   = 8403;
    http_server->base_path      = safe_strdup(DEFAULT_WWW_PATH);

    config.http_server  = http_server;

    t_mqtt_server *mqtt_server = (t_mqtt_server *)malloc(sizeof(sizeof(t_mqtt_server)));
    memset(mqtt_server, 0, sizeof(t_mqtt_server));
    mqtt_server->hostname   = safe_strdup(DEFAULT_MQTT_SERVER);
    mqtt_server->port       = 8883;
    mqtt_server->cafile     = safe_strdup(DEFAULT_CA_CRT_FILE);
    mqtt_server->crtfile    = NULL;
    mqtt_server->keyfile    = NULL;
    config.mqtt_server  = mqtt_server;
	//<<<

    debugconf.log_stderr = 1;
    debugconf.debuglevel = DEFAULT_DEBUGLEVEL;
    debugconf.syslog_facility = DEFAULT_SYSLOG_FACILITY;
    debugconf.log_syslog = DEFAULT_LOG_SYSLOG;
}

/**
 * If the command-line didn't provide a config, use the default.
 */
void
config_init_override(void)
{
    if (config.daemon == -1) {
        config.daemon = DEFAULT_DAEMON;
        if (config.daemon > 0) {
            debugconf.log_stderr = 0;
        }
    }
}

/** @internal
Parses a single token from the config file
*/
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
    int i;

    for (i = 0; keywords[i].name; i++)
        if (strcasecmp(cp, keywords[i].name) == 0)
            return keywords[i].opcode;

    debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
    return oBadOption;
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE * file, const char *filename, int *linenum)
{
    char *host = NULL,
        *path = NULL,
        *loginscriptpathfragment = NULL,
        *portalscriptpathfragment = NULL,
        *msgscriptpathfragment = NULL,
        *pingscriptpathfragment = NULL, *authscriptpathfragment = NULL, line[MAX_BUF], *p1, *p2;
    int http_port, ssl_port, ssl_available, opcode;
	int connect_timeout;
    t_auth_serv *new, *tmp;

    /* Defaults */
    path = safe_strdup(DEFAULT_AUTHSERVPATH);
    loginscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
    portalscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
    msgscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
    pingscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
    authscriptpathfragment = safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
    http_port = DEFAULT_AUTHSERVPORT;
    ssl_port = DEFAULT_AUTHSERVSSLPORT;
    ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;
	connect_timeout = 5; // 5 seconds to wait

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* trim all blanks at the end of the line */
        for (p2 = (p2 != NULL ? p2 - 1 : &line[MAX_BUF - 2]); isblank(*p2) && p2 > p1; p2--) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            switch (opcode) {
            case oAuthServHostname:
                /* Coverity rightfully pointed out we could have duplicates here. */
                if (NULL != host)
                    free(host);
                host = safe_strdup(p2);
                break;
            case oAuthServPath:
                free(path);
                path = safe_strdup(p2);
                break;
			case oAuthServConnectTimeout:
				connect_timeout = atoi(p2);
				break;	
            case oAuthServLoginScriptPathFragment:
                free(loginscriptpathfragment);
                loginscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServPortalScriptPathFragment:
                free(portalscriptpathfragment);
                portalscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServMsgScriptPathFragment:
                free(msgscriptpathfragment);
                msgscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServPingScriptPathFragment:
                free(pingscriptpathfragment);
                pingscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServAuthScriptPathFragment:
                free(authscriptpathfragment);
                authscriptpathfragment = safe_strdup(p2);
                break;
            case oAuthServSSLPort:
                ssl_port = atoi(p2);
                break;
            case oAuthServHTTPPort:
                http_port = atoi(p2);
				if (http_port == 443)
					ssl_available = 1;
                break;
            case oAuthServSSLAvailable:
                ssl_available = parse_boolean_value(p2);
                if (ssl_available < 0) {
                    debug(LOG_WARNING, "Bad syntax for Parameter: SSLAvailable on line %d " "in %s."
                        "The syntax is yes or no." , *linenum, filename);
                    exit(-1);
                }
                break;
            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                exit(-1);
                break;
            }
        }
    }

    /* only proceed if we have an host and a path */
    if (host == NULL) {
        free(path);
        free(authscriptpathfragment);
        free(pingscriptpathfragment);
        free(msgscriptpathfragment);
        free(portalscriptpathfragment);
        free(loginscriptpathfragment);
        return;
    }

    debug(LOG_DEBUG, "Adding %s:%d (SSL: %d) %s to the auth server list", host, http_port, ssl_port, path);

    /* Allocate memory */
    new = safe_malloc(sizeof(t_auth_serv));

    /* Fill in struct */
    new->authserv_hostname = host;
    new->authserv_use_ssl = ssl_available;
    new->authserv_path = path;
	new->authserv_connect_timeout = connect_timeout;
    new->authserv_login_script_path_fragment = loginscriptpathfragment;
    new->authserv_portal_script_path_fragment = portalscriptpathfragment;
    new->authserv_msg_script_path_fragment = msgscriptpathfragment;
    new->authserv_ping_script_path_fragment = pingscriptpathfragment;
    new->authserv_auth_script_path_fragment = authscriptpathfragment;
    new->authserv_http_port = http_port;
    new->authserv_ssl_port 	= ssl_port;
	new->authserv_fd		= -1;
	new->authserv_fd_ref	= 0;

    /* If it's the first, add to config, else append to last server */
    if (config.auth_servers == NULL) {
        config.auth_servers = new;
    } else {
        for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next) ;
        tmp->next = new;
    }

    debug(LOG_DEBUG, "Auth server added");
}

/**
Advance to the next word
@param s string to parse, this is the next_word pointer, the value of s
	 when the macro is called is the current word, after the macro
	 completes, s contains the beginning of the NEXT word, so you
	 need to save s to something else before doing TO_NEXT_WORD
@param e should be 0 when calling TO_NEXT_WORD(), it'll be changed to 1
	 if the end of the string is reached.
*/
#define TO_NEXT_WORD(s, e) do { \
	while (*s != '\0' && !isblank(*s)) { \
		s++; \
	} \
	if (*s != '\0') { \
		*s = '\0'; \
		s++; \
		while (isblank(*s)) \
			s++; \
	} else { \
		e = 1; \
	} \
} while (0)

/** @internal
Parses firewall rule set information
*/
static void
parse_firewall_ruleset(const char *ruleset, FILE * file, const char *filename, int *linenum)
{
    char line[MAX_BUF], *p1, *p2;
    int opcode;

    debug(LOG_DEBUG, "Adding Firewall Rule Set %s", ruleset);

    /* Parsing loop */
    while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
        (*linenum)++;           /* increment line counter. */

        /* skip leading blank spaces */
        for (p1 = line; isblank(*p1); p1++) ;

        /* End at end of line */
        if ((p2 = strchr(p1, '#')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\r')) != NULL) {
            *p2 = '\0';
        } else if ((p2 = strchr(p1, '\n')) != NULL) {
            *p2 = '\0';
        }

        /* next, we coopt the parsing of the regular config */
        if (strlen(p1) > 0) {
            p2 = p1;
            /* keep going until word boundary is found. */
            while ((*p2 != '\0') && (!isblank(*p2)))
                p2++;

            /* Terminate first word. */
            *p2 = '\0';
            p2++;

            /* skip all further blanks. */
            while (isblank(*p2))
                p2++;

            /* Get opcode */
            opcode = config_parse_token(p1, filename, *linenum);

            debug(LOG_DEBUG, "p1 = [%s]; p2 = [%s]", p1, p2);

            switch (opcode) {
            case oFirewallRule:
                _parse_firewall_rule(ruleset, p2);
                break;

            case oBadOption:
            default:
                debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
                debug(LOG_ERR, "Exiting...");
                exit(-1);
                break;
            }
        }
    }

    debug(LOG_DEBUG, "Firewall Rule Set %s added.", ruleset);
}

/** @internal
Helper for parse_firewall_ruleset.  Parses a single rule in a ruleset
*/
static int
_parse_firewall_rule(const char *ruleset, char *leftover)
{
    int i;
    t_firewall_target target = TARGET_REJECT;     /**< firewall target */
    int all_nums = 1;     /**< If 0, port contained non-numerics */
    int finished = 0;     /**< reached end of line */
    char *token = NULL;     /**< First word */
    char *port = NULL;     /**< port to open/block */
    char *protocol = NULL;     /**< protocol to block, tcp/udp/icmp */
    char *mask = NULL;     /**< Netmask */
    char *other_kw = NULL;     /**< other key word */
    int mask_is_ipset = 0;
    t_firewall_ruleset *tmpr;
    t_firewall_ruleset *tmpr2;
    t_firewall_rule *tmp;
    t_firewall_rule *tmp2;

    debug(LOG_DEBUG, "leftover: %s", leftover);

    /* lower case */
    for (i = 0; *(leftover + i) != '\0' && (*(leftover + i) = tolower((unsigned char)*(leftover + i))); i++) ;

    token = leftover;
    TO_NEXT_WORD(leftover, finished);

    /* Parse token */
    if (!strcasecmp(token, "block") || finished) {
        target = TARGET_REJECT;
    } else if (!strcasecmp(token, "drop")) {
        target = TARGET_DROP;
    } else if (!strcasecmp(token, "allow")) {
        target = TARGET_ACCEPT;
    } else if (!strcasecmp(token, "log")) {
        target = TARGET_LOG;
    } else if (!strcasecmp(token, "ulog")) {
        target = TARGET_ULOG;
    } else {
        debug(LOG_ERR, "Invalid rule type %s, expecting " "\"block\",\"drop\",\"allow\",\"log\" or \"ulog\"", token);
        return -1;
    }

    /* Parse the remainder */
    /* Get the protocol */
    if (strncmp(leftover, "tcp", 3) == 0 || strncmp(leftover, "udp", 3) == 0 || strncmp(leftover, "icmp", 4) == 0) {
        protocol = leftover;
        TO_NEXT_WORD(leftover, finished);
    }

    /* Get the optional port or port range */
    if (strncmp(leftover, "port", 4) == 0) {
        TO_NEXT_WORD(leftover, finished);
        /* Get port now */
        port = leftover;
        TO_NEXT_WORD(leftover, finished);
        for (i = 0; *(port + i) != '\0'; i++)
            if (!isdigit((unsigned char)*(port + i)) && ((unsigned char)*(port + i) != ':'))
                all_nums = 0;   /*< No longer only digits */
        if (!all_nums) {
            debug(LOG_ERR, "ERROR: wifidog config file, section FirewallRuleset %s. " "Invalid port %s", ruleset, port);
            return -3;          /*< Fail */
        }
    }

    /* Now, further stuff is optional */
    if (!finished) {
        /* should be exactly "to" or "to-ipset" */
        other_kw = leftover;
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            /* Get arg now and check validity in next section */
            mask = leftover;
        }
        if (strncmp(other_kw, "to-ipset", 8) == 0 && !finished) {
            mask_is_ipset = 1;
        }
        TO_NEXT_WORD(leftover, finished);
        if (!finished) {
            debug(LOG_WARNING, "Ignoring trailining string after successfully parsing rule: %s", leftover);
        }
    }
    /* Generate rule record */
    tmp = safe_malloc(sizeof(t_firewall_rule));
    tmp->target = target;
    tmp->mask_is_ipset = mask_is_ipset;
    if (protocol != NULL)
        tmp->protocol = safe_strdup(protocol);
    if (port != NULL)
        tmp->port = safe_strdup(port);
    if (mask == NULL)
        tmp->mask = safe_strdup("0.0.0.0/0");
    else
        tmp->mask = safe_strdup(mask);

    debug(LOG_DEBUG, "Adding Firewall Rule %s %s port %s to %s", token, tmp->protocol, tmp->port, tmp->mask);

    /* Append the rule record */
    if (config.rulesets == NULL) {
        config.rulesets = safe_malloc(sizeof(t_firewall_ruleset));
        config.rulesets->name = safe_strdup(ruleset);
        tmpr = config.rulesets;
    } else {
        tmpr2 = tmpr = config.rulesets;
        while (tmpr != NULL && (strcmp(tmpr->name, ruleset) != 0)) {
            tmpr2 = tmpr;
            tmpr = tmpr->next;
        }
        if (tmpr == NULL) {
            /* Rule did not exist */
            tmpr = safe_malloc(sizeof(t_firewall_ruleset));
            tmpr->name = safe_strdup(ruleset);
            tmpr2->next = tmpr;
        }
    }

    /* At this point, tmpr == current ruleset */
    if (tmpr->rules == NULL) {
        /* No rules... */
        tmpr->rules = tmp;
    } else {
        tmp2 = tmpr->rules;
        while (tmp2->next != NULL)
            tmp2 = tmp2->next;
        tmp2->next = tmp;
    }

    return 1;
}

t_firewall_rule *
get_ruleset(const char *ruleset)
{
    t_firewall_ruleset *tmp;

    for (tmp = config.rulesets; tmp != NULL && strcmp(tmp->name, ruleset) != 0; tmp = tmp->next) ;

    if (tmp == NULL)
        return NULL;

    return (tmp->rules);
}

/**
@param filename Full path of the configuration file to be read 
*/
void
config_read(const char *filename)
{
    FILE *fd;
    char line[MAX_BUF] = {0}, *s, *p1, *p2, *rawarg = NULL;
    int linenum = 0, opcode, value;
    size_t len;

    debug(LOG_INFO, "Reading configuration file '%s'", filename);

    if (!(fd = fopen(filename, "r"))) {
        debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filename);
        exit(1);
    }

    while (!feof(fd) && fgets(line, MAX_BUF, fd)) {
        linenum++;
        s = line;

        if (s[strlen(s) - 1] == '\n')
            s[strlen(s) - 1] = '\0';

        if ((p1 = strchr(s, ' '))) {
            p1[0] = '\0';
        } else if ((p1 = strchr(s, '\t'))) {
            p1[0] = '\0';
        }

        if (p1) {
            p1++;

            // Trim leading spaces
            len = strlen(p1);
            while (*p1 && len) {
                if (*p1 == ' ')
                    p1++;
                else
                    break;
                len = strlen(p1);
            }
            rawarg = safe_strdup(p1);
            if ((p2 = strchr(p1, ' '))) {
                p2[0] = '\0';
            } else if ((p2 = strstr(p1, "\r\n"))) {
                p2[0] = '\0';
            } else if ((p2 = strchr(p1, '\n'))) {
                p2[0] = '\0';
            }
        }

        if (p1 && p1[0] != '\0') {
            /* Strip trailing spaces */

            if ((strncmp(s, "#", 1)) != 0) {
                debug(LOG_DEBUG, "Parsing token: %s, " "value: %s", s, p1);
                opcode = config_parse_token(s, filename, linenum);

                switch (opcode) {
                case oDeltaTraffic:
                    config.deltatraffic = parse_boolean_value(p1);
                    break;
                case oDaemon:
                    if (config.daemon == -1 && ((value = parse_boolean_value(p1)) != -1)) {
                        config.daemon = value;
                        if (config.daemon > 0) {
                            debugconf.log_stderr = 0;
                        } else {
                            debugconf.log_stderr = 1;
                        }
                    }
                    break;
                case oExternalInterface:
                    config.external_interface = safe_strdup(p1);
                    break;
                case oGatewayID:
                    config.gw_id = safe_strdup(p1);
                    break;
                case oGatewayInterface:
                    config.gw_interface = safe_strdup(p1);
                    break;
                case oGatewayAddress:
                    config.gw_address = safe_strdup(p1);
                    break;
                case oGatewayPort:
                    sscanf(p1, "%d", &config.gw_port);
                    break;
                case oAuthServer:
                    parse_auth_server(fd, filename, &linenum);
                    break;
                case oFirewallRuleSet:
                    parse_firewall_ruleset(p1, fd, filename, &linenum);
                    break;
                case oTrustedMACList:
                    parse_trusted_mac_list(p1);
                    break;
                case oPopularServers:
                    parse_popular_servers(rawarg);
                    break;
                case oHTTPDName:
                    config.httpdname = safe_strdup(p1);
                    break;
                case oHTTPDMaxConn:
                    sscanf(p1, "%d", &config.httpdmaxconn);
                    break;
                case oHTTPDRealm:
                    config.httpdrealm = safe_strdup(p1);
                    break;
                case oHTTPDUsername:
                    config.httpdusername = safe_strdup(p1);
                    break;
                case oHTTPDPassword:
                    config.httpdpassword = safe_strdup(p1);
                    break;
                case oCheckInterval:
                    sscanf(p1, "%d", &config.checkinterval);
                    break;
                case oWdctlSocket:
                    free(config.wdctl_sock);
                    config.wdctl_sock = safe_strdup(p1);
                    break;
                case oClientTimeout:
                    sscanf(p1, "%d", &config.clienttimeout);
                    break;
                case oSyslogFacility:
                    sscanf(p1, "%d", &debugconf.syslog_facility);
                    break;
                case oHtmlMessageFile:
                    config.htmlmsgfile = safe_strdup(p1);
                    break;
                case oProxyPort:
                    sscanf(p1, "%d", &config.proxy_port);
                    break;
                case oSSLCertPath:
                    config.ssl_certs = safe_strdup(p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLCertPath is set but not SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLPeerVerification:
                    config.ssl_verify = parse_boolean_value(p1);
                    if (config.ssl_verify < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLPeerVerification on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLPeerVerification is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLAllowedCipherList:
                    config.ssl_cipher_list = safe_strdup(p1);
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLAllowedCipherList is set but no SSL compiled in. Ignoring!");
#endif
                    break;
                case oSSLUseSNI:
                    config.ssl_use_sni = parse_boolean_value(p1);
                    if (config.ssl_use_sni < 0) {
                        debug(LOG_WARNING, "Bad syntax for Parameter: SSLUseSNI on line %d " "in %s."
                            "The syntax is yes or no." , linenum, filename);
                        exit(-1);
                    }
#ifndef USE_CYASSL
                    debug(LOG_WARNING, "SSLUseSNI is set but no SSL compiled in. Ignoring!");
#else
#ifndef HAVE_SNI
                    debug(LOG_WARNING, "SSLUseSNI is set but no CyaSSL SNI enabled. Ignoring!");
#endif
#endif
                    break;
				// >>> liudf added 20151224
				case oTrustedPanDomains:
					parse_trusted_pan_domain_string(rawarg);
					break;
				case oTrustedDomains:
					parse_user_trusted_domain_string(rawarg);
					break;
				case oUntrustedMACList:
					parse_untrusted_mac_list(p1);
					break;
				case oJsFilter:
                    config.js_filter = parse_boolean_value(p1);
					break;
				case oPoolMode:
					config.pool_mode = parse_boolean_value(p1);
					break;
				case oThreadNumber:
                    sscanf(p1, "%hd", &config.thread_number);
					break;
				case oQueueSize:
                    sscanf(p1, "%hd", &config.queue_size);
					break;
				case oWiredPassed:
                    config.wired_passed = parse_boolean_value(p1);
					break;
				case oParseChecked:
					config.parse_checked = parse_boolean_value(p1);
					break;
				case oTrustedIpList:
					add_trusted_ip_list(rawarg);
					break;
				case oNoAuth:
					config.no_auth = parse_boolean_value(p1);	
					break;
				case oGatewayHttpsPort:
					sscanf(p1, "%hu", &config.https_server->gw_https_port);
					break;
				case oWorkMode:
					sscanf(p1, "%hu", &config.work_mode);
					break;
                case oUpdateDomainInterval:
                    sscanf(p1, "%d", &config.update_domain_interval);
                    break;
				// <<< liudf added end
                case oBadOption:
                    /* FALL THROUGH */
                default:
                    debug(LOG_ERR, "Bad option on line %d " "in %s.", linenum, filename);
                    debug(LOG_ERR, "Exiting...");
                    exit(-1);
                    break;
                }
            }
        }
        if (rawarg) {
            free(rawarg);
            rawarg = NULL;
        }
    }
	
	// liudf added 20160125
	// parse inner trusted domain string
	parse_inner_trusted_domain_string(g_inner_trusted_domains);

    if (config.httpdusername && !config.httpdpassword) {
        debug(LOG_ERR, "HTTPDUserName requires a HTTPDPassword to be set.");
        exit(-1);
    }

    fclose(fd);
}

/** @internal
Parses a boolean value from the config file
*/
static int
parse_boolean_value(char *line)
{
    if (strcasecmp(line, "yes") == 0) {
        return 1;
    }
    if (strcasecmp(line, "no") == 0) {
        return 0;
    }
    if (strcmp(line, "1") == 0) {
        return 1;
    }
    if (strcmp(line, "0") == 0) {
        return 0;
    }

    return -1;
}

/**
 * Parse possiblemac to see if it is valid MAC address format */
static int
check_mac_format(const char *possiblemac)
{
    char hex2[3];
	if(!possiblemac || strlen(possiblemac) != 17)
		return 0;

    return
        sscanf(possiblemac,
               "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

//>>> liudf added 20160114
/** @internal
 * 
 */

static void 
remove_online_client(const char *mac)
{
	debug(LOG_DEBUG, "remove mac [%s] from client list", mac);

	t_client *client = NULL;
	LOCK_CLIENT_LIST();
	if((client = client_list_find_by_mac(mac)) != NULL) {
		fw_deny(client);        
    	client_list_remove(client);
		client_free_node(client);
	}	
	UNLOCK_CLIENT_LIST();
}

static void
add_roam_mac(const char *mac)
{
	debug(LOG_DEBUG, "Adding MAC address [%s] to roam mac list", mac);

	if (config.roam_maclist == NULL) {
		config.roam_maclist = safe_malloc(sizeof(t_trusted_mac));
		config.roam_maclist->mac = safe_strdup(mac);
		config.roam_maclist->next = NULL;
	} else {
		int skipmac;
		/* Advance to the last entry */
		t_trusted_mac *p = config.roam_maclist;
		skipmac = 0;
		while (p != NULL) {
			if (0 == strcmp(p->mac, mac)) {
				skipmac = 1;
			}
			p = p->next;
		}
		if (!skipmac) {
			p = safe_malloc(sizeof(t_trusted_mac));
			p->mac = safe_strdup(mac);
			p->next = config.roam_maclist;
			config.roam_maclist = p;
		} else {
			debug(LOG_ERR,
				"MAC address [%s] already on roam mac list.  ",
				mac);
		}
	}
}

static void
remove_trusted_mac(const char *mac)
{
	t_trusted_mac *p = config.trustedmaclist, *p1 = p;
	debug(LOG_DEBUG, "Remove MAC address [%s] to trusted mac list", mac);
	if(config.trustedmaclist== NULL)
		return;

	LOCK_CONFIG();
	
	while(p) {
		if(strcmp(p->mac, mac) == 0) {
			break;
		}
		p1 = p;
		p = p->next;
	}	
	
	if(p) {
		if(p == config.trustedmaclist)
			config.trustedmaclist = p->next;
		else
			p1->next = p->next;
		free(p->mac);
		if(p->ip) free(p->ip);
		free(p);	
	}
	
	UNLOCK_CONFIG();
}

t_trusted_mac *
add_trusted_mac(const char *mac)
{
	t_trusted_mac *pret = NULL;
	
	remove_online_client(mac);

	debug(LOG_DEBUG, "Adding MAC address [%s] to trusted mac list", mac);
			
	LOCK_CONFIG();

	if (config.trustedmaclist == NULL) {
		config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
		config.trustedmaclist->mac = safe_strdup(mac);
		config.trustedmaclist->next = NULL;
		pret = config.trustedmaclist;
	} else {
		int skipmac;
		/* Advance to the last entry */
		t_trusted_mac *p = config.trustedmaclist;
		skipmac = 0;
		while (p != NULL) {
			if (0 == strcmp(p->mac, mac)) {
				skipmac = 1;
			}
			p = p->next;
		}
		if (!skipmac) {
			p = safe_malloc(sizeof(t_trusted_mac));
			p->mac = safe_strdup(mac);
			p->next = config.trustedmaclist;
			config.trustedmaclist = p;
			pret = p;
		} else {
			debug(LOG_ERR,
				"MAC address [%s] already on trusted mac list.  ",
				mac);
		}
	}

	UNLOCK_CONFIG();
	return pret;
}

static void
add_untrusted_mac(const char *mac)
{
	remove_online_client(mac);

	debug(LOG_DEBUG, "Adding MAC address [%s] to untrusted mac list", mac);

	if (config.mac_blacklist == NULL) {
		config.mac_blacklist = safe_malloc(sizeof(t_untrusted_mac));
		config.mac_blacklist->mac = safe_strdup(mac);
		config.mac_blacklist->next = NULL;
	} else {
		int skipmac;
		/* Advance to the last entry */
		t_untrusted_mac *p = config.mac_blacklist;
		skipmac = 0;
		while (p != NULL) {
			if (0 == strcmp(p->mac, mac)) {
				skipmac = 1;
			}
			p = p->next;
		}
		if (!skipmac) {
			p = safe_malloc(sizeof(t_untrusted_mac));
			p->mac = safe_strdup(mac);
			p->next = config.mac_blacklist;
			config.mac_blacklist = p;
		} else {
			debug(LOG_ERR,
				"MAC address [%s] already on untrusted mac list.  ",
				mac);
		}
	}
}

static void
remove_untrusted_mac(const char *mac)
{
	t_untrusted_mac *p = config.mac_blacklist, *p1 = p;
	debug(LOG_DEBUG, "Remove MAC address [%s] to untrusted mac list", mac);
	if(config.mac_blacklist == NULL)
		return;

	LOCK_CONFIG();
	
	while(p) {
		if(strcmp(p->mac, mac) == 0) {
			break;
		}
		p1 = p;
		p = p->next;
	}	
	
	if(p) {
		if(p == config.mac_blacklist)
			config.mac_blacklist = p->next;
		else
			p1->next = p->next;
		free(p->mac);
		if(p->ip) free(p->ip);
		free(p);	
	}

	UNLOCK_CONFIG();
}

void
remove_mac(const char *mac, mac_choice_t which)
{
	switch(which) {
	case TRUSTED_MAC:
		remove_trusted_mac(mac);
		break;
	case UNTRUSTED_MAC:
		remove_untrusted_mac(mac);
		break;
	case ROAM_MAC:
		// no operation
		break;
	}
}

void
add_mac(const char *mac, mac_choice_t which)
{
	switch(which) {
	case TRUSTED_MAC:
		add_trusted_mac(mac);
		break;
	case UNTRUSTED_MAC:
		add_untrusted_mac(mac);
		break;
	case ROAM_MAC:
		add_roam_mac(mac);
		break;
	}
}

/* *
 * action: 1 add, 0 remove
 */
static void
parse_mac_list_action(const char *ptr, mac_choice_t which, int action)
{
    char *ptrcopy = NULL, *pt = NULL;
    char *possiblemac = NULL;
	int  len = 0;

    debug(LOG_DEBUG, "Parsing string [%s] for  MAC addresses", ptr);
	
	while(isspace(*ptr))
		ptr++;
	
	if(is_valid_mac(ptr)) {
		// in case only one mac
    	debug(LOG_DEBUG, "add|remove [%d] mac [%s] to list", action, ptr);
		if(action)
			add_mac(ptr, which);
		else
			remove_mac(ptr, which);
		return;
	}

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);
	pt = ptrcopy;
	
	len = strlen(ptrcopy);
	while(isspace(ptrcopy[--len]))
		ptrcopy[len] = '\0';
	
    while ((possiblemac = strsep(&ptrcopy, ","))) {
        /* check for valid format */
		if (is_valid_mac(possiblemac)) {
			debug(LOG_DEBUG, "add|remove mac [%s]", possiblemac);
			if(action)
				add_mac(possiblemac, which);
			else
				remove_mac(possiblemac, which);
		} else
            debug(LOG_ERR, "[%s] not a valid MAC address ", possiblemac);
    }

    free(pt);
}

static void
parse_remove_mac_list(const char *ptr, mac_choice_t which)
{
	parse_mac_list_action(ptr, which, 0);;
}

void
parse_mac_list(const char *ptr, mac_choice_t which)
{
	parse_mac_list_action(ptr, which, 1);
}

void
parse_trusted_mac_list(const char *pstr)
{
	parse_mac_list(pstr, TRUSTED_MAC);
}

void
parse_del_trusted_mac_list(const char *pstr)
{
	parse_remove_mac_list(pstr, TRUSTED_MAC);
}

void
parse_untrusted_mac_list(const char *pstr)
{
	parse_mac_list(pstr, UNTRUSTED_MAC);
}

void
parse_del_untrusted_mac_list(const char *pstr)
{
	parse_remove_mac_list(pstr, UNTRUSTED_MAC);
}

void 
parse_roam_mac_list(const char *pstr)
{
	parse_mac_list(pstr, ROAM_MAC);
}

//<<< liudf added end

/** @internal
 * Add a popular server to the list. It prepends for simplicity.
 * @param server The hostname to add.
 */
static void
add_popular_server(const char *server)
{
    t_popular_server *p = NULL;

    p = (t_popular_server *)safe_malloc(sizeof(t_popular_server));
    p->hostname = safe_strdup(server);

    if (config.popular_servers == NULL) {
        p->next = NULL;
        config.popular_servers = p;
    } else {
        p->next = config.popular_servers;
        config.popular_servers = p;
    }
}

static void
parse_popular_servers(const char *ptr)
{
    char *ptrcopy = NULL, *pt = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for popular servers", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);
	pt = ptrcopy;

    while ((hostname = strsep(&ptrcopy, ","))) {  /* hostname does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*hostname != '\0' && isblank(*hostname)) { 
            hostname++;
        }
        if (*hostname == '\0') {  /* Equivalent to strcmp(hostname, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = hostname;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
        debug(LOG_DEBUG, "Adding Popular Server [%s] to list", hostname);
        add_popular_server(hostname);
    }

    free(pt);
}

/*
 * liudf added 20151224
 * trust domain related function
 */

t_domain_trusted *
__del_domain_common(const char *domain, trusted_domain_t which)
{
	t_domain_trusted *p = NULL, *p1 = NULL;
	
	if(which == USER_TRUSTED_DOMAIN) {	
    	if (config.domains_trusted != NULL) {
			for(p = config.domains_trusted; p != NULL; p1 = p, p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}

			if(p == NULL)
				return NULL;
	
			if(p1 != NULL) {
				p1->next = p->next;
			} else {
				config.domains_trusted = p->next;
			}
    	}
	} else if (which == INNER_TRUSTED_DOMAIN) {
		if (config.inner_domains_trusted != NULL) {
			for(p = config.inner_domains_trusted; p != NULL; p1 = p, p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}
			
			if(p == NULL)
				return NULL;
	
			if(p1 != NULL) {
				p1->next = p->next;
			} else {
				config.inner_domains_trusted = p->next;
			}
    	}
	} else if (which == TRUSTED_PAN_DOMAIN) {	
		if (config.pan_domains_trusted != NULL) {
			for(p = config.pan_domains_trusted; p != NULL; p1 = p, p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}
			
			if(p == NULL)
				return NULL;
	
			if(p1 != NULL) {
				p1->next = p->next;
			} else {
				config.pan_domains_trusted = p->next;
			}
    	}
	}

	return p;
}

void
del_domain_common(const char *domain, trusted_domain_t which)
{
	t_domain_trusted *p = NULL;
	LOCK_DOMAIN();
	p = __del_domain_common(domain, which);
	UNLOCK_DOMAIN();

	if(p) {
		__clear_trusted_domain_ip(p->ips_trusted);
		free(p->domain);
		free(p);
	}
}

t_domain_trusted *
__add_domain_common(const char *domain, trusted_domain_t which)
{
    t_domain_trusted *p = NULL;
	
	if(which == USER_TRUSTED_DOMAIN) {	
    	if (config.domains_trusted == NULL) {
    		p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    		p->domain = safe_strdup(domain);
    	    p->next = NULL;
    	    config.domains_trusted = p;
    	} else {
			for(p = config.domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0)
					break;
			}
			if(p == NULL) {
    			p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    			p->domain = safe_strdup(domain);
    	    	p->next = config.domains_trusted;
    	    	config.domains_trusted = p;
			}
    	}
		
		return p;
	} else if (which == INNER_TRUSTED_DOMAIN) {
		if (config.inner_domains_trusted == NULL) {
    		p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    		p->domain = safe_strdup(domain);
    	    p->next = NULL;
    	    config.inner_domains_trusted = p;
    	} else {
			for(p = config.inner_domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0)
					break;
			}
			if(p == NULL) {
    			p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    			p->domain = safe_strdup(domain);
    	    	p->next = config.inner_domains_trusted;
    	    	config.inner_domains_trusted = p;
			}
    	}
		
		return p;
	} else if ( which == TRUSTED_PAN_DOMAIN) {
		if (config.pan_domains_trusted == NULL) {
    		p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    		p->domain = safe_strdup(domain);
    	    p->next = NULL;
    	    config.pan_domains_trusted = p;
    	} else {
			for(p = config.pan_domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0)
					break;
			}
			if(p == NULL) {
    			p = (t_domain_trusted *)safe_malloc(sizeof(t_domain_trusted));
    			p->domain = safe_strdup(domain);
    	    	p->next = config.pan_domains_trusted;
    	    	config.pan_domains_trusted = p;
			}
    	}
		
		return p;
	}
	
	return NULL;
}


t_domain_trusted *
add_domain_common(const char *domain, trusted_domain_t which)
{
    t_domain_trusted *p = NULL;
	
	LOCK_DOMAIN();

	p = __add_domain_common(domain, which);
	
	UNLOCK_DOMAIN();
	
	return p;
}

// add domain to user trusted domain list
t_domain_trusted *
add_user_trusted_domain(const char *domain)
{
	return add_domain_common(domain, USER_TRUSTED_DOMAIN);
}

t_domain_trusted *
__add_user_trusted_domain(const char *domain)
{
	return __add_domain_common(domain, USER_TRUSTED_DOMAIN);
}

// add domain to inner trusted domain list
t_domain_trusted *
add_inner_trusted_domain(const char *domain)
{
	return add_domain_common(domain, INNER_TRUSTED_DOMAIN);
}

t_domain_trusted *
__add_inner_trusted_domain(const char *domain)
{
	return	__add_domain_common(domain, INNER_TRUSTED_DOMAIN);
}

void parse_inner_trusted_domain_string(const char *domain_list)
{
	parse_domain_string_common(domain_list, INNER_TRUSTED_DOMAIN);
}

void parse_user_trusted_domain_string(const char *domain_list)
{
	parse_domain_string_common(domain_list, USER_TRUSTED_DOMAIN);
}

void parse_trusted_pan_domain_string(const char *domain_list)
{
	parse_domain_string_common(domain_list, TRUSTED_PAN_DOMAIN);
}

void
parse_domain_string_common_action(const char *ptr, trusted_domain_t which, int action)
{
    char *ptrcopy = NULL, *pt = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trust domains", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);
	pt = ptrcopy;

	LOCK_DOMAIN();
	
    while ((hostname = strsep(&ptrcopy, ","))) {  /* hostname does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*hostname != '\0' && isblank(*hostname)) { 
            hostname++;
        }
        if (*hostname == '\0') {  /* Equivalent to strcmp(hostname, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = hostname;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
        debug(LOG_DEBUG, "Adding&Delete [%d] trust domain [%s] to&from list", action, hostname);
		if(action) // 1: add
        	__add_domain_common(hostname, which);
		else {// 0: del
			t_domain_trusted *p = __del_domain_common(hostname, which);
			if(p) {
				__clear_trusted_domain_ip(p->ips_trusted);
				free(p->domain);
				free(p);
			}
		}
    }
	
	UNLOCK_DOMAIN();
    free(pt);
}

void
parse_domain_string_common(const char *ptr, trusted_domain_t which)
{
	parse_domain_string_common_action(ptr, which, 1);
}

void
parse_del_trusted_pan_domain_string(const char *ptr)
{
	parse_domain_string_common_action(ptr, TRUSTED_PAN_DOMAIN, 0);
}

void
parse_del_trusted_domain_string(const char *ptr)
{
	parse_domain_string_common_action(ptr, USER_TRUSTED_DOMAIN, 0);
}

// add ip to domain list
static t_ip_trusted *
__add_ip_2_domain(t_domain_trusted *dt, const char *ip)
{
	t_ip_trusted *ipt = dt->ips_trusted;
	for(; ipt != NULL && strcmp(ipt->ip, ip) != 0; ipt = ipt->next)
		;
	
	if(ipt == NULL) {
		ipt = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
		strncpy(ipt->ip, ip, HTTP_IP_ADDR_LEN);
		ipt->ip[HTTP_IP_ADDR_LEN-1] = '\0';
		ipt->next = dt->ips_trusted;
		dt->ips_trusted = ipt;
	}	

	return ipt;
}

// add domain:ip to user define & inner trusted domains
void
add_domain_ip_pair(const char *args, trusted_domain_t which)
{
	char *domain 	= NULL;
	char *ip 		= NULL;
	t_domain_trusted	*dt = NULL;
    char *ptrcopy = NULL, *pt = NULL;

    debug(LOG_DEBUG, "add domain ip pair (%s)", args);
    ptrcopy = safe_strdup(args);
	pt = ptrcopy;

	if((domain = strsep(&ptrcopy, ":")) == NULL) {	
        debug(LOG_DEBUG, "args is illegal");
		free(pt);
		return;
	}

	ip = ptrcopy;	
	if(ip == NULL || !(strlen(ip) >= 7 && strlen(ip) <= 15)) {
		debug(LOG_DEBUG, "illegal ip");
		free(pt);
		return;
	}
		
	LOCK_DOMAIN();

	dt = __add_domain_common(domain, which);
	if(dt)
		__add_ip_2_domain(dt, ip);
	
	UNLOCK_DOMAIN();	

	free(pt);
}

// parse domain to get ip and add it to its list
void
parse_trusted_domain_2_ip(t_domain_trusted *p)
{
	struct hostent *he;
    struct in_addr **addr_list;
    int i;
	
	// if has parsed or ip list; then passed it	
	if(p->ips_trusted != NULL || strcmp(p->domain, "iplist") == 0 || p->invalid == 1) {	
        debug(LOG_INFO, "domain has parsed (%s)", p->domain);
		return;
	}

    if ( (he=gethostbyname2(p->domain, AF_INET) ) == NULL){
		p->invalid = 1;
        goto err;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++){
        char hostname[HTTP_IP_ADDR_LEN] = {0};
		t_ip_trusted *ipt = NULL;
		inet_ntop(AF_INET, addr_list[i], hostname, HTTP_IP_ADDR_LEN);
		hostname[HTTP_IP_ADDR_LEN-1] = '\0';
        debug(LOG_DEBUG, "hostname ip is(%s)", hostname);

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

err:	
	return;
}

void 
parse_common_trusted_domain_list(trusted_domain_t which)
{
	t_domain_trusted *p = NULL;
	
	if(which == INNER_TRUSTED_DOMAIN)
		p = config.inner_domains_trusted;
	else if (which == USER_TRUSTED_DOMAIN)
		p = config.domains_trusted;
	else
		return;

	evdns_parse_trusted_domain_2_ip(p);
}

void parse_user_trusted_domain_list()
{
	parse_common_trusted_domain_list(USER_TRUSTED_DOMAIN);
}

void parse_inner_trusted_domain_list()
{	
	parse_common_trusted_domain_list(INNER_TRUSTED_DOMAIN);
}

void add_trusted_ip_list(const char *ptr)
{
	char *ptrcopy = NULL, *pt = NULL;
    char *ip = NULL;
    char *tmp = NULL;
	t_domain_trusted *p = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trust domains", ptr);
	
	p = add_domain_common("iplist", USER_TRUSTED_DOMAIN);
	if(p == NULL) {
    	debug(LOG_ERR, "Impossible: add iplist domain failed");
		return;
	}
	
    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);
	pt = ptrcopy;
	
	LOCK_DOMAIN();
    while ((ip = strsep(&ptrcopy, ","))) {  /* ip does *not* need allocation. strsep
                                                     provides a pointer in ptrcopy. */
        /* Skip leading spaces. */
        while (*ip != '\0' && isblank(*ip)) { 
            ip++;
        }
        if (*ip == '\0') {  /* Equivalent to strcmp(ip, "") == 0 */
            continue;
        }
        /* Remove any trailing blanks. */
        tmp = ip;
        while (*tmp != '\0' && !isblank(*tmp)) {
            tmp++;
        }
        if (*tmp != '\0' && isblank(*tmp)) {
            *tmp = '\0';
        }
		
		if(is_valid_ip(ip) == 0) // not valid ip address
			continue;
		
        debug(LOG_DEBUG, "Adding trust ip [%s] to list", ip);		
		__add_ip_2_domain(p, ip);
		
    }
	UNLOCK_DOMAIN();
	
    free(pt);

}

static void parse_weixin_http_dns_ip_cb(char *xml_buffer, int buffer_size)
{
	if (!xml_buffer) 
		debug(LOG_INFO, "xml_buffer is NULL\n");
	
	ezxml_t xml_dns = ezxml_parse_str(xml_buffer, buffer_size);
	ezxml_t domain_list, domain, ip;
	
	if (!xml_dns) {
		debug(LOG_INFO, "ezxml_parse_str failed ");
		return;
	}
	
	LOCK_DOMAIN();
	
	t_domain_trusted *dt = __add_inner_trusted_domain("short.weixin.qq.com");
	
	for (domain_list = ezxml_child(xml_dns, "domainlist"); domain_list; domain_list = domain_list->next) {
		for (domain = ezxml_child(domain_list, "domain"); domain; domain = domain->next) {
			char *name = ezxml_attr(domain, "name");
			if (name && strcmp(name, "short.weixin.qq.com") == 0) {
				for (ip = ezxml_child(domain, "ip"); ip; ip = ip->next) {
					char *addr = ip->txt;			
					if (dt) {
						debug(LOG_DEBUG, "Add short.weixin.qq.com ip %s\n", addr);
						__add_ip_2_domain(dt, addr);
					}
				}
			}
		}
	}
	
	UNLOCK_DOMAIN();
	
	ezxml_free(xml_dns);
	
	return ;
}

void
fix_weixin_http_dns_ip (void)
{
	const char *url_weixin_dns = "http://dns.weixin.qq.com/cgi-bin/micromsg-bin/newgetdns";
	start_http_request(url_weixin_dns, REQUEST_GET_FLAG, NULL, NULL, parse_weixin_http_dns_ip_cb);
}

// clear domain's ip collection
void
__clear_trusted_domain_ip(t_ip_trusted *ipt)
{
	t_ip_trusted *p, *p1;
	for(p = ipt; p != NULL;) {
		p1 = p;
		p = p->next;
		free(p1);
	}
}

// clear domain_trusted list
void
__clear_trusted_domains(void)
{
	t_domain_trusted *p, *p1;
	int has_iplist = 0;
    for (p = config.domains_trusted; p != NULL;) {
		if(strcmp(p->domain, "iplist") != 0) {
    		p1 = p;
        	p = p->next;
        	__clear_trusted_domain_ip(p1->ips_trusted);
        	free(p1->domain);
        	free(p1);
		} else {
			config.domains_trusted = p;
			has_iplist = 1;
			p = p->next;
			config.domains_trusted->next = NULL;
		}
    }
	if(has_iplist == 0)
    	config.domains_trusted = NULL;
}

void
clear_trusted_domains_(void)
{
	LOCK_DOMAIN();
	__clear_trusted_domains();
	UNLOCK_DOMAIN();
}

static void
__clear_trusted_pan_domains(void)
{
	t_domain_trusted *p, *p1;
    for (p = config.pan_domains_trusted; p != NULL;) {
    	p1 = p;
       	p = p->next;
       	free(p1->domain);
       	free(p1);
    }

   	config.pan_domains_trusted = NULL;
}

void
clear_trusted_pan_domains(void)
{
	LOCK_DOMAIN();
	__clear_trusted_pan_domains();
	UNLOCK_DOMAIN();
}

void
__clear_trusted_iplist(void)
{
	t_domain_trusted *p, *p1;
    for (p = config.domains_trusted, p1 = p; p != NULL; p1 = p, p = p->next) {
		if(strcmp(p->domain, "iplist") == 0) {
			if(p == config.domains_trusted)
				config.domains_trusted = p->next;
			else
				p1->next = p->next;
			p->next = NULL;
			break;
		}
    }
	
	if(p != NULL) {
		__clear_trusted_domain_ip(p->ips_trusted);
		free(p->domain);
		free(p);
	}
}

void
clear_trusted_ip_list(void)
{
	LOCK_DOMAIN();
	__clear_trusted_iplist();
	UNLOCK_DOMAIN();
}

t_domain_trusted *
get_domains_trusted(void)
{
	return config.domains_trusted;
}


/** 
 * Operate the roam mac list.
 */
void
__clear_roam_mac_list()
{
	t_trusted_mac *p, *p1;
    for (p = config.roam_maclist; p != NULL;) {
    	p1 = p;
        p = p->next;
        free(p1->mac);
        free(p1);
    }
    config.domains_trusted = NULL;
}

void 
clear_roam_mac_list()
{
	LOCK_CONFIG();
	__clear_roam_mac_list();
	UNLOCK_CONFIG();
}

t_trusted_mac *
get_roam_maclist() 
{
	return config.roam_maclist;
}

int
is_roaming(const char *mac)
{
	t_trusted_mac *p = NULL;

    for (p = config.roam_maclist; p != NULL; p = p->next) {
    	if(strcmp(mac, p->mac) == 0)
			break;
	}
	
	return p==NULL?0:1;
}

int
is_trusted_mac(const char *mac)
{
	t_trusted_mac *p = NULL;

    for (p = config.trustedmaclist; p != NULL; p = p->next) {
    	if(strcmp(mac, p->mac) == 0)
			break;
	}
	
	return p==NULL?0:1;

}

int
is_untrusted_mac(const char *mac)
{
	t_trusted_mac *p = NULL;

    for (p = config.mac_blacklist; p != NULL; p = p->next) {
    	if(strcmp(mac, p->mac) == 0)
			break;
	}
	
	return p==NULL?0:1;

}

void
clear_dup_trusted_mac_list(t_trusted_mac *dup_list)
{
	t_trusted_mac *p, *p1;
    for (p = dup_list; p != NULL;) {
    	p1 = p;
        p = p->next;
		if(p1->ip) free(p1->ip);
        free(p1->mac);
        free(p1);
    }
    dup_list = NULL;
}

void
__clear_trusted_mac_list()
{
	t_trusted_mac *p, *p1;
    for (p = config.trustedmaclist; p != NULL;) {
    	p1 = p;
        p = p->next;
		if(p1->ip) free(p1->ip);
        free(p1->mac);
        free(p1);
    }
    config.trustedmaclist = NULL;
}

void 
clear_trusted_mac_list()
{
	LOCK_CONFIG();
	__clear_trusted_mac_list();
	UNLOCK_CONFIG();
}

void
__clear_untrusted_mac_list()
{
	t_untrusted_mac *p, *p1;
    for (p = config.mac_blacklist; p != NULL;) {
    	p1 = p;
        p = p->next;
		if(p1->ip) free(p1->ip);
        free(p1->mac);
        free(p1);
    }
    config.mac_blacklist = NULL;
}

void 
clear_untrusted_mac_list()
{
	LOCK_CONFIG();
	__clear_untrusted_mac_list();
	UNLOCK_CONFIG();
}

// set all trusted mac to offline
static void
__reset_trusted_mac_list()
{
	t_trusted_mac *p;
    for (p = config.trustedmaclist; p != NULL; p = p->next) {
		p->is_online = 0;
    }
}

void
reset_trusted_mac_list()
{
	LOCK_CONFIG();
	__reset_trusted_mac_list();
	UNLOCK_CONFIG();
}

static t_trusted_mac *
trusted_mac_dup(t_trusted_mac *src)
{
	t_trusted_mac *new = NULL;
	
	if(src == NULL)
		return NULL;

	new = safe_malloc(sizeof(t_trusted_mac));	
	new->mac 	= safe_strdup(src->mac);
	new->ip 	= NULL;
	new->is_online = 0;

	return new;
}

static int
__trusted_mac_list_dup(t_trusted_mac ** dest)
{
	t_trusted_mac *new, *cur, *top, *prev;
	int copied = 0;

	cur = config.trustedmaclist;
    new = top = prev = NULL;
	
	if (NULL == cur) {
        *dest = new;            /* NULL */
        return copied;
    }

    while (NULL != cur) {
        new = trusted_mac_dup(cur);
        if (NULL == top) {
            /* first item */
            top = new;
        } else {
            prev->next = new;
        }
        prev = new;
        copied++;
        cur = cur->next;
    }

    *dest = top;
    return copied;

}

int 
trusted_mac_list_dup(t_trusted_mac **worklist)
{
	int num = 0;
	LOCK_CONFIG();
	num = __trusted_mac_list_dup(worklist);
	UNLOCK_CONFIG();
	
	return num;
}
// >>> end liudf added

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
    config_notnull(config.gw_interface, "GatewayInterface");
    config_notnull(config.auth_servers, "AuthServer");
    validate_popular_servers();

    if (missing_parms) {
        debug(LOG_ERR, "Configuration is not complete, exiting...");
        exit(-1);
    }
}

/** @internal
 * Validate that popular servers are populated or log a warning and set a default.
 */
static void
validate_popular_servers(void)
{
    if (config.popular_servers == NULL) {  
		add_popular_server("www.qq.com");
        add_popular_server("www.kunteng.org");
        add_popular_server("www.baidu.com");        
    }
}

/** @internal
    Verifies that a required parameter is not a null pointer
*/
static void
config_notnull(const void *parm, const char *parmname)
{
    if (parm == NULL) {
        debug(LOG_ERR, "%s is not set", parmname);
        missing_parms = 1;
    }
}

/**
 * This function returns the current (first auth_server)
 */
t_auth_serv *
get_auth_server(void)
{

    /* This is as good as atomic */
    return config.auth_servers;
}

/**
 * This function marks the current auth_server, if it matches the argument,
 * as bad. Basically, the "bad" server becomes the last one on the list.
 */
void
mark_auth_server_bad(t_auth_serv * bad_server)
{
    t_auth_serv *tmp;
	
	if (bad_server->authserv_fd > 0) {
		close(bad_server->authserv_fd);
		bad_server->authserv_fd = -1;
		bad_server->authserv_fd_ref = 0;
	}
		
    if (config.auth_servers == bad_server && bad_server->next != NULL) {
        /* Go to the last */
        for (tmp = config.auth_servers; tmp->next != NULL; tmp = tmp->next) ;
        /* Set bad server as last */
        tmp->next = bad_server;
        /* Remove bad server from start of list */
        config.auth_servers = bad_server->next;
        /* Set the next pointe to NULL in the last element */
        bad_server->next = NULL;
    }

}
