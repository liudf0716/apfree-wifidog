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

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "config.h"

#include "util.h"

//>>> liudf added 20160114
//const char	*g_inner_trusted_domains = "wifi.weixin.qq.com,api.weixin.qq.com,dns.weixin.qq.com,calong.weixin.qq.com,cashort.weixin.qq.com,hklong.weixin.qq.com,hkshort.weixin.qq.com,long.weixin.qq.com,short.weixin.qq.com,szlong.weixin.qq.com,szshort.weixin.qq.com,www.kunteng.org,cloud.kunteng.org";

const char	*g_inner_trusted_domains = "www.kunteng.org,cloud.kunteng.org";
/** @internal
 * Holds the current configuration of the gateway */
static s_config config;

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	oTrustedDomains,
	oInnerTrustedDomains,
	oUntrustedMACList,
	oJsFilter,
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
	"trustedDomains", oTrustedDomains}, {
	"untrustedmaclist", oUntrustedMACList}, {
	"jsFilter", oJsFilter}, {
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
	config.js_filter = 1; // default enable it
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
    new->authserv_login_script_path_fragment = loginscriptpathfragment;
    new->authserv_portal_script_path_fragment = portalscriptpathfragment;
    new->authserv_msg_script_path_fragment = msgscriptpathfragment;
    new->authserv_ping_script_path_fragment = pingscriptpathfragment;
    new->authserv_auth_script_path_fragment = authscriptpathfragment;
    new->authserv_http_port = http_port;
    new->authserv_ssl_port = ssl_port;

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
				case oTrustedDomains:
					parse_user_trusted_domain_string(rawarg);
					break;
				case oUntrustedMACList:
					parse_untrusted_mac_list(p1);
					break;
				case oJsFilter:
                    config.js_filter = parse_boolean_value(p1);
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
int
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
add_trusted_mac(const char *mac)
{
	debug(LOG_DEBUG, "Adding MAC address [%s] to trusted mac list", mac);
	
	LOCK_CONFIG();

	if (config.trustedmaclist == NULL) {
		config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
		config.trustedmaclist->mac = safe_strdup(mac);
		config.trustedmaclist->next = NULL;
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
		} else {
			debug(LOG_ERR,
				"MAC address [%s] already on trusted mac list.  ",
				mac);
		}
	}

	UNLOCK_CONFIG();
}

static void
add_untrusted_mac(const char *mac)
{
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

void
parse_mac_list(const char *ptr, mac_choice_t which)
{
    char *ptrcopy = NULL, *pt = NULL;
    char *possiblemac = NULL;
    char *mac = NULL;
	int  len = 0;

    debug(LOG_DEBUG, "Parsing string [%s] for  MAC addresses", ptr);
	
	while(isspace(*ptr))
		ptr++;
	
	if (check_mac_format(ptr)) {
		// in case only one mac
    	debug(LOG_DEBUG, "add mac [%s] to list", ptr);
		add_mac(ptr, which);
		return;
	}

    mac = safe_malloc(18);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);
	pt = ptrcopy;
	
	len = strlen(ptrcopy);
	while(isspace(ptrcopy[--len]))
		ptrcopy[len] = '\0';
	
    while ((possiblemac = strsep(&ptrcopy, ","))) {
        /* check for valid format */
        if (!check_mac_format(possiblemac)) {
            debug(LOG_ERR,
                  "[%s] not a valid MAC address ",
                  possiblemac);
			break;
        } else {
            if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
                /* Copy mac to the list */
				add_mac(mac, which);
            }
        }
    }

    free(pt);
    free(mac);
}

void
parse_trusted_mac_list(const char *pstr)
{
	parse_mac_list(pstr, TRUSTED_MAC);
}

void
parse_untrusted_mac_list(const char *pstr)
{
	parse_mac_list(pstr, UNTRUSTED_MAC);
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
	}
	
	return NULL;
}


t_domain_trusted *
add_domain_common(const char *domain, trusted_domain_t which)
{
    t_domain_trusted *p = NULL;
	
	LOCK_CONFIG();
	p = __add_domain_common(domain, which);
    UNLOCK_CONFIG();
	
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

void
parse_domain_string_common(const char *ptr, trusted_domain_t which)
{
    char *ptrcopy = NULL, *pt = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trust domains", ptr);

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
        debug(LOG_DEBUG, "Adding trust domain [%s] to list", hostname);
        add_domain_common(hostname, which);
    }

    free(pt);
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
		
	LOCK_CONFIG();

	dt = __add_domain_common(domain, which);
	if(dt)
		__add_ip_2_domain(dt, ip);
	
	UNLOCK_CONFIG();

	free(pt);
}

// parse domain to get ip and add it to its list
void
parse_trusted_domain_2_ip(t_domain_trusted *p)
{
	struct hostent *he;
    struct in_addr **addr_list;
    int i;

    if ( (he=gethostbyname2(p->domain, AF_INET) ) == NULL)
    {
        return ;
    }

    addr_list = (struct in_addr **) he->h_addr_list;

    for(i = 0; addr_list[i] != NULL; i++){
        char hostname[HTTP_IP_ADDR_LEN] = {0};
		t_ip_trusted *ipt = NULL;
		inet_ntop(AF_INET, addr_list[i], hostname, HTTP_IP_ADDR_LEN);
		hostname[HTTP_IP_ADDR_LEN-1] = '\0';
        debug(LOG_DEBUG, "hostname ip is(%s)", hostname);
		
		LOCK_CONFIG();

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

		UNLOCK_CONFIG();
	}	
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

	while(p && p->domain) {
        debug(LOG_DEBUG, "parse domain (%s)", p->domain);
		parse_trusted_domain_2_ip(p);
		p = p->next;
	}

}

void parse_user_trusted_domain_list()
{
	parse_common_trusted_domain_list(USER_TRUSTED_DOMAIN);
}

void parse_inner_trusted_domain_list()
{	
	parse_common_trusted_domain_list(INNER_TRUSTED_DOMAIN);
}

void 
__fix_weixin_http_dns_ip(void)
{
	const char *get_weixin_ip_cmd = "curl --compressed http://dns.weixin.qq.com/cgi-bin/micromsg-bin/newgetdns 2>/dev/null";
	const char *short_weixin_begin="<domain name=\"short.weixin.qq.com";
    FILE *file = NULL;

    if((file = popen(get_weixin_ip_cmd, "r")) != NULL) {
    	char buf[512];
        char *ip = NULL, *p = NULL;
        int flag = 0;

        while(memset(buf, 0, 512) && fgets(buf, 512, file)) {
        	if(!flag&&strncmp(buf, short_weixin_begin, strlen(short_weixin_begin)) == 0) {
            	flag = 1;
            }
            if(flag&&strncmp(buf, "</domain>", 9) == 0) {
            	flag = 0;
                break;
            }
            if(flag&&strncmp(buf, "<ip>", 4) == 0) {
				t_domain_trusted	*dt = NULL;
            	p = rindex(buf, '<');
                *p='\0';
				ip = buf+4;
				dt = __add_inner_trusted_domain("short.weixin.qq.com");
				if (dt)
					__add_ip_2_domain(dt, ip);
            }
       	}
    	pclose(file);
	}
}

// clear domain's ip collection
static void
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
    for (p = config.domains_trusted; p != NULL;) {
    	p1 = p;
        p = p->next;
        __clear_trusted_domain_ip(p1->ips_trusted);
        free(p1->domain);
        free(p1);
    }
    config.domains_trusted = NULL;
}

void
clear_trusted_domains(void)
{
	LOCK_CONFIG();
	__clear_trusted_domains();
	UNLOCK_CONFIG();
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

void
__clear_trusted_mac_list()
{
	t_trusted_mac *p, *p1;
    for (p = config.trustedmaclist; p != NULL;) {
    	p1 = p;
        p = p->next;
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
        debug(LOG_WARNING, "PopularServers not set in config file, this will become fatal in a future version.");
        add_popular_server("www.baidu.com");
        add_popular_server("www.qq.com");
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
