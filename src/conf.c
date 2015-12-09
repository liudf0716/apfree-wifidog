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

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "config.h"

#include "util.h"

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
NULL, oBadOption},};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static int _parse_firewall_rule(const char *, char *);
static void parse_firewall_ruleset(const char *, FILE *, const char *, int *);
static void parse_trusted_mac_list(const char *);
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
    char line[MAX_BUF], *s, *p1, *p2, *rawarg = NULL;
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
check_mac_format(char *possiblemac)
{
    char hex2[3];
    return
        sscanf(possiblemac,
               "%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]:%2[A-Fa-f0-9]",
               hex2, hex2, hex2, hex2, hex2, hex2) == 6;
}

/** @internal
 * Parse the trusted mac list.
 */
static void
parse_trusted_mac_list(const char *ptr)
{
    char *ptrcopy = NULL;
    char *possiblemac = NULL;
    char *mac = NULL;
    t_trusted_mac *p = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for trusted MAC addresses", ptr);

    mac = safe_malloc(18);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

    while ((possiblemac = strsep(&ptrcopy, ","))) {
        /* check for valid format */
        if (!check_mac_format(possiblemac)) {
            debug(LOG_ERR,
                  "[%s] not a valid MAC address to trust. See option TrustedMACList in wifidog.conf for correct this mistake.",
                  possiblemac);
            free(ptrcopy);
            free(mac);
            return;
        } else {
            if (sscanf(possiblemac, " %17[A-Fa-f0-9:]", mac) == 1) {
                /* Copy mac to the list */

                debug(LOG_DEBUG, "Adding MAC address [%s] to trusted list", mac);

                if (config.trustedmaclist == NULL) {
                    config.trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
                    config.trustedmaclist->mac = safe_strdup(mac);
                    config.trustedmaclist->next = NULL;
                } else {
                    int skipmac;
                    /* Advance to the last entry */
                    p = config.trustedmaclist;
                    skipmac = 0;
                    /* Check before loop to handle case were mac is a duplicate
                     * of the first and only item in the list so far.
                     */
                    if (0 == strcmp(p->mac, mac)) {
                        skipmac = 1;
                    }
                    while (p->next != NULL) {
                        if (0 == strcmp(p->mac, mac)) {
                            skipmac = 1;
                        }
                        p = p->next;
                    }
                    if (!skipmac) {
                        p->next = safe_malloc(sizeof(t_trusted_mac));
                        p = p->next;
                        p->mac = safe_strdup(mac);
                        p->next = NULL;
                    } else {
                        debug(LOG_ERR,
                              "MAC address [%s] already on trusted list. See option TrustedMACList in wifidog.conf file ",
                              mac);
                    }
                }
            }
        }
    }

    free(ptrcopy);

    free(mac);

}

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
    char *ptrcopy = NULL;
    char *hostname = NULL;
    char *tmp = NULL;

    debug(LOG_DEBUG, "Parsing string [%s] for popular servers", ptr);

    /* strsep modifies original, so let's make a copy */
    ptrcopy = safe_strdup(ptr);

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

    free(ptrcopy);
}

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
        add_popular_server("www.google.com");
        add_popular_server("www.yahoo.com");
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
