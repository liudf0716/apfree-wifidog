
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "http.h"
#include "auth.h"
#include "firewall.h"
#include "util.h"
#include "wd_util.h"

/** @internal
 * Holds the current configuration of the gateway */
static s_config config = {0};

/**
 * Mutex for the configuration file, used by the auth_servers related
 * functions. */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

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
	oGatewayPort,
	oGatewayHttpsPort,
	oDeltaTraffic,
	oGatewaySetting,
	oDeviceID,
	oGatewayID,
	oGatewayInterface,
	oGatewayChannel,
	oGatewaySubnetV4,
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
	oAuthServWsScriptPathFragment,
	oAuthServerOfflineFile,
	oInternetOfflineFile,
	oLocalPortal,
	oHTTPDMaxConn,
	oHTTPDName,
	oHTTPDRealm,
	oHTTPDUsername,
	oHTTPDPassword,
	oClientTimeout,
	oCheckInterval,
	oWdctlSocket,
	oSyslogFacility,
	oTrustedMACList,
	oPopularServers,
	oHtmlMessageFile,
	oProxyPort,
	oTrustedPanDomains,
	oTrustedDomains,
	oInnerTrustedDomains,
	oUntrustedMACList,
	oJsFilter,
	oWiredPassed,
	oParseChecked,
	oTrustedIpList,
	oUpdateDomainInterval,
	oTrustedLocalMACList,
	oAppleCNA,
	oMQTT,
	oMQTTServer,
	oMQTTServerPort,
	oMQTTUsername,
	oMQTTPassword,
	oDNSTimeout,
	oFW4Enable,
	oDhcpOptionCpi,
	oEnableDhcpOptionCpi,
	oEnableBypassAuth,
	oEnableDNSForward,
	oWebSocket,
	oWSServer,
	oWSServerPort,
	oWSServerPath,
	oWSServerSSL,
	oEnableDelConntrack,
	oAuthServerMode,
	oEnableAntiNat,
	oEnableUserReload,
	oTTLValues,
	oAntiNatPermitMacs,
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
	"deviceid", oDeviceID}, {
	"gatewayid", oGatewayID}, {
	"gatewayinterface", oGatewayInterface}, {
	"gatewaychannel", oGatewayChannel}, {
	"gatewaysubnetv4", oGatewaySubnetV4}, {
	"gatewayport", oGatewayPort}, {
	"gatewayhttpsport", oGatewayHttpsPort}, {
	"gatewaysetting", oGatewaySetting}, {
	"authserver", oAuthServer}, {
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
	"wsscriptpathfragment", oAuthServWsScriptPathFragment}, {
	"authserverofflinefile", oAuthServerOfflineFile}, {
	"internetofflinefile", oInternetOfflineFile}, {
	"localportal", oLocalPortal}, {
	"trustedmaclist", oTrustedMACList}, {
	"popularservers", oPopularServers}, {
	"htmlmessagefile", oHtmlMessageFile}, {
	"proxyport", oProxyPort}, {
	"trustedPanDomains", oTrustedPanDomains}, {
	"trustedDomains", oTrustedDomains}, {
	"untrustedmaclist", oUntrustedMACList}, {
	"jsFilter", oJsFilter}, {
	"wiredPassed", oWiredPassed}, {
	"parseChecked", oParseChecked}, {
	"trustedIpList", oTrustedIpList}, {
	"updateDomainInterval", oUpdateDomainInterval}, {
	"trustedlocalmaclist", oTrustedLocalMACList}, {
	"bypassAppleCNA", oAppleCNA}, {
	"mqtt", oMQTT}, {
	"serveraddr", oMQTTServer}, {
	"serverport", oMQTTServerPort}, {
	"mqttUsername", oMQTTUsername}, {
	"mqttPassword", oMQTTPassword}, {
	"dnstimeout",oDNSTimeout},{
	"fw4enable",oFW4Enable},{
	"dhcpoptioncpi",oDhcpOptionCpi},{
	"enabledhcpoptioncpi",oEnableDhcpOptionCpi},{
	"enablebypassauth",oEnableBypassAuth},{
	"enablednsforward",oEnableDNSForward},{
	"websocket",oWebSocket},{
	"wsserver",oWSServer},{
	"wsserverport",oWSServerPort},{
	"wsserverpath",oWSServerPath},{
	"wsserverssl",oWSServerSSL},{
	"enabledelconntrack",oEnableDelConntrack},{
	"authservermode", oAuthServerMode}, {
	"enableantinat", oEnableAntiNat}, {
	"enableuserreload", oEnableUserReload}, {
	"ttlvalues", oTTLValues}, {
	"antinatpermitmacs", oAntiNatPermitMacs}, {
	NULL, oBadOption},
};

static void config_notnull(const void *, const char *);
static int parse_boolean_value(char *);
static void parse_auth_server(FILE *, const char *, int *);
static void parse_mqtt_server(FILE *, const char *, int *);
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

t_gateway_setting *
get_gateway_settings(void)
{
	return config.gateway_settings;
}

t_ws_server *
get_ws_server(void)
{
	return config.ws_server;
}

t_mqtt_server *
get_mqtt_server(void)
{
	return config.mqtt_server;
}

const char *
get_device_id(void)
{
	return config.device_id;
}

int
get_gateway_count(void)
{
	int count = 0;
	t_gateway_setting *tmp = config.gateway_settings;

	while (tmp) {
		count++;
		tmp = tmp->next;
	}

	return count;
}

/**
 * @brief Initializes the gateway configuration with default parameters.
 *
 * This function sets up the default configuration for the gateway by
 * allocating memory for various configuration structures and setting
 * their initial values. It ensures that all necessary fields are
 * properly initialized to avoid undefined behavior.
 */
void config_init(void)
{
	debug(LOG_DEBUG, "Initializing default configuration parameters");

	// Initialize basic configuration parameters
	config.configfile               = safe_strdup(DEFAULT_CONFIGFILE);
	config.htmlmsgfile              = safe_strdup(DEFAULT_HTMLMSGFILE);
	config.external_interface       = safe_strdup(DEFAULT_EXT_IF);
	config.gw_port                  = DEFAULT_GATEWAYPORT;
	config.gw_https_port            = DEFAULT_GATEWAY_HTTPS_PORT;
	config.gateway_settings         = NULL;
	config.auth_servers             = NULL;
	config.clienttimeout            = DEFAULT_CLIENTTIMEOUT;
	config.checkinterval            = DEFAULT_CHECKINTERVAL;
	config.daemon                   = -1;
	config.pidfile                  = NULL;
	config.wdctl_sock               = safe_strdup(DEFAULT_WDCTL_SOCK);
	config.internal_sock            = safe_strdup(DEFAULT_INTERNAL_SOCK);
	config.trustedmaclist           = NULL;
	config.popular_servers          = NULL;
	config.proxy_port               = 0;
	config.deltatraffic             = DEFAULT_DELTATRAFFIC;
	config.arp_table_path           = safe_strdup(DEFAULT_ARPTABLE);
	config.htmlredirfile            = safe_strdup(DEFAULT_REDIRECTFILE);
	config.internet_offline_file    = safe_strdup(DEFAULT_INTERNET_OFFLINE_FILE);
	config.authserver_offline_file  = safe_strdup(DEFAULT_AUTHSERVER_OFFLINE_FILE);
	config.local_portal             = safe_strdup(DEFAULT_LOCAL_PORTAL);
	config.js_redir                 = 1; // Enable JavaScript redirection by default
	config.wired_passed             = 1; // Allow wired devices without login by default
	config.parse_checked            = 1; // Enable domain IP parsing with fping check
	config.update_domain_interval   = 60; // Update trusted domains every 60 seconds
	config.dns_timeout              = "1.0"; // DNS parsing timeout set to 1.0 seconds
	config.bypass_apple_cna         = 1; // Enable Apple CNA bypass by default
	config.pan_domains_trusted      = NULL;
	config.domains_trusted          = NULL;
	config.inner_domains_trusted    = NULL;
	config.roam_maclist             = NULL;
	config.trusted_local_maclist    = NULL;
	config.mac_blacklist            = NULL;

	config.is_custom_auth_offline_file = 0;

	// Initialize HTTPS server configuration
	t_https_server *https_server = malloc(sizeof(t_https_server));
	if (!https_server) {
		debug(LOG_ERR, "Failed to allocate memory for HTTPS server");
		exit(EXIT_FAILURE);
	}
	memset(https_server, 0, sizeof(t_https_server));
	https_server->ca_crt_file      = safe_strdup(DEFAULT_CA_CRT_FILE);
	https_server->svr_crt_file     = safe_strdup(DEFAULT_SVR_CRT_FILE);
	https_server->svr_key_file     = safe_strdup(DEFAULT_SVR_KEY_FILE);
	config.https_server            = https_server;

	// Initialize HTTP server configuration
	t_http_server *http_server = malloc(sizeof(t_http_server));
	if (!http_server) {
		debug(LOG_ERR, "Failed to allocate memory for HTTP server");
		exit(EXIT_FAILURE);
	}
	memset(http_server, 0, sizeof(t_http_server));
	http_server->gw_http_port      = 8403;
	http_server->base_path         = safe_strdup(DEFAULT_WWW_PATH);
	config.http_server             = http_server;

	// Initialize firewall and feature flags
	config.fw4_enable           = 1;
	config.enable_bypass_auth   = 0;
	config.enable_dhcp_cpi      = 0;
	config.enable_dns_forward   = 1;
	config.enable_del_conntrack = 1;
	config.auth_server_mode 	= 0;
	config.enable_anti_nat 		= 0;
	config.enable_smart_qos 	= 0;
	config.enable_user_reload 	= 1;
	config.ttl_values 			= safe_strdup(DEFAULT_TTL_VALUES);
	config.anti_nat_permit_macs = NULL;

	// Initialize debugging configuration
	debugconf.log_stderr     	= 1;
	debugconf.debuglevel     	= DEFAULT_DEBUGLEVEL;
	debugconf.syslog_facility 	= DEFAULT_SYSLOG_FACILITY;
	debugconf.log_syslog     	= DEFAULT_LOG_SYSLOG;
}

/** @internal
 * Parses a single token from the configuration file.
 *
 * @param cp        The token string to parse.
 * @param filename  The name of the configuration file.
 * @param linenum   The current line number being parsed.
 * @return          The corresponding OpCode, or oBadOption if invalid.
 */
static OpCodes
config_parse_token(const char *cp, const char *filename, int linenum)
{
	for (int i = 0; keywords[i].name; i++) {
		if (strcasecmp(cp, keywords[i].name) == 0) {
			return keywords[i].opcode;
		}
	}

	debug(LOG_ERR, "%s: line %d: Bad configuration option: %s", filename, linenum, cp);
	return oBadOption;
}

/**
 * Parses an IPv4 subnet string in CIDR notation (e.g., "192.168.1.0/24")
 * and converts it to numeric address and netmask.
 *
 * @param subnet  The subnet string in CIDR notation to parse
 * @param addr    Pointer to store the parsed network address in host byte order
 * @param mask    Pointer to store the calculated netmask in host byte order
 *
 * @return true if parsing was successful, false if the input was invalid
 *
 * The function validates:
 * - Proper CIDR format with '/' separator
 * - Valid mask length (0-32)
 * - Valid IPv4 address format
 *
 * On success, stores the network address and calculated netmask in the provided pointers.
 * On failure, outputs error messages via debug() and returns false.
 */
static bool
parse_subnet_v4(const char *subnet, uint32_t *addr, uint32_t *mask)
{
	char *slash = strchr(subnet, '/');
	if (!slash) {
		debug(LOG_ERR, "Invalid subnet format: %s", subnet);
		return false;
	}

	char *endptr;
	long masklen = strtol(slash + 1, &endptr, 10);
	if (*endptr || masklen < 0 || masklen > 32) {
		debug(LOG_ERR, "Invalid subnet mask length: %s", slash + 1);
		return false;
	}

	char ip[16]={0};
	strncpy(ip, subnet, slash - subnet);
	ip[slash - subnet] = '\0';

	struct in_addr in;
	if (!inet_aton(ip, &in)) {
		debug(LOG_ERR, "Invalid subnet IP address: %s", ip);
		return false;
	}

	*addr = ntohl(in.s_addr);
	*mask = 0xFFFFFFFF << (32 - masklen);

	return true;
}

/** @internal
 * Parses gateway settings from the configuration file.
 *
 * @param file      The file pointer to read from.
 * @param filename  The name of the configuration file.
 * @param linenum   The current line number being parsed.
 */
static void
parse_gateway_settings(FILE *file, const char *filename, int *linenum)
{
	char line[MAX_BUF];
	char *gw_id = NULL;
	char *gw_interface = NULL;
	char *gw_channel = NULL;
	char *gw_subnet_v4 = NULL;
	t_gateway_setting *new_setting = NULL;
	t_gateway_setting *current = NULL;

	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && !strchr(line, '}')) {
		(*linenum)++;

		// Trim leading whitespace
		char *p = line;
		while (isblank(*p)) p++;

		// Remove comments and trailing whitespace
		char *end = strpbrk(p, "#\r\n");
		if (end) *end = '\0';

		// Trim trailing whitespace
		end = p + strlen(p) - 1;
		while (end > p && isblank(*end)) {
			*end = '\0';
			end--;
		}

		if (strlen(p) > 0) {
			// Extract key and value
			char *key = p;
			char *value = NULL;

			char *space = strpbrk(p, " \t");
			if (space) {
				*space = '\0';
				value = space + 1;

				while (isblank(*value)) value++;
			}

			if (value) {
				OpCodes opcode = config_parse_token(key, filename, *linenum);
				switch (opcode) {
					case oGatewayID:
						gw_id = safe_strdup(value);
						break;
					case oGatewayInterface:
						gw_interface = safe_strdup(value);
						break;
					case oGatewayChannel:
						gw_channel = safe_strdup(value);
						break;
					case oGatewaySubnetV4:
						gw_subnet_v4 = safe_strdup(value);
						break;
					case oBadOption:
					default:
						debug(LOG_ERR, "Bad option on line %d in %s.", *linenum, filename);
						debug(LOG_ERR, "Exiting...");
						goto ERR;
				}
			}
		}
	}

	// Validate mandatory fields
	if (gw_id == NULL || gw_channel == NULL || gw_interface == NULL || gw_subnet_v4 == NULL) {
		debug(LOG_ERR, "Missing mandatory parameters for gateway settings");
		goto ERR;
	}

	debug(LOG_DEBUG, "Adding gateway settings: %s %s %s", gw_id ? gw_id : "null", gw_interface, gw_channel);

	// Allocate and initialize new gateway setting
	new_setting = safe_malloc(sizeof(t_gateway_setting));

	if (!parse_subnet_v4(gw_subnet_v4, &new_setting->ip_v4, &new_setting->mask_v4)) {
		debug(LOG_ERR, "Invalid subnet format: %s", gw_subnet_v4);
		goto ERR;
	}
	new_setting->gw_id = gw_id;
	new_setting->gw_interface = gw_interface;
	new_setting->gw_channel = gw_channel;
	new_setting->auth_mode = 1;
	new_setting->next = NULL;

	// Append to the gateway settings list
	if (config.gateway_settings == NULL) {
		config.gateway_settings = new_setting;
	} else {
		current = config.gateway_settings;
		while (current->next != NULL) {
			current = current->next;
		}
		current->next = new_setting;
	}

	return;

ERR:
	if (gw_id) free(gw_id);
	if (gw_interface) free(gw_interface);
	if (gw_channel) free(gw_channel);
}

/** @internal
Parses auth server information
*/
static void
parse_auth_server(FILE * file, const char *filename, int *linenum)
{
	char 	*host = NULL;
	char	*path = NULL;
	char	*loginscriptpathfragment = NULL;
	char	*portalscriptpathfragment = NULL;
	char	*msgscriptpathfragment = NULL;
	char	*pingscriptpathfragment = NULL;
	char	*authscriptpathfragment = NULL;
	char line[MAX_BUF], *p1, *p2;
	int http_port, ssl_port, ssl_available, opcode;
	int connect_timeout;
	t_auth_serv *new, *tmp;

	/* Defaults */
	path = safe_strdup(DEFAULT_AUTHSERVPATH);
	loginscriptpathfragment 	= safe_strdup(DEFAULT_AUTHSERVLOGINPATHFRAGMENT);
	portalscriptpathfragment 	= safe_strdup(DEFAULT_AUTHSERVPORTALPATHFRAGMENT);
	msgscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVMSGPATHFRAGMENT);
	pingscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVPINGPATHFRAGMENT);
	authscriptpathfragment 		= safe_strdup(DEFAULT_AUTHSERVAUTHPATHFRAGMENT);
	
	http_port = DEFAULT_AUTHSERVPORT;
	ssl_port = DEFAULT_AUTHSERVSSLPORT;
	ssl_available = DEFAULT_AUTHSERVSSLAVAILABLE;
	connect_timeout = 5; // 5 seconds to wait

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++;		   /* increment line counter. */

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
		debug(LOG_ERR, "Missing mandatory parameters for auth server");
		exit(-1);
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
 * @internal
 * Parses mqtt server information
 */
static void
parse_mqtt_server(FILE * file, const char *filename, int *linenum)
{
	char *host = NULL, *username = NULL, *password = NULL, line[MAX_BUF], *p1, *p2;
	int port = 0, opcode;

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++;		   /* increment line counter. */

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
			case oMQTTServer:
				host = safe_strdup(p2);
				break;
			case oMQTTUsername:
				username = safe_strdup(p2);
				break;
			case oMQTTPassword:
				password = safe_strdup(p2);
				break;
			case oMQTTServerPort:
				port = atoi(p2);
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

	/* only proceed if we have an host and a port */
	if (host == NULL || port < 1 || port > 65535) {
		debug(LOG_ERR, "Missing mandatory parameters for mqtt server");
		exit(-1);
	}
	debug(LOG_DEBUG, "Adding %s:%d to the mqtt server", host, port);

	t_mqtt_server *mqtt_server = (t_mqtt_server *)malloc(sizeof(t_mqtt_server));
	mqtt_server->hostname = host;
	mqtt_server->port = port;
	mqtt_server->username = username;
	mqtt_server->password = password;
	config.mqtt_server = mqtt_server;

	debug(LOG_DEBUG, "MQTT server added");
}

static void
parse_ws_server(FILE * file, const char *filename, int *linenum)
{
	char *host = NULL, line[MAX_BUF], *p1, *p2;
	int port = 0, ssl = 0, opcode;
	char *wsscriptpathfragment = NULL;

	wsscriptpathfragment 	= safe_strdup(DEFAULT_WSPATHFRAGMENT);

	/* Parsing loop */
	while (memset(line, 0, MAX_BUF) && fgets(line, MAX_BUF - 1, file) && (strchr(line, '}') == NULL)) {
		(*linenum)++;		   /* increment line counter. */

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
			case oWSServer:
				host = safe_strdup(p2);
				break;
			case oWSServerPort:
				port = atoi(p2);
				break;
			case oWSServerPath:
				free(wsscriptpathfragment);
				wsscriptpathfragment = safe_strdup(p2);
				break;
			case oWSServerSSL:
				ssl = parse_boolean_value(p2);
				if (ssl < 0) {
					debug(LOG_WARNING, "Bad syntax for Parameter: WSServerSSL on line %d " "in %s."
						"The syntax is yes or no." , *linenum, filename);
					exit(-1);
				}
				break;
			case oBadOption:
			default:
				debug(LOG_ERR, "Bad option on line %d " "in %s.", *linenum, filename);
				exit(-1);
				break;
			}
		}
	}

	/* only proceed if we have an host and a port */
	if (host == NULL || port < 1 || port > 65535) {
		debug(LOG_ERR, "Missing mandatory parameters for ws server");
		exit(-1);
	}

	debug(LOG_DEBUG, "Adding %s:%d to the ws server", host, port);
	t_ws_server *ws = (t_ws_server *)malloc(sizeof(t_ws_server));
	ws->hostname = host;
	ws->port = port;
	ws->path = wsscriptpathfragment;
	ws->use_ssl = ssl;
	config.ws_server = ws;

	debug(LOG_DEBUG, "WS server added");
}

/**
@param filename Full path of the configuration file to be read
*/
void
config_read()
{
	const char *filename = config.configfile;
	FILE *fd;
	char line[MAX_BUF] = {0}, *s, *p1, *p2, *rawarg = NULL;
	int linenum = 0, opcode, value;
	size_t len;

	debug(LOG_INFO, "Reading configuration file '%s'", filename);

	if (!(fd = fopen(filename, "r"))) {
		debug(LOG_ERR, "Could not open configuration file '%s', " "exiting...", filename);
		exit(EXIT_FAILURE);
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
				case oGatewayPort:
					sscanf(p1, "%hu", &config.gw_port);
					break;
				case oGatewayHttpsPort:
					sscanf(p1, "%hu", &config.gw_https_port);
					break;
				case oGatewaySetting:
					parse_gateway_settings(fd, filename, &linenum);
					break;
				case oAuthServer:
					parse_auth_server(fd, filename, &linenum);
					break;
				case oTrustedMACList:
					parse_trusted_mac_list(p1);
					break;
				case oTrustedLocalMACList:
					parse_trusted_local_mac_list(p1);
					break;
				case oPopularServers:
					parse_popular_servers(rawarg);
					break;
				case oMQTT:
					parse_mqtt_server(fd, filename, &linenum);
				case oWebSocket:
					parse_ws_server(fd, filename, &linenum);
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
					config.js_redir = parse_boolean_value(p1);
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
				case oUpdateDomainInterval:
					sscanf(p1, "%d", &config.update_domain_interval);
					break;
				case oDNSTimeout:
					config.dns_timeout = safe_strdup(p1);
					break;
				case oAppleCNA:
					sscanf(p1, "%hu", &config.bypass_apple_cna);
					break;
				case oFW4Enable:
					config.fw4_enable = parse_boolean_value(p1);
					break;
				case oDhcpOptionCpi:
					config.dhcp_cpi_uri = safe_strdup(p1);
					break;
				case oEnableDhcpOptionCpi:
					config.enable_dhcp_cpi = parse_boolean_value(p1);
					break;
				case oEnableBypassAuth:
					config.enable_bypass_auth = parse_boolean_value(p1);
					break;
				case oEnableDNSForward:
					config.enable_dns_forward = parse_boolean_value(p1);
					break;
				case oEnableDelConntrack:
					config.enable_del_conntrack = parse_boolean_value(p1);
					break;
				case oAuthServerMode:
					sscanf(p1, "%hu", &config.auth_server_mode);
					break;
				case oEnableAntiNat:
					config.enable_anti_nat = parse_boolean_value(p1);
					break;
				case oEnableUserReload:
					config.enable_user_reload = parse_boolean_value(p1);
					break;
				case oTTLValues:
					config.ttl_values = safe_strdup(p1);
					break;
				case oAntiNatPermitMacs:
					if (is_valid_mac(p1))
						config.anti_nat_permit_macs = safe_strdup(p1);
					else
						debug(LOG_ERR, "Invalid MAC address %s", p1);
					break;
				case oDeviceID:
					config.device_id = safe_strdup(p1);
					break;
				case oAuthServerOfflineFile:
					if (config.authserver_offline_file)
						free(config.authserver_offline_file);
					config.authserver_offline_file = safe_strdup(p1);
					config.is_custom_auth_offline_file = 1;
					break;
				case oInternetOfflineFile:
					if (config.internet_offline_file)
						free(config.internet_offline_file);
					config.internet_offline_file = safe_strdup(p1);
					break;
				case oLocalPortal:
					if (config.local_portal)
						free(config.local_portal);
					config.local_portal = safe_strdup(p1);
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

void
remove_mac(const char *mac, mac_choice_t which)
{
	remove_mac_from_list(mac, which);
}

void
add_mac(const char *mac, mac_choice_t which)
{
	add_mac_from_list(mac, 0, NULL, which);
}


/**
 * @brief Parses a string of MAC addresses and performs add or remove actions.
 *
 * This function takes a string containing one or multiple MAC addresses, validates each
 * address, and either adds it to or removes it from the specified MAC address list based
 * on the provided action.
 *
 * @param ptr     Pointer to the string containing MAC addresses.
 * @param which   Specifies which MAC address list to modify.
 * @param action  Action to perform: non-zero to add MAC addresses, zero to remove them.
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

void
parse_trusted_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, TRUSTED_MAC, 1);
}

void
parse_trusted_local_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, TRUSTED_LOCAL_MAC, 1);
}

void
parse_del_trusted_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, TRUSTED_MAC, 0);
}

void
parse_del_trusted_local_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, TRUSTED_LOCAL_MAC, 0);
}

void
parse_untrusted_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, UNTRUSTED_MAC, 1);
}

void
parse_del_untrusted_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, UNTRUSTED_MAC, 0);
}

void
parse_roam_mac_list(const char *pstr)
{
	parse_mac_list_action(pstr, ROAM_MAC, 1);
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
static void
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
clear_trusted_domains(void)
{
	LOCK_DOMAIN();
	__clear_trusted_domains();
	UNLOCK_DOMAIN();
}

static t_domain_trusted *
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

static t_domain_trusted *
__del_ip_domain_common(const char *domain, trusted_domain_t which)
{
	t_domain_trusted *p = NULL;
	
	if(which == USER_TRUSTED_DOMAIN) {	
    	if (config.domains_trusted != NULL) {
			for(p = config.domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}
    	}
	} else if (which == INNER_TRUSTED_DOMAIN) {
		if (config.inner_domains_trusted != NULL) {
			for(p = config.inner_domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}
    	}
	} else if (which == TRUSTED_PAN_DOMAIN) {	
		if (config.pan_domains_trusted != NULL) {
			for(p = config.pan_domains_trusted; p != NULL; p = p->next) {
				if(strcmp(p->domain, domain) == 0) {
					break;
				}
			}
    	}
	}

	return p;
}

static t_domain_trusted *
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


static t_domain_trusted *
add_domain_common(const char *domain, trusted_domain_t which)
{
	t_domain_trusted *p = NULL;

	LOCK_DOMAIN();

	p = __add_domain_common(domain, which);

	UNLOCK_DOMAIN();

	return p;
}

static void
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

		debug(LOG_DEBUG, "[%s] trust domain [%s] to&from list", action?"add":"del", hostname);
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
parse_del_trusted_pan_domain_string(const char *ptr)
{
	parse_domain_string_common_action(ptr, TRUSTED_PAN_DOMAIN, 0);
}

void
parse_del_trusted_domain_string(const char *ptr)
{
	parse_domain_string_common_action(ptr, USER_TRUSTED_DOMAIN, 0);
}

static void
parse_domain_string_common(const char *ptr, trusted_domain_t which)
{
	parse_domain_string_common_action(ptr, which, 1);
}

void 
parse_user_trusted_domain_string(const char *domain_list)
{
	parse_domain_string_common(domain_list, USER_TRUSTED_DOMAIN);
}

void 
parse_trusted_pan_domain_string(const char *domain_list)
{
	parse_domain_string_common(domain_list, TRUSTED_PAN_DOMAIN);
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

static void
__del_ip_2_domain(t_domain_trusted *dt, const char *ip)
{
	t_ip_trusted *ipt = dt->ips_trusted;
	t_ip_trusted *tmp = NULL;
	for(; ipt != NULL && strcmp(ipt->ip, ip) != 0; tmp = ipt,ipt = ipt->next)
		;
	debug(LOG_DEBUG,"deling ip = %s",ipt->ip);

	if(ipt == NULL)
		return;
	
	if(tmp == NULL) {
		dt->ips_trusted = ipt->next;
	} else {
		tmp->next = ipt->next;
	}	
	free(ipt);	
	return ;
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

/**
 * @brief parse trusted domains and set its ip in thread
 * @param which The INNER_TRUSTED_DOMAIN or USER_TRUSTED_DOMAIN
 * 
 */ 
static void
parse_common_trusted_domain_list(trusted_domain_t which)
{
	evdns_parse_trusted_domain_2_ip(which);
}

void 
parse_user_trusted_domain_list()
{
	parse_common_trusted_domain_list(USER_TRUSTED_DOMAIN);
}

void 
parse_inner_trusted_domain_list()
{
	parse_common_trusted_domain_list(INNER_TRUSTED_DOMAIN);
}

static t_domain_trusted * 
del_domain_ip_common(const char *domain, trusted_domain_t which)
{
	t_domain_trusted *p = NULL;
	LOCK_DOMAIN();
	p = __del_ip_domain_common(domain, which);
	UNLOCK_DOMAIN();

	return p;
}
void del_trusted_ip_list(const char *ptr)
{
	char *ptrcopy = NULL, *pt = NULL;
	char *ip = NULL;
	char *tmp = NULL;
	t_domain_trusted *p = NULL;

	debug(LOG_DEBUG, "Parsing string [%s] for trust domains", ptr);

	if(ptr == NULL)
		return;

	p = del_domain_ip_common("iplist", USER_TRUSTED_DOMAIN);
	if(p == NULL) {
		debug(LOG_ERR, "Impossible: del iplist domain failed");
	return;
	}

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

		debug(LOG_DEBUG, "Deling trust ip [%s] from list", ip);
		__del_ip_2_domain(p, ip);
	}
	UNLOCK_DOMAIN();

    free(pt);
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

static void
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

static void
__clear_mac_list(mac_choice_t which)
{
	t_trusted_mac *p, *p1;
	switch (which) {
	case TRUSTED_MAC:
		p = config.trustedmaclist;
		break;
	case UNTRUSTED_MAC:
		p = config.mac_blacklist;
		break;
	case TRUSTED_LOCAL_MAC:
		p = config.trusted_local_maclist;
		break;
	case ROAM_MAC:
		p = config.roam_maclist;
		break;
	default:
		return;
	}
	
	for (; p != NULL;) {
		p1 = p;
		p = p->next;
		free(p1->mac);
		free(p1);
	}
	
	switch (which) {
	case TRUSTED_MAC:
		config.trustedmaclist = NULL;
		break;
	case UNTRUSTED_MAC:
		config.mac_blacklist = NULL;
		break;
	case TRUSTED_LOCAL_MAC:
		config.trusted_local_maclist = NULL;
		break;
	case ROAM_MAC:
		config.roam_maclist = NULL;
		break;
	}
}

void
clear_roam_mac_list()
{
	LOCK_CONFIG();
	__clear_mac_list(ROAM_MAC);
	UNLOCK_CONFIG();
}

t_trusted_mac *
get_roam_maclist()
{
	return config.roam_maclist;
}

bool
is_trusted_mac(const char *mac)
{
	t_trusted_mac *p = NULL;

	LOCK_CONFIG();
	for (p = config.trustedmaclist; p != NULL; p = p->next) {
		if(strcmp(mac, p->mac) == 0) {
			UNLOCK_CONFIG();
			return true;
		}
	}
	UNLOCK_CONFIG();

	return false;
}

void
clear_trusted_mac_list()
{
	LOCK_CONFIG();
	__clear_mac_list(TRUSTED_MAC);
	UNLOCK_CONFIG();
}

void
clear_trusted_local_mac_list()
{
	LOCK_CONFIG();
	__clear_mac_list(TRUSTED_LOCAL_MAC);
	UNLOCK_CONFIG();
}

void
clear_untrusted_mac_list()
{
	LOCK_CONFIG();
	__clear_mac_list(UNTRUSTED_MAC);
	UNLOCK_CONFIG();
}

static bool
is_auth_server_mode_valid(short mode) 
{
	return (mode >= AUTH_MODE_CLOUD && mode <= AUTH_MODE_LOCAL);
}

/** Verifies if the configuration is complete and valid.  Terminates the program if it isn't */
void
config_validate(void)
{
	if (!is_auth_server_mode_valid(config.auth_server_mode)) {
		debug(LOG_ERR, "Invalid auth server mode: %d", config.auth_server_mode);
		exit(1);
	}
	
	config_notnull(config.gateway_settings, "GatewaySetting");
	config_notnull(config.external_interface, "ExternalInterface");

	if (!is_local_auth_mode()) {
		config_notnull(config.auth_servers, "AuthServer");
	} 
	
	if (config.enable_anti_nat) {
		config_notnull(config.ttl_values, "TTLValues");
	}

	if (config.ws_server) {
		config_notnull(config.ws_server->hostname, "WSHostname");
		config_notnull(config.ws_server->path, "WSPath");
	}

	if (missing_parms) {
		debug(LOG_ERR, "Configuration is incomplete.  Exiting.");
		exit(1);
	}

	validate_popular_servers();
}

/** @internal
 * Validate that popular servers are populated or log a warning and set a default.
 */
static void
validate_popular_servers(void)
{
	if (config.popular_servers == NULL) {
		add_popular_server("www.baidu.com");
		add_popular_server("www.x.com");
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
		if (bad_server->last_ip)
			free(bad_server->last_ip);
		bad_server->last_ip = NULL;
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


bool
is_bypass_mode(void)
{
	return config.auth_server_mode == AUTH_MODE_BYPASS;
}

bool
is_local_auth_mode(void)
{
	return config.auth_server_mode == AUTH_MODE_LOCAL;
}

bool
is_cloud_mode(void)
{
	return config.auth_server_mode == AUTH_MODE_CLOUD;
}

bool
is_custom_auth_offline_page(void)
{
	return config.is_custom_auth_offline_file == 1;
}

bool
is_user_reload_enabled(void)
{
	return config.enable_user_reload;
}