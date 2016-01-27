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

/* $Id$ */
/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

//>>> liudf added 20160127
static FILE	*f_fw_init = NULL;
static FILE	*f_fw_destroy = NULL;
static FILE	*f_fw_allow  = NULL;

static void f_fw_init_close();
static void f_fw_init_open();
static void f_fw_destroy_close();
static void f_fw_destroy_open();
static void f_fw_allow_close();
static void f_fw_allow_open();
static void f_fw_script_write(const char *cmd);

static char *fw_init_script 	= "/tmp/fw_init";
static char *fw_destroy_script 	= "/tmp/fw_destroy";
static char *fw_allow_script	= "/tmp/fw_allow";

//<<< liudf add end

static int iptables_do_command(const char *format, ...);
static char *iptables_compile(const char *, const char *, const t_firewall_rule *);
static void iptables_load_ruleset(const char *, const char *, const char *);

/**
Used to supress the error output of the firewall during destruction */
static int fw_quiet = 0;

/** @internal
 * @brief Insert $ID$ with the gateway's id in a string.
 *
 * This function can replace the input string with a new one. It assumes
 * the input string is dynamically allocted and can be free()ed safely.
 *
 * This function must be called with the CONFIG_LOCK held.
 */
static void
iptables_insert_gateway_id(char **input)
{
    char *token;
    const s_config *config;
    char *buffer;

    if (strstr(*input, "$ID$") == NULL)
        return;

    while ((token = strstr(*input, "$ID$")) != NULL)
        /* This string may look odd but it's standard POSIX and ISO C */
        memcpy(token, "%1$s", 4);

    config = config_get_config();
    safe_asprintf(&buffer, *input, config->gw_interface);

    free(*input);
    *input = buffer;
}

/** @internal 
 * */
static int
ipset_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "ipset %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);
	
	// liudf added 20160127
	f_fw_script_write(cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "ipset command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "ipset command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/** @internal
 * */
static void
iptables_do_command_save(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

	f_fw_script_write(cmd);

    free(cmd);
}

/** @internal 
 * */
static int
iptables_do_command(const char *format, ...)
{
    va_list vlist;
    char *fmt_cmd;
    char *cmd;
    int rc;

    va_start(vlist, format);
    safe_vasprintf(&fmt_cmd, format, vlist);
    va_end(vlist);

    safe_asprintf(&cmd, "iptables %s", fmt_cmd);
    free(fmt_cmd);

    iptables_insert_gateway_id(&cmd);

	f_fw_script_write(cmd);

    debug(LOG_DEBUG, "Executing command: %s", cmd);

    rc = execute(cmd, fw_quiet);

    if (rc != 0) {
        // If quiet, do not display the error
        if (fw_quiet == 0)
            debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);
        else if (fw_quiet == 1)
            debug(LOG_DEBUG, "iptables command failed(%d): %s", rc, cmd);
    }

    free(cmd);

    return rc;
}

/**
 * @internal
 * Compiles a struct definition of a firewall rule into a valid iptables
 * command.
 * @arg table Table containing the chain.
 * @arg chain Chain that the command will be (-A)ppended to.
 * @arg rule Definition of a rule into a struct, from conf.c.
 */
static char *
iptables_compile(const char *table, const char *chain, const t_firewall_rule * rule)
{
    char command[MAX_BUF], *mode;

    memset(command, 0, MAX_BUF);
    mode = NULL;

    switch (rule->target) {
    case TARGET_DROP:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("DROP");
        break;
    case TARGET_REJECT:
        if (strncmp(table, "nat", 3) == 0) {
            free(mode);
            return NULL;
        }
        mode = safe_strdup("REJECT");
        break;
    case TARGET_ACCEPT:
        mode = safe_strdup("ACCEPT");
        break;
    case TARGET_LOG:
        mode = safe_strdup("LOG");
        break;
    case TARGET_ULOG:
        mode = safe_strdup("ULOG");
        break;
    }

    snprintf(command, sizeof(command), "-t %s -A %s ", table, chain);
    if (rule->mask != NULL) {
        if (rule->mask_is_ipset) {
            snprintf((command + strlen(command)), (sizeof(command) -
                                                   strlen(command)), "-m set --match-set %s dst ", rule->mask);
        } else {
            snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-d %s ", rule->mask);
        }
    }
    if (rule->protocol != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-p %s ", rule->protocol);
    }
    if (rule->port != NULL) {
        snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "--dport %s ", rule->port);
    }
    snprintf((command + strlen(command)), (sizeof(command) - strlen(command)), "-j %s", mode);

    free(mode);

    /* XXX The buffer command, an automatic variable, will get cleaned
     * off of the stack when we return, so we strdup() it. */
    return (safe_strdup(command));
}

/**
 * @internal
 * Load all the rules in a rule set.
 * @arg ruleset Name of the ruleset
 * @arg table Table containing the chain.
 * @arg chain IPTables chain the rules go into
 */
static void
iptables_load_ruleset(const char *table, const char *ruleset, const char *chain)
{
    t_firewall_rule *rule;
    char *cmd;

    debug(LOG_DEBUG, "Load ruleset %s into table %s, chain %s", ruleset, table, chain);

    for (rule = get_ruleset(ruleset); rule != NULL; rule = rule->next) {
        cmd = iptables_compile(table, chain, rule);
        if (cmd != NULL) {
            debug(LOG_DEBUG, "Loading rule \"%s\" into table %s, chain %s", cmd, table, chain);
            iptables_do_command(cmd);
        }
        free(cmd);
    }

    debug(LOG_DEBUG, "Ruleset %s loaded into table %s, chain %s", ruleset, table, chain);
}

void
iptables_fw_clear_authservers(void)
{
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
}

void
iptables_fw_set_authservers(void)
{
    const s_config *config;
    t_auth_serv *auth_server;

    config = config_get_config();

    for (auth_server = config->auth_servers; auth_server != NULL; auth_server = auth_server->next) {
        if (auth_server->last_ip && strcmp(auth_server->last_ip, "0.0.0.0") != 0) {
            iptables_do_command("-t filter -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
            iptables_do_command("-t nat -A " CHAIN_AUTHSERVERS " -d %s -j ACCEPT", auth_server->last_ip);
        }
    }

}

// >>>liudf added 20151223

void
iptables_fw_refresh_user_domains_trusted(void)
{
	iptables_fw_clear_user_domains_trusted();
	iptables_fw_set_user_domains_trusted();
}

void
iptables_fw_clear_user_domains_trusted(void)
{
	ipset_do_command("flush " CHAIN_DOMAIN_TRUSTED);
}

void
iptables_fw_set_user_domains_trusted(void)
{
	const s_config *config;
	t_domain_trusted *domain_trusted = NULL;

    config = config_get_config();
	
	for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		t_ip_trusted *ip_trusted = NULL;
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
			ipset_do_command("add " CHAIN_DOMAIN_TRUSTED " %s ", ip_trusted->ip);
		}
	}
}

// set inner trusted domains
void
iptables_fw_refresh_inner_domains_trusted(void)
{
	iptables_fw_clear_inner_domains_trusted();
	iptables_fw_set_inner_domains_trusted();
}

void
iptables_fw_clear_inner_domains_trusted(void)
{
	ipset_do_command("flush " CHAIN_INNER_DOMAIN_TRUSTED);
}

void
iptables_fw_set_inner_domains_trusted(void)
{
	const s_config *config;
	t_domain_trusted *domain_trusted = NULL;

    config = config_get_config();
	
	for (domain_trusted = config->inner_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		t_ip_trusted *ip_trusted = NULL;
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
			ipset_do_command("add " CHAIN_INNER_DOMAIN_TRUSTED " %s ", ip_trusted->ip);
		}
	}
}


void
iptables_fw_clear_roam_maclist(void)
{
	ipset_do_command("flush " CHAIN_ROAM);
}

void
iptables_fw_set_roam_mac(const char *mac)
{
	ipset_do_command("add " CHAIN_ROAM " %s", mac);
}

void
iptables_fw_clear_trusted_maclist(void)
{
	ipset_do_command("flush " CHAIN_TRUSTED);
}

void
iptables_fw_set_trusted_maclist(void)
{
	const s_config *config;
	t_trusted_mac *p = NULL;
	
    config = config_get_config();

	for (p = config->trustedmaclist; p != NULL; p = p->next)
		ipset_do_command("add " CHAIN_TRUSTED " %s", p->mac);
}

void
iptables_fw_clear_untrusted_maclist(void)
{
	ipset_do_command("flush " CHAIN_UNTRUSTED);
}

void
iptables_fw_set_untrusted_maclist(void)
{
	const s_config *config;
	t_trusted_mac *p = NULL;

    config = config_get_config();

	for (p = config->mac_blacklist; p != NULL; p = p->next)
		ipset_do_command("add " CHAIN_UNTRUSTED " %s", p->mac);
}

static void
f_fw_init_close()
{
	if(f_fw_init) {
		fclose(f_fw_init);
		f_fw_init = NULL;
	}
}

static void
f_fw_init_open()
{
	if(f_fw_init)
		return;

	f_fw_init = fopen(fw_init_script, "w"); 
	if(f_fw_init) {
		fchmod(f_fw_init, S_IXOTH);
		fprintf(f_fw_init, "#!/bin/sh");
	}
}

static void
f_fw_script_write(const char *cmd)
{
	if(f_fw_init) 
		fprintf(f_fw_init, cmd);
	
	if(f_fw_destroy)
		fprintf(f_fw_destroy, cmd);
	
	if(f_fw_allow)
		fprintf(f_fw_allow, cmd);
}

static void
f_fw_destroy_close()
{
	if(f_fw_destroy) {
		fclose(f_fw_destroy);
		f_fw_destroy = NULL;
	}
}

static void
f_fw_destroy_open()
{
	if(f_fw_destroy)
		return;

	f_fw_destroy = fopen(fw_destroy_script, "w"); 
	if(f_fw_destroy) {
		fchmod(f_fw_destroy, S_IXOTH);
		fprintf(f_fw_destroy, "#!/bin/sh");
	}
}

static void
f_fw_allow_close()
{
	if(f_fw_allow) {
		fclose(f_fw_allow);
		f_fw_allow = NULL;
	}
}

static void
f_fw_allow_open()
{
	if(f_fw_allow)
		return;

	f_fw_allow = fopen(fw_allow_script, "w"); 
	if(f_fw_allow) {
		fchmod(f_fw_allow, S_IXOTH);
		fprintf(f_fw_allow, "#!/bin/sh");
	}
}

void
iptables_fw_save_online_clients()
{
	t_client *sublist, *current;

	LOCK_CLIENT_LIST();

    client_list_dup(&sublist);

    UNLOCK_CLIENT_LIST();

    current = sublist;
	
	f_fw_allow_open();

    while (current != NULL) {
		iptables_do_command_save("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", 
					current->ip, current->mac, FW_MARK_KNOWN);
        iptables_do_command_save("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", current->ip);

        current = current->next;
    }

	f_fw_allow_close();	
}
// <<< liudf added end

/** Initialize the firewall rules
*/
int
iptables_fw_init(void)
{
    const s_config *config;
    char *ext_interface = NULL;
    int gw_port = 0;
    int proxy_port;
    fw_quiet = 0;
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
	
	// liudf added 20160127	
	if(access(fw_init_script, F_OK|X_OK)) {
		// need to create it
		f_fw_init_open();
	} else {
		// execut fw_init_script
	}
	
    LOCK_CONFIG();
    config = config_get_config();
    gw_port = config->gw_port;
    if (config->external_interface) {
        ext_interface = safe_strdup(config->external_interface);
    } else {
        ext_interface = get_ext_iface();
    }

    if (ext_interface == NULL) {
        UNLOCK_CONFIG();
		f_fw_init_close();	
        debug(LOG_ERR, "FATAL: no external interface");
        return 0;
    }
	
	

	// add ipset support
	ipset_do_command("create " CHAIN_TRUSTED " hash:mac");
	ipset_do_command("create " CHAIN_ROAM " hash:mac");
	ipset_do_command("create " CHAIN_UNTRUSTED " hash:mac");
	ipset_do_command("create " CHAIN_DOMAIN_TRUSTED " hash:ip ");
	ipset_do_command("create " CHAIN_INNER_DOMAIN_TRUSTED " hash:ip ");

    /*
     *
     * Everything in the MANGLE table
     *
     */

    /* Create new chains */
	// liudf added 20160106
    iptables_do_command("-t mangle -N " CHAIN_ROAM);
    iptables_do_command("-t mangle -N " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -N " CHAIN_OUTGOING);
    iptables_do_command("-t mangle -N " CHAIN_INCOMING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_OUTGOING, config->gw_interface);
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_TRUSTED, config->gw_interface);     //this rule will be inserted before the prior one
	// liudf added 20160106
    iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_ROAM, config->gw_interface);    
	iptables_do_command("-t mangle -A " CHAIN_ROAM " -m set --match-set " CHAIN_ROAM " src -j MARK --set-mark %d",
		 				FW_MARK_KNOWN);

    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -I PREROUTING 1 -i %s -j " CHAIN_AUTH_IS_DOWN, config->gw_interface);    //this rule must be last in the chain
    iptables_do_command("-t mangle -I POSTROUTING 1 -o %s -j " CHAIN_INCOMING, config->gw_interface);
	
	//>>> liudf added&modified 20160113	 
    iptables_do_command("-t mangle -A " CHAIN_TRUSTED " -m set --match-set " CHAIN_TRUSTED " src -j MARK --set-mark %d",
		 				FW_MARK_KNOWN);
	//<<< liudf added end

    /*
     *
     * Everything in the NAT table
     *
     */

    /* Create new chains */
	iptables_do_command("-t nat -N " CHAIN_UNTRUSTED);
    iptables_do_command("-t nat -N " CHAIN_OUTGOING);
    iptables_do_command("-t nat -N " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -N " CHAIN_GLOBAL);
    iptables_do_command("-t nat -N " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -N " CHAIN_AUTHSERVERS);
	//>>> liudf added 20151224
    iptables_do_command("-t nat -N " CHAIN_DOMAIN_TRUSTED);
    //<<< liudf added end
	if (got_authdown_ruleset)
        iptables_do_command("-t nat -N " CHAIN_AUTH_IS_DOWN);
	
	//>>> liudf added 20160113
	// add this rule for mac blacklist
 	iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_UNTRUSTED, config->gw_interface);
	iptables_do_command("-t nat -A " CHAIN_UNTRUSTED " -m set --match-set " CHAIN_UNTRUSTED " src -j MARK --set-mark 0x%u", FW_MARK_LOCKED);
	//<<<

    /* Assign links and rules to these new chains */
    iptables_do_command("-t nat -A PREROUTING -i %s -j " CHAIN_OUTGOING, config->gw_interface);
	
	
    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -d %s -j " CHAIN_TO_ROUTER, config->gw_address);
    iptables_do_command("-t nat -A " CHAIN_TO_ROUTER " -j ACCEPT");

    iptables_do_command("-t nat -A " CHAIN_OUTGOING " -j " CHAIN_TO_INTERNET);

    if ((proxy_port = config_get_config()->proxy_port) != 0) {
        debug(LOG_DEBUG, "Proxy port set, setting proxy rule");
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_KNOWN,
                            proxy_port);
        iptables_do_command("-t nat -A " CHAIN_TO_INTERNET
                            " -p tcp --dport 80 -m mark --mark 0x%u -j REDIRECT --to-port %u", FW_MARK_PROBATION,
                            proxy_port);
    }

    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_KNOWN);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j ACCEPT", FW_MARK_PROBATION);
    iptables_do_command("-t nat -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);

    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTHSERVERS);
	// liudf added 20151224
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_DOMAIN_TRUSTED);
	iptables_do_command("-t nat -A " CHAIN_DOMAIN_TRUSTED " -m set --match-set " CHAIN_DOMAIN_TRUSTED " dst -j ACCEPT");
	iptables_do_command("-t nat -A " CHAIN_DOMAIN_TRUSTED " -m set --match-set " CHAIN_INNER_DOMAIN_TRUSTED " dst -j ACCEPT");
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_GLOBAL);
    if (got_authdown_ruleset) {
        iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -j " CHAIN_AUTH_IS_DOWN);
        iptables_do_command("-t nat -A " CHAIN_AUTH_IS_DOWN " -m mark --mark 0x%u -j ACCEPT", FW_MARK_AUTH_IS_DOWN);
    }
    iptables_do_command("-t nat -A " CHAIN_UNKNOWN " -p tcp --dport 80 -j REDIRECT --to-ports %d", gw_port);

    /*
     *
     * Everything in the FILTER table
     *
     */

    /* Create new chains */
    iptables_do_command("-t filter -N " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -N " CHAIN_AUTHSERVERS);
	// liudf added 20151224
    iptables_do_command("-t filter -N " CHAIN_DOMAIN_TRUSTED);
    iptables_do_command("-t filter -N " CHAIN_LOCKED);
    iptables_do_command("-t filter -N " CHAIN_GLOBAL);
    iptables_do_command("-t filter -N " CHAIN_VALIDATE);
    iptables_do_command("-t filter -N " CHAIN_KNOWN);
    iptables_do_command("-t filter -N " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -N " CHAIN_AUTH_IS_DOWN);

    /* Assign links and rules to these new chains */
	
    /* Insert at the beginning */
    iptables_do_command("-t filter -I FORWARD -i %s -j " CHAIN_TO_INTERNET, config->gw_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state INVALID -j DROP");

    /* XXX: Why this? it means that connections setup after authentication
       stay open even after the connection is done... 
       iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m state --state RELATED,ESTABLISHED -j ACCEPT"); */

    //Won't this rule NEVER match anyway?!?!? benoitg, 2007-06-23
    //iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -i %s -m state --state NEW -j DROP", ext_interface);

    /* TCPMSS rule for PPPoE */
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET
                        " -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu", ext_interface);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_AUTHSERVERS);
    iptables_fw_set_authservers();
	
	// liudf added 20151224
    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_LOCKED, FW_MARK_LOCKED);
    iptables_load_ruleset("filter", FWRULESET_LOCKED_USERS, CHAIN_LOCKED);
    
	iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_DOMAIN_TRUSTED);
	iptables_do_command("-t filter -A " CHAIN_DOMAIN_TRUSTED " -m set --match-set " CHAIN_DOMAIN_TRUSTED " dst -j ACCEPT");
	iptables_do_command("-t filter -A " CHAIN_DOMAIN_TRUSTED " -m set --match-set " CHAIN_INNER_DOMAIN_TRUSTED " dst -j ACCEPT");
	

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_GLOBAL);
  	iptables_load_ruleset("filter", FWRULESET_GLOBAL, CHAIN_GLOBAL);
    iptables_load_ruleset("nat", FWRULESET_GLOBAL, CHAIN_GLOBAL);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_VALIDATE, FW_MARK_PROBATION);
    iptables_load_ruleset("filter", FWRULESET_VALIDATING_USERS, CHAIN_VALIDATE);

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_KNOWN, FW_MARK_KNOWN);
    iptables_load_ruleset("filter", FWRULESET_KNOWN_USERS, CHAIN_KNOWN);

    if (got_authdown_ruleset) {
        iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -m mark --mark 0x%u -j " CHAIN_AUTH_IS_DOWN,
                            FW_MARK_AUTH_IS_DOWN);
        iptables_load_ruleset("filter", FWRULESET_AUTH_IS_DOWN, CHAIN_AUTH_IS_DOWN);
    }

    iptables_do_command("-t filter -A " CHAIN_TO_INTERNET " -j " CHAIN_UNKNOWN);
    iptables_load_ruleset("filter", FWRULESET_UNKNOWN_USERS, CHAIN_UNKNOWN);
    iptables_do_command("-t filter -A " CHAIN_UNKNOWN " -j REJECT --reject-with icmp-port-unreachable");

	
	__fix_weixin_http_dns_ip();

    UNLOCK_CONFIG();
	
	parse_user_trusted_domain_list();
	parse_inner_trusted_domain_list();

    free(ext_interface);

	//>>> liudf added 20160114
	// after initialize firewall chain; 
	// add trusted&untrusted mac list; parse and add trusted domain	
	fw_set_trusted_maclist();
	fw_set_untrusted_maclist();
	
	iptables_fw_set_inner_domains_trusted();
    iptables_fw_set_user_domains_trusted();

	f_fw_init_close();
	//<<< liudf added end

    return 1;
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int
iptables_fw_destroy(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    fw_quiet = 1;

    debug(LOG_DEBUG, "Destroying our iptables entries");
	
	// liudf added 20160127	
	if(access(fw_destroy_script, F_OK|X_OK)) {
		f_fw_destroy_open();
	} else {
	}
	
    /*
     *
     * Everything in the MANGLE table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the MANGLE table");
	// liudf added 20160106
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_ROAM);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_TRUSTED);
    iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_fw_destroy_mention("mangle", "PREROUTING", CHAIN_AUTH_IS_DOWN);
    iptables_fw_destroy_mention("mangle", "POSTROUTING", CHAIN_INCOMING);
	// liudf added 20160106
    iptables_do_command("-t mangle -F " CHAIN_ROAM);
    iptables_do_command("-t mangle -F " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -F " CHAIN_INCOMING);
	// liudf added 20160106
    iptables_do_command("-t mangle -X " CHAIN_ROAM);
    iptables_do_command("-t mangle -X " CHAIN_TRUSTED);
    iptables_do_command("-t mangle -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t mangle -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t mangle -X " CHAIN_INCOMING);

    /*
     *
     * Everything in the NAT table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the NAT table");
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_UNTRUSTED);
    iptables_fw_destroy_mention("nat", "PREROUTING", CHAIN_OUTGOING);
    iptables_do_command("-t nat -F " CHAIN_AUTHSERVERS);
	// liudf added 20151224
    iptables_do_command("-t nat -F " CHAIN_UNTRUSTED);
    iptables_do_command("-t nat -F " CHAIN_DOMAIN_TRUSTED);
    iptables_do_command("-t nat -F " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -F " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -F " CHAIN_GLOBAL);
    iptables_do_command("-t nat -F " CHAIN_UNKNOWN);
    iptables_do_command("-t nat -X " CHAIN_AUTHSERVERS);
	// liudf added 20151224
   	iptables_do_command("-t nat -X " CHAIN_UNTRUSTED);
    iptables_do_command("-t nat -X " CHAIN_DOMAIN_TRUSTED);
    iptables_do_command("-t nat -X " CHAIN_OUTGOING);
    if (got_authdown_ruleset)
        iptables_do_command("-t nat -X " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t nat -X " CHAIN_TO_ROUTER);
    iptables_do_command("-t nat -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t nat -X " CHAIN_GLOBAL);
    iptables_do_command("-t nat -X " CHAIN_UNKNOWN);

    /*
     *
     * Everything in the FILTER table
     *
     */
    debug(LOG_DEBUG, "Destroying chains in the FILTER table");
    iptables_fw_destroy_mention("filter", "FORWARD", CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -F " CHAIN_AUTHSERVERS);
	// liudf added 20151224
    iptables_do_command("-t filter -F " CHAIN_DOMAIN_TRUSTED);
    iptables_do_command("-t filter -F " CHAIN_LOCKED);
    iptables_do_command("-t filter -F " CHAIN_GLOBAL);
    iptables_do_command("-t filter -F " CHAIN_VALIDATE);
    iptables_do_command("-t filter -F " CHAIN_KNOWN);
    iptables_do_command("-t filter -F " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -F " CHAIN_AUTH_IS_DOWN);
    iptables_do_command("-t filter -X " CHAIN_TO_INTERNET);
    iptables_do_command("-t filter -X " CHAIN_AUTHSERVERS);
	// liudf added 20151224
    iptables_do_command("-t filter -X " CHAIN_DOMAIN_TRUSTED);
    iptables_do_command("-t filter -X " CHAIN_LOCKED);
    iptables_do_command("-t filter -X " CHAIN_GLOBAL);
    iptables_do_command("-t filter -X " CHAIN_VALIDATE);
    iptables_do_command("-t filter -X " CHAIN_KNOWN);
    iptables_do_command("-t filter -X " CHAIN_UNKNOWN);
    if (got_authdown_ruleset)
        iptables_do_command("-t filter -X " CHAIN_AUTH_IS_DOWN);
	
	//>>> destroy all our ipset set 	
	ipset_do_command("destroy " CHAIN_TRUSTED);
	ipset_do_command("destroy " CHAIN_ROAM);
	ipset_do_command("destroy " CHAIN_UNTRUSTED);
	ipset_do_command("destroy " CHAIN_DOMAIN_TRUSTED);
	ipset_do_command("destroy " CHAIN_INNER_DOMAIN_TRUSTED);
	
	// liudf added 20160127
	f_fw_destroy_close();

    return 1;
}

/*
 * Helper for iptables_fw_destroy
 * @param table The table to search
 * @param chain The chain in that table to search
 * @param mention A word to find and delete in rules in the given table+chain
 */
int
iptables_fw_destroy_mention(const char *table, const char *chain, const char *mention)
{
    FILE *p = NULL;
    char *command = NULL;
    char *command2 = NULL;
    char line[MAX_BUF] = {0};
    char rulenum[10] = {0};
    char *victim = safe_strdup(mention);
    int deleted = 0;

    iptables_insert_gateway_id(&victim);

    debug(LOG_DEBUG, "Attempting to destroy all mention of %s from %s.%s", victim, table, chain);

    safe_asprintf(&command, "iptables -t %s -L %s -n --line-numbers -v", table, chain);
    iptables_insert_gateway_id(&command);

    if ((p = popen(command, "r"))) {
        /* Skip first 2 lines */
        while (!feof(p) && fgetc(p) != '\n') ;
        while (!feof(p) && fgetc(p) != '\n') ;
        /* Loop over entries */
        while (fgets(line, sizeof(line), p)) {
            /* Look for victim */
            if (strstr(line, victim)) {
                /* Found victim - Get the rule number into rulenum */
                if (sscanf(line, "%9[0-9]", rulenum) == 1) {
                    /* Delete the rule: */
                    debug(LOG_DEBUG, "Deleting rule %s from %s.%s because it mentions %s", rulenum, table, chain,
                          victim);
                    safe_asprintf(&command2, "-t %s -D %s %s", table, chain, rulenum);
                    iptables_do_command(command2);
                    free(command2);
                    deleted = 1;
                    /* Do not keep looping - the captured rulenums will no longer be accurate */
                    break;
                }
            }
        }
        pclose(p);
    }

    free(command);
    free(victim);

    if (deleted) {
        /* Recurse just in case there are more in the same table+chain */
        iptables_fw_destroy_mention(table, chain, mention);
    }

    return (deleted);
}

/** Set if a specific client has access through the firewall */
int
iptables_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t mangle -A " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -A " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    case FW_ACCESS_DENY:
        /* XXX Add looping to really clear? */
        iptables_do_command("-t mangle -D " CHAIN_OUTGOING " -s %s -m mac --mac-source %s -j MARK --set-mark %d", ip,
                            mac, tag);
        rc = iptables_do_command("-t mangle -D " CHAIN_INCOMING " -d %s -j ACCEPT", ip);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

int
iptables_fw_access_host(fw_access_t type, const char *host)
{
    int rc;

    fw_quiet = 0;

    switch (type) {
    case FW_ACCESS_ALLOW:
        iptables_do_command("-t nat -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -A " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    case FW_ACCESS_DENY:
        iptables_do_command("-t nat -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        rc = iptables_do_command("-t filter -D " CHAIN_GLOBAL " -d %s -j ACCEPT", host);
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

/** Set a mark when auth server is not reachable */
int
iptables_fw_auth_unreachable(int tag)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -A " CHAIN_AUTH_IS_DOWN " -j MARK --set-mark 0x%u", tag);
    else
        return 1;
}

/** Remove mark when auth server is reachable again */
int
iptables_fw_auth_reachable(void)
{
    int got_authdown_ruleset = NULL == get_ruleset(FWRULESET_AUTH_IS_DOWN) ? 0 : 1;
    if (got_authdown_ruleset)
        return iptables_do_command("-t mangle -F " CHAIN_AUTH_IS_DOWN);
    else
        return 1;
}

// liudf added 20160127
/***/
void
__get_client_name(t_client *client)
{
	char cmd[256] = {0};
	FILE *f_dhcp = NULL;
 	
	snprintf(cmd, 256, "cat /tmp/dhcp.leases |grep %s|cut -d' ' -f 4", client->ip);	
	
	if((f_dhcp = popen(cmd, "r"))) {
		char name[32] = {0};
		fgets(name, 31,  f_dhcp);
		client->name = safe_strdup(name);
		pclose(f_dhcp);
	}
}

/** Update the counters of all the clients in the client list */
int
iptables_fw_counters_update(void)
{
    FILE *output;
    char *script, ip[16] = {0}, rc;
    unsigned long long int counter;
    t_client *p1;
    struct in_addr tempaddr;

    /* Look for outgoing traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_OUTGOING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s %*s", &counter, ip);
        //rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %15[0-9.] %*s %*s %*s %*s %*s 0x%*u", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read outgoing traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.outgoing - p1->counters.outgoing_history) < counter) {
                    p1->counters.outgoing_delta = p1->counters.outgoing_history + counter - p1->counters.outgoing;
                    p1->counters.outgoing = p1->counters.outgoing_history + counter;
                    p1->counters.last_updated = time(NULL);
                    debug(LOG_DEBUG, "%s - Outgoing traffic %llu bytes, updated counter.outgoing to %llu bytes.  Updated last_updated to %d", ip,
                          counter, p1->counters.outgoing, p1->counters.last_updated);
                }
				
				// liudf added 20160127
				// get client name	
				if(p1->name)
					__get_client_name();

            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
			
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    /* Look for incoming traffic */
    safe_asprintf(&script, "%s %s", "iptables", "-v -n -x -t mangle -L " CHAIN_INCOMING);
    iptables_insert_gateway_id(&script);
    output = popen(script, "r");
    free(script);
    if (!output) {
        debug(LOG_ERR, "popen(): %s", strerror(errno));
        return -1;
    }

    /* skip the first two lines */
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (('\n' != fgetc(output)) && !feof(output)) ;
    while (output && !(feof(output))) {
        rc = fscanf(output, "%*s %llu %*s %*s %*s %*s %*s %*s %15[0-9.]", &counter, ip);
        if (2 == rc && EOF != rc) {
            /* Sanity */
            if (!inet_aton(ip, &tempaddr)) {
                debug(LOG_WARNING, "I was supposed to read an IP address but instead got [%s] - ignoring it", ip);
                continue;
            }
            debug(LOG_DEBUG, "Read incoming traffic for %s: Bytes=%llu", ip, counter);
            LOCK_CLIENT_LIST();
            if ((p1 = client_list_find_by_ip(ip))) {
                if ((p1->counters.incoming - p1->counters.incoming_history) < counter) {
                    p1->counters.incoming_delta = p1->counters.incoming_history + counter - p1->counters.incoming;
                    p1->counters.incoming = p1->counters.incoming_history + counter;
                    debug(LOG_DEBUG, "%s - Incoming traffic %llu bytes, Updated counter.incoming to %llu bytes", ip, counter, p1->counters.incoming);
                }
            } else {
                debug(LOG_ERR,
                      "iptables_fw_counters_update(): Could not find %s in client list, this should not happen unless if the gateway crashed",
                      ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_OUTGOING);
                iptables_fw_destroy_mention("mangle", CHAIN_OUTGOING, ip);
                debug(LOG_ERR, "Preventively deleting firewall rules for %s in table %s", ip, CHAIN_INCOMING);
                iptables_fw_destroy_mention("mangle", CHAIN_INCOMING, ip);
            }
            UNLOCK_CLIENT_LIST();
        }
    }
    pclose(output);

    return 1;
}
