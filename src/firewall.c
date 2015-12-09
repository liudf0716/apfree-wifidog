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

/** @internal
  @file firewall.c
  @brief Firewall update functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  2006 Benoit Grégoire, Technologies Coeus inc. <bock@step.polymtl.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netdb.h>
#include <sys/time.h>

#include "httpd.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "commandline.h"

static int _fw_deny_raw(const char *, const char *, const int);

/**
 * Allow a client access through the firewall by adding a rule in the firewall to MARK the user's packets with the proper
 * rule by providing his IP and MAC address
 * @param ip IP address to allow
 * @param mac MAC address to allow
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_allow(t_client * client, int new_fw_connection_state)
{
    int result;
    int old_state = client->fw_connection_state;

    debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", client->ip, client->mac, new_fw_connection_state);
    client->fw_connection_state = new_fw_connection_state;

    /* Grant first */
    result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);

    /* Deny after if needed. */
    if (old_state != FW_MARK_NONE) {
        debug(LOG_DEBUG, "Clearing previous fw_connection_state %d", old_state);
        _fw_deny_raw(client->ip, client->mac, old_state);
    }

    return result;
}

/**
 * Allow a host through the firewall by adding a rule in the firewall
 * @param host IP address, domain or hostname to allow
 * @return Return code of the command
 */
int
fw_allow_host(const char *host)
{
    debug(LOG_DEBUG, "Allowing %s", host);

    return iptables_fw_access_host(FW_ACCESS_ALLOW, host);
}

/**
 * @brief Deny a client access through the firewall by removing the rule in the firewall that was fw_connection_stateging the user's traffic
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param fw_connection_state fw_connection_state Tag
 * @return Return code of the command
 */
int
fw_deny(t_client * client)
{
    int fw_connection_state = client->fw_connection_state;
    debug(LOG_DEBUG, "Denying %s %s with fw_connection_state %d", client->ip, client->mac, client->fw_connection_state);

    client->fw_connection_state = FW_MARK_NONE; /* Clear */
    return _fw_deny_raw(client->ip, client->mac, fw_connection_state);
}

/** @internal
 * Actually does the clearing, so fw_allow can call it to clear previous mark.
 * @param ip IP address to deny
 * @param mac MAC address to deny
 * @param mark fw_connection_state Tag
 * @return Return code of the command
 */
static int
_fw_deny_raw(const char *ip, const char *mac, const int mark)
{
    return iptables_fw_access(FW_ACCESS_DENY, ip, mac, mark);
}

/** Passthrough for clients when auth server is down */
int
fw_set_authdown(void)
{
    debug(LOG_DEBUG, "Marking auth server down");

    return iptables_fw_auth_unreachable(FW_MARK_AUTH_IS_DOWN);
}

/** Remove passthrough for clients when auth server is up */
int
fw_set_authup(void)
{
    debug(LOG_DEBUG, "Marking auth server up again");

    return iptables_fw_auth_reachable();
}

/* XXX DCY */
/**
 * Get an IP's MAC address from the ARP cache.
 * Go through all the entries in config->arp_table_path until we find the
 * requested IP address and return the MAC address bound to it.
 * @todo Make this function portable (using shell scripts?)
 */
char *
arp_get(const char *req_ip)
{
    FILE *proc;
    char ip[16];
    char mac[18];
    char *reply;
    s_config *config = config_get_config();

    if (!(proc = fopen(config->arp_table_path, "r"))) {
        return NULL;
    }

    /* Skip first line */
    while (!feof(proc) && fgetc(proc) != '\n') ;

    /* Find ip, copy mac in reply */
    reply = NULL;
    while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[A-Fa-f0-9:] %*s %*s", ip, mac) == 2)) {
        if (strcmp(ip, req_ip) == 0) {
            reply = safe_strdup(mac);
            break;
        }
    }

    fclose(proc);

    return reply;
}

/** Initialize the firewall rules
 */
int
fw_init(void)
{
    int result = 0;
    int new_fw_state;
    t_client *client = NULL;

    if (!init_icmp_socket()) {
        return 0;
    }

    debug(LOG_INFO, "Initializing Firewall");
    result = iptables_fw_init();

    if (restart_orig_pid) {
        debug(LOG_INFO, "Restoring firewall rules for clients inherited from parent");
        LOCK_CLIENT_LIST();
        client = client_get_first_client();
        while (client) {
            new_fw_state = client->fw_connection_state;
            client->fw_connection_state = FW_MARK_NONE;
            fw_allow(client, new_fw_state);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();
    }

    return result;
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
    debug(LOG_INFO, "Clearing the authservers list");
    iptables_fw_clear_authservers();
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
    debug(LOG_INFO, "Setting the authservers list");
    iptables_fw_set_authservers();
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
    close_icmp_socket();
    debug(LOG_INFO, "Removing Firewall rules");
    return iptables_fw_destroy();
}

/**Probably a misnomer, this function actually refreshes the entire client list's traffic counter, re-authenticates every client with the central server and update's the central servers traffic counters and notifies it if a client has logged-out.
 * @todo Make this function smaller and use sub-fonctions
 */
void
fw_sync_with_authserver(void)
{
    t_authresponse authresponse;
    t_client *p1, *p2, *worklist, *tmp;
    s_config *config = config_get_config();

    if (-1 == iptables_fw_counters_update()) {
        debug(LOG_ERR, "Could not get counters from firewall!");
        return;
    }

    LOCK_CLIENT_LIST();

    /* XXX Ideally, from a thread safety PoV, this function should build a list of client pointers,
     * iterate over the list and have an explicit "client still valid" check while list is locked.
     * That way clients can disappear during the cycle with no risk of trashing the heap or getting
     * a SIGSEGV.
     */
    client_list_dup(&worklist);
    UNLOCK_CLIENT_LIST();

    for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
        p2 = p1->next;

        /* Ping the client, if he responds it'll keep activity on the link.
         * However, if the firewall blocks it, it will not help.  The suggested
         * way to deal witht his is to keep the DHCP lease time extremely
         * short:  Shorter than config->checkinterval * config->clienttimeout */
        icmp_ping(p1->ip);
        /* Update the counters on the remote server only if we have an auth server */
        if (config->auth_servers != NULL) {
            auth_server_request(&authresponse, REQUEST_TYPE_COUNTERS, p1->ip, p1->mac, p1->token, p1->counters.incoming,
                                p1->counters.outgoing, p1->counters.incoming_delta, p1->counters.outgoing_delta);
        }

        time_t current_time = time(NULL);
        debug(LOG_INFO,
              "Checking client %s for timeout:  Last updated %ld (%ld seconds ago), timeout delay %ld seconds, current time %ld, ",
              p1->ip, p1->counters.last_updated, current_time - p1->counters.last_updated,
              config->checkinterval * config->clienttimeout, current_time);
        if (p1->counters.last_updated + (config->checkinterval * config->clienttimeout) <= current_time) {
            /* Timing out user */
            debug(LOG_INFO, "%s - Inactive for more than %ld seconds, removing client and denying in firewall",
                  p1->ip, config->checkinterval * config->clienttimeout);
            LOCK_CLIENT_LIST();
            tmp = client_list_find_by_client(p1);
            if (NULL != tmp) {
                logout_client(tmp);
            } else {
                debug(LOG_NOTICE, "Client was already removed. Not logging out.");
            }
            UNLOCK_CLIENT_LIST();
        } else {
            /*
             * This handles any change in
             * the status this allows us
             * to change the status of a
             * user while he's connected
             *
             * Only run if we have an auth server
             * configured!
             */
            LOCK_CLIENT_LIST();
            tmp = client_list_find_by_client(p1);
            if (NULL == tmp) {
                UNLOCK_CLIENT_LIST();
                debug(LOG_NOTICE, "Client was already removed. Skipping auth processing");
                continue;       /* Next client please */
            }

            if (config->auth_servers != NULL) {
                switch (authresponse.authcode) {
                case AUTH_DENIED:
                    debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", tmp->ip);
                    fw_deny(tmp);
                    client_list_delete(tmp);
                    break;

                case AUTH_VALIDATION_FAILED:
                    debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules",
                          tmp->ip);
                    fw_deny(tmp);
                    client_list_delete(tmp);
                    break;

                case AUTH_ALLOWED:
                    if (tmp->fw_connection_state != FW_MARK_KNOWN) {
                        debug(LOG_INFO, "%s - Access has changed to allowed, refreshing firewall and clearing counters",
                              tmp->ip);
                        //WHY did we deny, then allow!?!? benoitg 2007-06-21
                        //fw_deny(tmp->ip, tmp->mac, tmp->fw_connection_state); /* XXX this was possibly to avoid dupes. */

                        if (tmp->fw_connection_state != FW_MARK_PROBATION) {
                            tmp->counters.incoming_delta =
                             tmp->counters.outgoing_delta =
                             tmp->counters.incoming =
                             tmp->counters.outgoing = 0;
                        } else {
                            //We don't want to clear counters if the user was in validation, it probably already transmitted data..
                            debug(LOG_INFO,
                                  "%s - Skipped clearing counters after all, the user was previously in validation",
                                  tmp->ip);
                        }
                        fw_allow(tmp, FW_MARK_KNOWN);
                    }
                    break;

                case AUTH_VALIDATION:
                    /*
                     * Do nothing, user
                     * is in validation
                     * period
                     */
                    debug(LOG_INFO, "%s - User in validation period", tmp->ip);
                    break;

                case AUTH_ERROR:
                    debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", tmp->ip);
                    break;

                default:
                    debug(LOG_ERR, "I do not know about authentication code %d", authresponse.authcode);
                    break;
                }
            }
            UNLOCK_CLIENT_LIST();
        }
    }

    client_list_destroy(worklist);
}
