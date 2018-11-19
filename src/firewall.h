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
/** @file firewall.h
    @brief Firewall update functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _FIREWALL_H_
#define _FIREWALL_H_

#include "client_list.h"
#include "auth.h"

/** Used by fw_iptables.c */
typedef enum _t_fw_marks {
    FW_MARK_NONE = 0, /**< @brief No mark set. */
    FW_MARK_PROBATION = 1, /**< @brief The client is in probation period and must be authenticated 
			    @todo: VERIFY THAT THIS IS ACCURATE*/
    FW_MARK_KNOWN = 2,  /**< @brief The client is known to the firewall */
    FW_MARK_AUTH_IS_DOWN = 253, /**< @brief The auth servers are down */
    FW_MARK_LOCKED = 254 /**< @brief The client has been locked out */
} t_fw_marks;

struct wd_request_context;

/** @brief Initialize the firewall */
int fw_init(void);

/** @brief Clears the authservers list */
void fw_clear_authservers(void);

/** @brief Sets the authservers list */
void fw_set_authservers(void);

/** @brief Destroy the firewall */
int fw_destroy(void);

/** @brief Allow a user through the firewall*/
int fw_allow(t_client *, int);

/** @brief Allow a host through the firewall*/
int fw_allow_host(const char *);

/** @brief Deny a client access through the firewall*/
int fw_deny(t_client *);

/** @brief Passthrough for clients when auth server is down */
int fw_set_authdown(void);

/** @brief Remove passthrough for clients when auth server is up */
int fw_set_authup(void);

/** @brief Get an IP's MAC address from the ARP cache.*/
char *arp_get(const char *);

/** @brief Get a Mac's ip from ARP cache*/
char *arp_get_ip(const char *);

/** @brief refer to iptables_fw_clear_domains_trusted */
void fw_clear_user_domains_trusted(void);

/** @brief refer to iptables_fw_set_domains_trusted */
void fw_set_user_domains_trusted(void);

/** @brief refer to iptables_fw_refresh_domains_trusted */
void fw_refresh_user_domains_trusted(void);

/** pan domains */
void fw_clear_pan_domains_trusted(void);

void fw_set_pan_domains_trusted(void);

/** inner trusted domains */

void fw_set_inner_domains_trusted(void);
void fw_clear_inner_domains_trusted(void);
void fw_refresh_inner_domains_trusted(void);


void fw_clear_roam_maclist(void);

void fw_set_roam_mac(const char *);

void fw_set_trusted_maclist();

void fw_clear_trusted_maclist();

void fw_set_trusted_local_maclist();

void fw_clear_trusted_local_maclist();

void fw_set_untrusted_maclist();

void fw_clear_untrusted_maclist();

void fw_set_mac_temporary(const char *, int);

void fw_set_trusted_mac(const char *);

void fw_client_process_from_authserver_response(t_authresponse *, t_client *p1);

/** @brief Refreshes the entire client list */
void ev_fw_sync_with_authserver(struct wd_request_context *);

/** @brief  */
void ev_fw_sync_with_authserver_v2(struct wd_request_context *);

#endif                          /* _FIREWALL_H_ */
