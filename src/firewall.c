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
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE

#include "common.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "ping_thread.h"
#include "firewall.h"
#include "fw_iptables.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "commandline.h"
#include "wd_util.h"
#include "wd_client.h"

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

	/* Deny after if needed. */
	if (old_state != FW_MARK_NONE) {
		debug(LOG_DEBUG, "Clearing previous fw_connection_state %d", old_state);
		_fw_deny_raw(client->ip, client->mac, old_state);
	}

	debug(LOG_DEBUG, "Allowing %s %s with fw_connection_state %d", client->ip, client->mac, new_fw_connection_state);
	client->fw_connection_state = new_fw_connection_state;

	/* Grant first */
	result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);

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
	s_config *config = config_get_config();
	FILE *proc;
	if (!(proc = fopen(config->arp_table_path, "r"))) {
		return NULL;
	}

	/* skip first line */
	while (!feof(proc) && fgetc(proc) != '\n') ;

	/* find ip, copy mac in reply */
	char ip[IP_LENGTH] = {0}, mac[MAC_LENGTH] = {0};
	while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		if (strcmp(ip, req_ip) == 0) {
			return safe_strdup(mac);
		}
	}
	fclose(proc);

	return NULL;
}

char *
arp_get_ip(const char *req_mac)
{
	FILE *proc 		= NULL;
	char ip[16] 	= {0};
	char mac[18] 	= {0};
	char *reply;
	s_config *config = config_get_config();

	if (!(proc = fopen(config->arp_table_path, "r"))) {
		return NULL;
	}

	/* skip first line */
	while (!feof(proc) && fgetc(proc) != '\n') ;

	/* find last mac, copy ip in reply */
	reply = NULL;
	while (!feof(proc) && (fscanf(proc, " %15[0-9.] %*s %*s %17[a-fa-f0-9:] %*s %*s", ip, mac) == 2)) {
		if (strcmp(mac, req_mac) == 0) {
			if(reply) {
				free(reply);
				reply = NULL;
			}
			reply = safe_strdup(ip);
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
	iptables_fw_set_authservers(NULL);
}

void
fw_clear_pan_domains_trusted(void)
{
	debug(LOG_DEBUG, "Clear pan trust domains list");
	iptables_fw_clear_ipset_domains_trusted();
}

void
fw_set_pan_domains_trusted(void)
{
	debug(LOG_DEBUG, "Set pan trust domains list");
	iptables_fw_set_ipset_domains_trusted();
}

void
fw_refresh_inner_domains_trusted(void)
{
	debug(LOG_INFO, "Refresh inner trust domains list");
	iptables_fw_refresh_inner_domains_trusted();
}

void
fw_clear_inner_domains_trusted(void)
{
	debug(LOG_INFO, "Clear inner trust domains list");
	iptables_fw_clear_inner_domains_trusted();
}

/**
 * @brief set inner trusted domains
 * 
 */ 
void
fw_set_inner_domains_trusted(void)
{
	debug(LOG_INFO, "Setting inner trust domains list");
	iptables_fw_set_inner_domains_trusted();
}


void
fw_refresh_user_domains_trusted(void)
{
	debug(LOG_INFO, "Refresh user trust domains list");
	iptables_fw_refresh_user_domains_trusted();
}

void
fw_clear_user_domains_trusted(void)
{
	debug(LOG_INFO, "Clear user trust domains list");
	iptables_fw_clear_user_domains_trusted();
}

void
fw_set_user_domains_trusted(void)
{
	debug(LOG_INFO, "Setting user trust domains list");
	iptables_fw_set_user_domains_trusted();
}

void
fw_set_roam_mac(const char *mac)
{
	debug(LOG_INFO, "Set roam mac");
	iptables_fw_set_roam_mac(mac);
}

void
fw_clear_roam_maclist(void)
{
	debug(LOG_INFO, "Clear roam maclist");
	iptables_fw_clear_roam_maclist();
}

void
fw_set_trusted_maclist()
{
	debug(LOG_INFO, "Set trusted maclist");
	iptables_fw_set_trusted_maclist();
}

void
fw_clear_trusted_maclist()
{
	debug(LOG_INFO, "Clear trusted maclist");
	iptables_fw_clear_trusted_maclist();
}

void
fw_set_trusted_local_maclist()
{
	debug(LOG_INFO, "Set trusted local maclist");
	iptables_fw_set_trusted_local_maclist();
}

void
fw_clear_trusted_local_maclist()
{
	debug(LOG_INFO, "Clear trusted local maclist");
	iptables_fw_clear_trusted_local_maclist();
}


void
fw_set_untrusted_maclist()
{
	debug(LOG_INFO, "Set untrusted maclist");
	iptables_fw_set_untrusted_maclist();
}

void
fw_clear_untrusted_maclist()
{
	debug(LOG_INFO, "Clear untrusted maclist");
	iptables_fw_clear_untrusted_maclist();
}

void
fw_set_mac_temporary(const char *mac, int which)
{
	debug(LOG_INFO, "Set trusted||untrusted mac [%s] temporary", mac);
	iptables_fw_set_mac_temporary(mac, which);
}

void
fw_set_trusted_mac(const char *mac)
{
	debug(LOG_DEBUG, "Clear untrusted maclist");
	iptables_fw_set_trusted_mac(mac);
}

/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog.
 * @return Return code of the fw.destroy script
 */
int
fw_destroy(void)
{
	close_icmp_socket();
	debug(LOG_DEBUG, "Removing Firewall rules");
	return iptables_fw_destroy();
}

/**
 * @brief According to auth server response, treating client's firewall rule
 * 
 */ 
static void
fw_client_operation(int operation, t_client *p1)
{
	switch(operation) {
	case AUTH_DENIED:
	case AUTH_VALIDATION_FAILED:
		fw_deny(p1);
		debug(LOG_DEBUG, "fw_client_operation deny");
		break;
	case AUTH_ALLOWED:
		fw_allow(p1, FW_MARK_KNOWN);
		debug(LOG_DEBUG, "fw_client_operation allow");
		break;
	default:
		break;
	}
}

/**
 * @brief According to auth server response, process client
 * 
 * @param authresponse Response result from auth server
 * @param p1 The client will be process. notice the p1 is duplicate client of connection list
 *           it can't be free here
 *  
 */ 
void
fw_client_process_from_authserver_response(t_authresponse *authresponse, t_client *p1)
{
	s_config *config = config_get_config();
	assert(p1 != NULL);

	LOCK_CLIENT_LIST();
	t_client *tmp_c = client_list_find_by_client_id(p1->id);
	if (!tmp_c) {
		UNLOCK_CLIENT_LIST();
		debug(LOG_NOTICE, "Client was already removed. Skipping auth processing");
		return;	   /* Next client please */
	}

	
	if (config->auth_servers) {
		switch (authresponse->authcode) {
		case AUTH_DENIED:
			debug(LOG_NOTICE, "%s - Denied. Removing client and firewall rules", tmp_c->ip);
			fw_client_operation(authresponse->authcode, tmp_c);
			client_list_delete(tmp_c);
			break;

		case AUTH_VALIDATION_FAILED:
			debug(LOG_NOTICE, "%s - Validation timeout, now denied. Removing client and firewall rules",
				  tmp_c->ip);
			fw_client_operation(authresponse->authcode, tmp_c);
			client_list_delete(tmp_c);
			break;

		case AUTH_ALLOWED:
			if (tmp_c->fw_connection_state != FW_MARK_KNOWN) {
				debug(LOG_INFO, "%s - Access has changed to allowed, refreshing firewall and clearing counters",
					  tmp_c->ip);

				if (tmp_c->fw_connection_state != FW_MARK_PROBATION) {
					tmp_c->counters.incoming_delta =
					 tmp_c->counters.outgoing_delta =
					 tmp_c->counters.incoming =
					 tmp_c->counters.outgoing = 0;
				} else {
					//We don't want to clear counters if the user was in validation, it probably already transmitted data..
					debug(LOG_INFO,
						  "%s - Skipped clearing counters after all, the user was previously in validation",
						  tmp_c->ip);
				}
			}
			break;

		case AUTH_VALIDATION:
			/*
			 * Do nothing, user
			 * is in validation
			 * period
			 */
			debug(LOG_INFO, "%s - User in validation period", tmp_c->ip);
			break;

		case AUTH_ERROR:
			debug(LOG_WARNING, "Error communicating with auth server - leaving %s as-is for now", tmp_c->ip);
			break;

		default:
			debug(LOG_ERR, "I do not know about authentication code %d", authresponse->authcode);
			break;
		}
	}

	UNLOCK_CLIENT_LIST();
}

/**
 * @brief send clients counter info to auth server by json  
 * 
 * {"gw_id":"gw_id", clients:[
 * {"id":id,"ip":"ipaddress","mac":"macaddress","token":"tokenvalue","channel_path":channelPath,
 * "name":"clientname","incoming":incoming,"outgoing":outgoing,"first_login":first_login,
 * "is_online":is_online,"wired":is_wired_device}, ....]}
 * 
 */ 
void
ev_fw_sync_with_authserver_v2(struct wd_request_context *context)
{
	t_client *p1 = NULL, *p2 = NULL, *worklist = NULL;
	s_config *config = config_get_config();

	if (-1 == iptables_fw_counters_update()) {
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();
	g_online_clients = client_list_dup(&worklist);
	UNLOCK_CLIENT_LIST();

	json_object *clients_info = json_object_new_object();
	json_object_object_add(clients_info, "gw_id", json_object_new_string(config->gw_id));
	json_object *client_array = json_object_new_array();
	for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
		json_object *clt = json_object_new_object();
		p2 = p1->next;	
		int online_time = time(0) - p1->first_login;
		/* Ping the client, if he responds it'll keep activity on the link.
		 * However, if the firewall blocks it, it will not help.  The suggested
		 * way to deal witht his is to keep the DHCP lease time extremely
		 * short:  Shorter than config->checkinterval * config->clienttimeout */
		icmp_ping(p1->ip);

		json_object_object_add(clt, "id", json_object_new_int(p1->id));
		json_object_object_add(clt, "ip", json_object_new_string(p1->ip));
		json_object_object_add(clt, "mac", json_object_new_string(p1->mac));
		json_object_object_add(clt, "token", json_object_new_string(p1->token));
		json_object_object_add(clt, "name", json_object_new_string(p1->name?p1->name:"null"));
		json_object_object_add(clt, "incoming", json_object_new_int(p1->counters.incoming));
		json_object_object_add(clt, "outgoing", json_object_new_int(p1->counters.outgoing));
		json_object_object_add(clt, "first_login", json_object_new_int(p1->first_login));
		json_object_object_add(clt, "online_time", json_object_new_int(online_time));
		json_object_object_add(clt, "is_online", json_object_new_boolean(p1->is_online));
		json_object_object_add(clt, "wired", json_object_new_boolean(p1->wired));
		json_object_array_add(client_array, clt);

		client_free_node(p1);
	}
	json_object_object_add(clients_info, "clients", client_array);

	/* Update the counters on the remote server only if we have an auth server */
	if (config->auth_servers != NULL) {
		char *uri = get_auth_counter_v2_uri();

		struct evhttp_connection *evcon = NULL;
		struct evhttp_request *req = NULL;
		if (!wd_make_request(context, &evcon, &req, process_auth_server_counter_v2)) {
			const char *param = json_object_to_json_string(clients_info);
			assert(param != NULL);
			char len[20] = {0};
			snprintf(len, 20, "%lu", strlen(param));
			evhttp_remove_header(evhttp_request_get_output_headers(req), "Content-Type");
			evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
        	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", len);
			evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", param);
			evhttp_make_request(evcon, req, EVHTTP_REQ_POST, uri);
		}	
		free(uri);
	}
	json_object_put(clients_info);
}

/**
 * @brief refreshes the entire client list's traffic counter, 
 *        and update's the central servers traffic counters 
 * 
 * @param context The context for request auth server
 * 
 */ 
void
ev_fw_sync_with_authserver(struct wd_request_context *context)
{
	t_client *p1 = NULL, *p2 = NULL, *worklist = NULL;
	s_config *config = config_get_config();

	if (-1 == iptables_fw_counters_update()) {
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();
	g_online_clients = client_list_dup(&worklist);
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
			char *uri = get_auth_uri(REQUEST_TYPE_COUNTERS, ONLINE_CLIENT, p1);
			if (!uri) {
				debug(LOG_ERR, "Could not get auth uri!");
				client_free_node(p1);
				continue;
			} 

			debug(LOG_DEBUG, "client's counter uri [%s]", uri);

			struct evhttp_connection *evcon = NULL;
			struct evhttp_request *req = NULL;
			context->data = p1; // free p1 in process_auth_server_counter
			if (!wd_make_request(context, &evcon, &req, process_auth_server_counter))
				evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
			else
				client_free_node(p1);
			free(uri);
		}
	}
}

