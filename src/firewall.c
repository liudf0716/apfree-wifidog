// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "util.h"
#include "debug.h"
#include "conf.h"
#include "ping_thread.h"
#include "firewall.h"
#include "auth.h"
#include "centralserver.h"
#include "client_list.h"
#include "client_snapshot.h"
#include "commandline.h"
#include "wd_util.h"
#include "wd_client.h"
#ifdef AW_FW3
	#include "fw_iptables.h"
#elif AW_VPP
	#include "fw_vpp.h"
#else
	#include "fw_nft.h"
#endif

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
	int result = 0;
	int old_state = client->fw_connection_state;

	/* Deny after if needed. */
	if (old_state != FW_MARK_NONE) {
		debug(LOG_DEBUG, "Clearing previous fw_connection_state %d", old_state);
		_fw_deny_raw(client->ip, client->mac, old_state);
	}

	debug(LOG_INFO, "Allowing %s %s %s with fw_connection_state %d", 
		client->ip?client->ip:"N/A", client->ip6?client->ip6:"N/A", client->mac, new_fw_connection_state);

	client->fw_connection_state = new_fw_connection_state;

	/* Grant first */
#ifdef AW_FW3
	result = iptables_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);
#elif AW_FW4
	if (client->ip6) {
		result = nft_fw_access(FW_ACCESS_ALLOW, client->ip6, client->mac, new_fw_connection_state);
	} 
	 
	if (client->ip) {
		result = nft_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);
	}
#else
	result = vpp_fw_access(FW_ACCESS_ALLOW, client->ip, client->mac, new_fw_connection_state);
#endif

	return result;
}

int
fw_allow_ip_mac(const char *ip, const char *mac, int fw_connection_state)
{
	int result = 0;
#ifdef AW_FW3
	result = iptables_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
#elif AW_FW4
     result = nft_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
#elif AW_VPP
    result = vpp_fw_access(FW_ACCESS_ALLOW, ip, mac, fw_connection_state);
 #endif
	return result;
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
	debug(LOG_INFO, "Denying %s %s %s with fw_connection_state %d",
		client->ip?client->ip:"N/A", client->ip6?client->ip6:"N/A", client->mac, client->fw_connection_state);

	client->fw_connection_state = FW_MARK_NONE; /* Clear */
	int nret = 0;
	if (client->ip6) {
		nret = _fw_deny_raw(client->ip6, client->mac, fw_connection_state);
		conntrack_flush(client->ip6);
	}

	if (client->ip) {
		nret = _fw_deny_raw(client->ip, client->mac, fw_connection_state);
		conntrack_flush(client->ip);
	}
	return nret;
}

int
fw_deny_ip_mac(const char *ip, const char *mac, int fw_connection_state)
{
	int nret;
	nret = _fw_deny_raw(ip, mac, fw_connection_state);
	conntrack_flush(ip);
	return nret;
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
#ifdef AW_FW3
	return iptables_fw_access(FW_ACCESS_DENY, ip, mac, mark);
#elif AW_FW4
	return nft_fw_access(FW_ACCESS_DENY, ip, mac, mark);
#else
	return vpp_fw_access(FW_ACCESS_DENY, ip, mac, mark);
#endif
}

/** Passthrough for clients when auth server is down */
int
fw_set_authdown(void)
{
	debug(LOG_DEBUG, "Marking auth server down");
#ifdef AW_FW3
	return iptables_fw_auth_unreachable(FW_MARK_AUTH_IS_DOWN);
#elif AW_FW4
	return nft_fw_auth_unreachable(FW_MARK_AUTH_IS_DOWN);
#else
	return 0;
#endif
}

/** Remove passthrough for clients when auth server is up */
int
fw_set_authup(void)
{
	debug(LOG_DEBUG, "Marking auth server up again");
#ifdef AW_FW3
	return iptables_fw_auth_reachable();
#elif AW_FW4
	return nft_fw_auth_reachable();
#else
	return 0;
#endif
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
	if (is_valid_ip(req_ip) == 0) {
		return NULL;
	}

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
#ifdef AW_VPP
	return 1;
#endif

	int result = 0;
	if (!init_icmp_socket()) {
		return 0;
	}

	debug(LOG_INFO, "Initializing Firewall");
#ifdef AW_FW3
	result = iptables_fw_init();
#elif AW_FW4
	result = nft_fw_init();
#endif

	return result;
}

int
fw_is_ready(void)
{
#ifdef AW_FW4
    return nft_check_core_rules();
#else
    return 1;
#endif
}

int
fw_reconcile(void)
{
    if (fw_is_ready()) return 1;

    debug(LOG_INFO, "Firewall rules missing, reconciling...");

    LOCK_CLIENT_LIST();

	fw_destroy();
	fw_init();

#ifdef AW_FW4
    /* 立即从内存恢复在线用户和信任列表，这是最实时的 */
    nft_fw_reload_client();
    nft_fw_reload_trusted_maclist();
#endif

    // Call snapshot load if implemented
    if (!is_portal_auth_disabled() && !is_bypass_mode()) {
        __client_snapshot_load();
    } else {
        debug(LOG_DEBUG, "Portal auth disabled or bypass mode, skip snapshot load");
    }

    UNLOCK_CLIENT_LIST();

    return 1;
}

void
thread_resilience(void *arg)
{
    if (is_portal_auth_disabled() || is_bypass_mode()) {
        debug(LOG_INFO, "Portal auth disabled or bypass mode, skip resilience thread");
        return;
    }

    debug(LOG_INFO, "Resilience thread started");
    
    int check_interval = 3; // Check firewall every 3 seconds
    int snapshot_interval = 60; // Save snapshot every 60 seconds
    int last_snapshot = 0;
    
    while (1) {
        sleep(check_interval);
        
        if (!fw_is_ready()) {
            debug(LOG_WARNING, "Firewall rules out of sync! Reconciling...");
            fw_reconcile();
        }
        
        last_snapshot += check_interval;
        if (last_snapshot >= snapshot_interval) {
            client_snapshot_save();
            last_snapshot = 0;
        }
    }
}

/** Remove all auth server firewall whitelist rules
 */
void
fw_clear_authservers(void)
{
	debug(LOG_DEBUG, "Clearing the authservers list");
#ifdef AW_FW3
	iptables_fw_clear_authservers();
#elif AW_FW4
	nft_fw_clear_authservers();
#endif
}

/** Add the necessary firewall rules to whitelist the authservers
 */
void
fw_set_authservers(void)
{
	debug(LOG_DEBUG, "Setting the authservers list");
#ifdef AW_FW3
	iptables_fw_set_authservers(NULL);
#elif AW_FW4
	nft_fw_set_authservers();
#endif
}

void
fw_clear_wildcard_domains_trusted(void)
{
	debug(LOG_DEBUG, "Clear wildcard trust domains list");
#ifdef AW_FW3
	iptables_fw_clear_ipset_domains_trusted();
#elif AW_FW4
	nft_fw_clear_wildcard_domains_trusted();
#endif
}

void
fw_set_wildcard_domains_trusted(void)
{
	debug(LOG_DEBUG, "Set wildcard trust domains list");
#ifdef AW_FW3
	iptables_fw_set_ipset_domains_trusted();
#elif AW_FW4
	nft_fw_set_wildcard_domains_trusted();
#endif
}

void
fw_refresh_inner_domains_trusted(void)
{
	debug(LOG_DEBUG, "Refresh inner trust domains list");
#ifdef AW_FW3
	iptables_fw_refresh_inner_domains_trusted();
#elif AW_FW4
	nft_fw_refresh_inner_domains_trusted();
#endif
}

void
fw_clear_inner_domains_trusted(void)
{
	debug(LOG_DEBUG, "Clear inner trust domains list");
#ifdef AW_FW3
	iptables_fw_clear_inner_domains_trusted();
#elif AW_FW4
	nft_fw_clear_inner_domains_trusted();
#endif
}

/**
 * @brief set inner trusted domains
 * 
 */ 
void
fw_set_inner_domains_trusted(void)
{
	debug(LOG_DEBUG, "Setting inner trust domains list");
#ifdef AW_FW3
	iptables_fw_set_inner_domains_trusted();
#elif AW_FW4
	nft_fw_set_inner_domains_trusted();
#endif
}


void
fw_refresh_user_domains_trusted(void)
{
	debug(LOG_DEBUG, "Refresh user trust domains list");
#ifdef AW_FW3
	iptables_fw_refresh_user_domains_trusted();
#elif AW_FW4
	nft_fw_refresh_user_domains_trusted();
#endif
}

void
fw_clear_user_domains_trusted(void)
{
	debug(LOG_DEBUG, "Clear user trust domains list");
#ifdef AW_FW3
	iptables_fw_clear_user_domains_trusted();
#elif AW_FW4
	nft_fw_clear_user_domains_trusted();
#endif
}

void
fw_set_user_domains_trusted(void)
{
	debug(LOG_DEBUG, "Setting user trust domains list");
#ifdef AW_FW3
	iptables_fw_set_user_domains_trusted();
#elif AW_FW4
	nft_fw_set_user_domains_trusted();
#endif
}

void
fw_set_roam_mac(const char *mac)
{
	debug(LOG_DEBUG, "Set roam mac");
#ifdef AW_FW3
	iptables_fw_set_roam_mac(mac);
#elif AW_FW4
	//nft_fw_set_roam_mac(mac);
#endif
}

void
fw_clear_roam_maclist(void)
{
	debug(LOG_DEBUG, "Clear roam maclist");
#ifdef AW_FW3
	iptables_fw_clear_roam_maclist();
#elif AW_FW4
	//nft_fw_clear_roam_maclist();
#endif
}

void
fw_set_trusted_maclist()
{
	debug(LOG_DEBUG, "Set trusted maclist");
#ifdef AW_FW3
	iptables_fw_set_trusted_maclist();
#elif AW_FW4
	nft_fw_set_trusted_maclist();
#endif
}

void
fw_clear_trusted_maclist()
{
	debug(LOG_DEBUG, "Clear trusted maclist");
#ifdef AW_FW3
	iptables_fw_clear_trusted_maclist();
#elif AW_FW4
	nft_fw_clear_trusted_maclist();
#endif
}

void
fw_set_trusted_local_maclist()
{
	debug(LOG_DEBUG, "Set trusted local maclist");
#ifdef AW_FW3
	iptables_fw_set_trusted_local_maclist();
#elif AW_FW4
	//nft_fw_set_trusted_local_maclist();
#endif
}

void
fw_clear_trusted_local_maclist()
{
	debug(LOG_DEBUG, "Clear trusted local maclist");
#ifdef AW_FW3
	iptables_fw_clear_trusted_local_maclist();
#elif AW_FW4
	//nft_fw_clear_trusted_local_maclist();
#endif
}


void
fw_set_untrusted_maclist()
{
	debug(LOG_DEBUG, "Set untrusted maclist");
#ifdef AW_FW3
	iptables_fw_set_untrusted_maclist();
#elif AW_FW4
	//nft_fw_set_untrusted_maclist();
#endif
}

void
fw_clear_untrusted_maclist()
{
	debug(LOG_DEBUG, "Clear untrusted maclist");
#ifdef AW_FW3
	iptables_fw_clear_untrusted_maclist();
#elif AW_FW4
	//nft_fw_clear_untrusted_maclist();
#endif
}

void
fw_set_mac_temporary(const char *mac, int which)
{
	debug(LOG_DEBUG, "Set trusted||untrusted mac [%s] temporary", mac);
#ifdef AW_FW3
	iptables_fw_set_mac_temporary(mac, which);
#elif AW_FW4
	nft_fw_set_mac_temporary(mac, which);
#endif
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
#ifdef AW_FW3
	return iptables_fw_destroy();
#elif AW_FW4
	return nft_fw_destroy();
#else
	return 0;
#endif
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
					tmp_c->counters.incoming_bytes =
					tmp_c->counters.outgoing_bytes = 0;
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

static const char *
get_gw_clients_counter(t_gateway_setting *gw_setting, t_client *worklist) 
{
    if (!gw_setting)
        return NULL;

    t_auth_serv *auth_server = get_auth_server();
    if (!auth_server) {
        debug(LOG_ERR, "Could not get auth server");
        return NULL;
    }

    json_object *obj = json_object_new_object();
    if (!obj) {
        debug(LOG_ERR, "Could not create json object");
        return NULL;
    }

    json_object_object_add(obj, "device_id", json_object_new_string(config_get_config()->device_id));
    json_object *gateway_array = json_object_new_array();
    if (!gateway_array) {
        debug(LOG_ERR, "Could not create json array");
        json_object_put(obj);
        return NULL;
    }

    while (gw_setting) {
        json_object *gw_obj = json_object_new_object();
        if (!gw_obj) {
            debug(LOG_ERR, "Could not create gw_obj for gateway %s", gw_setting->gw_id);
            continue;
        }
        json_object_object_add(gw_obj, "gw_id", json_object_new_string(gw_setting->gw_id));
		json_object_object_add(gw_obj, "gw_channel", json_object_new_string(gw_setting->gw_channel));
        json_object *client_array = json_object_new_array();
        if (!client_array) {
            debug(LOG_ERR, "Could not create json array");
            json_object_put(gw_obj);
            json_object_put(obj);
            return NULL;
        }

        t_client *p1 = NULL, *p2 = NULL;
        for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
            p2 = p1->next;
            if (p1->gw_setting && p1->gw_setting != gw_setting) {
				debug(LOG_DEBUG, "client %s client gw_setting %lu not in gateway %s", 
					p1->ip, p1->gw_setting,   gw_setting->gw_id);
				continue;
			}

            json_object *clt = json_object_new_object();
            json_object_object_add(clt, "id", json_object_new_int64(p1->id));
            json_object_object_add(clt, "ip", json_object_new_string(p1->ip));
			json_object_object_add(clt, "ip6", json_object_new_string(p1->ip6 ? p1->ip6 : "N/A"));
            json_object_object_add(clt, "mac", json_object_new_string(p1->mac));
            json_object_object_add(clt, "token", json_object_new_string(p1->token));
            json_object_object_add(clt, "name", json_object_new_string(p1->name ? p1->name : "N/A"));
            json_object_object_add(clt, "incoming_bytes", json_object_new_int64(p1->counters.incoming_bytes));
            json_object_object_add(clt, "outgoing_bytes", json_object_new_int64(p1->counters.outgoing_bytes));
            json_object_object_add(clt, "incoming_rate", json_object_new_int64(p1->counters.incoming_rate));
            json_object_object_add(clt, "outgoing_rate", json_object_new_int64(p1->counters.outgoing_rate));
            json_object_object_add(clt, "incoming_packets", json_object_new_int64(p1->counters.incoming_packets));
            json_object_object_add(clt, "outgoing_packets", json_object_new_int64(p1->counters.outgoing_packets));
            json_object_object_add(clt, "incoming_bytes_v6", json_object_new_int64(p1->counters6.incoming_bytes));
            json_object_object_add(clt, "outgoing_bytes_v6", json_object_new_int64(p1->counters6.outgoing_bytes));
            json_object_object_add(clt, "incoming_rate_v6", json_object_new_int64(p1->counters6.incoming_rate));
            json_object_object_add(clt, "outgoing_rate_v6", json_object_new_int64(p1->counters6.outgoing_rate));
            json_object_object_add(clt, "incoming_packets_v6", json_object_new_int64(p1->counters6.incoming_packets));
            json_object_object_add(clt, "outgoing_packets_v6", json_object_new_int64(p1->counters6.outgoing_packets));
            json_object_object_add(clt, "first_login", json_object_new_int64(p1->first_login));
            json_object_object_add(clt, "is_online", json_object_new_boolean(p1->is_online));
            json_object_object_add(clt, "wired", json_object_new_boolean(p1->wired));
            json_object_array_add(client_array, clt);
        }

        json_object_object_add(gw_obj, "clients", client_array);
        json_object_array_add(gateway_array, gw_obj);
        gw_setting = gw_setting->next;
    }

    json_object_object_add(obj, "gateway", gateway_array);

    const char *json_str = json_object_to_json_string(obj);
    char *result = strdup(json_str);
    json_object_put(obj); // Free the JSON object

    return result;
}

static void
sync_gw_clients_counter(struct wd_request_context *context, t_gateway_setting *gw_setting, t_client *worklist)
{
	t_auth_serv *auth_server = get_auth_server();
	if (!auth_server) {
		debug(LOG_ERR, "Could not get auth server");
		return;
	}

	char *uri = get_auth_counter_v2_uri();
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req = NULL;
	if (!wd_make_request(context, &evcon, &req, process_auth_server_counter_v2)) {
		const char *param = get_gw_clients_counter(gw_setting, worklist);
		assert(param != NULL);
		char len[20] = {0};
		snprintf(len, 20, "%lu", strlen(param));
		evhttp_remove_header(evhttp_request_get_output_headers(req), "Content-Type");
		evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
		evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Length", len);
		evbuffer_add_printf(evhttp_request_get_output_buffer(req), "%s", param);
		evhttp_make_request(evcon, req, EVHTTP_REQ_POST, uri);
		free((void *)param);
	}
	free(uri);
}

/**
 * @brief send clients counter info to auth server by json  
 * 
 */ 
void
ev_fw_sync_with_authserver_v2(struct wd_request_context *context)
{
	t_client *worklist = NULL;
	t_gateway_setting *gw_settings = get_gateway_settings();
	if (!gw_settings) {
		debug(LOG_INFO, "no gateway settings");
		return;
	}
	
	debug(LOG_DEBUG, "Syncing client counters with auth server");
	if (-1 == fw_counters_update())
	{
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();
	g_online_clients = client_list_dup(&worklist);
	UNLOCK_CLIENT_LIST();

	sync_gw_clients_counter(context, gw_settings, worklist);
		
	client_list_destroy(worklist);
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

	debug(LOG_DEBUG, "Syncing client counters with auth server");
	if (-1 == fw_counters_update()) {
		debug(LOG_ERR, "Could not get counters from firewall!");
		return;
	}

	LOCK_CLIENT_LIST();
	g_online_clients = client_list_dup(&worklist);
	UNLOCK_CLIENT_LIST();

	if (!worklist) {
		debug(LOG_DEBUG, "No clients to sync with auth server");
		return;
	}

	for (p1 = p2 = worklist; NULL != p1; p1 = p2) {
		p2 = p1->next;	

		/* Ping the client, if he responds it'll keep activity on the link.
		 * However, if the firewall blocks it, it will not help.  The suggested
		 * way to deal witht his is to keep the DHCP lease time extremely
		 * short:  Shorter than config->checkinterval * config->clienttimeout */
		if (p1->ip) {
			icmp_ping(p1->ip);
		}

		/* Update the counters on the remote server only if we have an auth server */
		if (config->auth_servers != NULL) {
			char *uri = get_auth_uri(REQUEST_TYPE_COUNTERS, ONLINE_CLIENT, p1);
			if (!uri) {
				debug(LOG_ERR, "Could not get auth uri for client %s!", p1->mac); // Added more info to log
				continue;
			} 

			debug(LOG_DEBUG, "client's counter uri [%s]", uri);

			struct evhttp_connection *evcon = NULL;
			struct evhttp_request *req = NULL;

			t_client *client_for_context = client_dup(p1); // Create a second duplicate
			if (!client_for_context) {
				debug(LOG_ERR, "Failed to duplicate client %s for context!", p1->mac);
				free(uri); // Free the allocated URI before continuing
				continue;  // Skip to the next client
			}
			context->data = client_for_context; // Assign the new duplicate to context->data

			// Pass the original context (which now contains client_for_context)
			if (!wd_make_request(context, &evcon, &req, process_auth_server_counter)) {
				evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
			} else {
				// If wd_make_request fails, the context->data (client_for_context) was set
				// but the request wasn't made. It needs to be freed here to prevent a leak,
				// as process_auth_server_counter won't be called.
				debug(LOG_ERR, "wd_make_request failed for client %s. Freeing duplicated client for context.", client_for_context->mac);
				client_free_node(client_for_context);
				context->data = NULL; // Defensive nulling
			}
			free(uri);
		}
	}
	client_list_destroy(worklist);
}

void 
conntrack_flush(const char *ip)
{
#ifdef AW_VPP
#else
	debug(LOG_DEBUG, "Flush conntrack for ip [%s]", ip?ip:"all");
	char cmd[128] = {0};
	if (ip) {
		snprintf(cmd, sizeof(cmd), "conntrack -D -s %s", ip);
	} else {
		snprintf(cmd, sizeof(cmd), "conntrack -F");
	}
	execute(cmd, 0);
#endif
}

void
fw_add_trusted_mac(const char *mac, uint32_t timeout)
{
	debug(LOG_DEBUG, "Set trusted mac [%s] with timeout %d", mac, timeout);
#ifdef AW_FW3
	 iptables_fw_set_trusted_mac(mac);
#elif AW_FW4
	nft_fw_add_trusted_mac(mac, timeout);
#endif
}

void
fw_del_trusted_mac(const char *mac)
{
	debug(LOG_DEBUG, "Del trusted mac [%s]", mac);
#ifdef AW_FW3
	iptables_fw_del_trusted_mac(mac);
#elif AW_FW4
	nft_fw_del_trusted_mac(mac);
#endif
}

void
fw_update_trusted_mac(const char *mac, uint32_t timeout)
{
	debug(LOG_DEBUG, "Update trusted mac [%s] with timeout %d", mac, timeout);
#ifdef AW_FW3
	iptables_fw_update_trusted_mac(mac);
#elif AW_FW4
	nft_fw_update_trusted_mac(mac, timeout);
#endif
}

void
fw_add_anti_nat_permit_device(const char *mac)
{
	debug(LOG_DEBUG, "Add anti nat permit device [%s]", mac);
#ifdef AW_FW3
#elif AW_FW4
	nft_fw_add_anti_nat_permit(mac);
#endif
}

void
fw_del_anti_nat_permit_device(const char *mac)
{
	debug(LOG_DEBUG, "Del anti nat permit device [%s]", mac);
#ifdef AW_FW3
#elif AW_FW4
	nft_fw_del_anti_nat_permit(mac);
#endif
}

int
fw_counters_update()
{
	debug(LOG_DEBUG, "Update firewall counters");
#ifdef AW_FW3
	return iptables_fw_counters_update();
#elif AW_VPP
	return vpp_fw_counters_update();
#else
	return nft_fw_counters_update();
#endif
}