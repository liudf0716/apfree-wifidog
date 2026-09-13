
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "firewall.h"
#include "client_list.h"
#include "wd_util.h"
#include "auth.h"
#include "long_conn.h"

void
logout_client(t_client *client)
{
	char mac[32] = {0};
	char ip[64] = {0};
	char gw_id[128] = {0};
	unsigned long long id;

	if (!client) {
		return;
	}

	id = client->id;
	if (client->mac) {
		snprintf(mac, sizeof(mac), "%s", client->mac);
	}
	if (client->ip) {
		snprintf(ip, sizeof(ip), "%s", client->ip);
	}
	if (client->gw_setting && client->gw_setting->gw_id) {
		snprintf(gw_id, sizeof(gw_id), "%s", client->gw_setting->gw_id);
	}

	LOCK_CLIENT_LIST();
	t_client *live = client_list_find_by_client_id(id);
	if (!live && mac[0]) {
		live = client_list_find_by_mac(mac);
	}
	if (live) {
		fw_deny(live);
		debug(LOG_INFO, "Client %s logged out locally", live->ip ? live->ip : mac);
		client_list_delete(live);
	}
	UNLOCK_CLIENT_LIST();

	long_conn_publish_logout(gw_id[0] ? gw_id : NULL, mac[0] ? mac : NULL, ip[0] ? ip : NULL);
}
