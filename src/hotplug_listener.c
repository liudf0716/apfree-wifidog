// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include <linux/rtnetlink.h>
#include <net/if.h>
#include "debug.h"
#include "wd_util.h"
#include "conf.h"
#include "mqtt_thread.h"
#include "ws_thread.h"
#include "hotplug_listener.h"

#define HOTPLUG_EVENT_BUF_SIZE 4096

static const char *
resolve_effective_interface(const char *interface, const char *device)
{
	if (interface && (strcmp(interface, "wan") == 0 || strcmp(interface, "wwan") == 0)) {
		return interface;
	}

	if (device && device[0] != '\0') {
		t_gateway_setting *gw = get_gateway_setting_by_ifname(device);
		if (gw && gw->gw_channel && (strcmp(gw->gw_channel, "wan") == 0 || strcmp(gw->gw_channel, "wwan") == 0)) {
			return gw->gw_channel;
		}

		if (strncmp(device, "wan", 3) == 0) {
			return "wan";
		}
		if (strncmp(device, "wwan", 4) == 0) {
			return "wwan";
		}
	}

	return NULL;
}

static int
hotplug_emit_event(const char *ifname, const char *action)
{
	char event_json[256];
	const char *effective_interface = resolve_effective_interface(NULL, ifname);

	if (!ifname || ifname[0] == '\0' || !action || action[0] == '\0') {
		return 0;
	}

	if (!effective_interface) {
		return 0;
	}

	snprintf(event_json, sizeof(event_json),
		"{\"interface\":\"%s\",\"action\":\"%s\",\"device\":\"%s\"}",
		effective_interface, action, ifname);

	hotplug_handle_event(NULL, event_json);
	return 1;
}

static int
handle_rtnl_link_msg(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh);
	int len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	char ifname[IFNAMSIZ] = {0};

	for (struct rtattr *attr = IFLA_RTA(ifi); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		if (attr->rta_type == IFLA_IFNAME) {
			size_t rta_len = RTA_PAYLOAD(attr);
			if (rta_len > 0) {
				if (rta_len >= sizeof(ifname))
					rta_len = sizeof(ifname) - 1;
				memcpy(ifname, RTA_DATA(attr), rta_len);
				ifname[rta_len] = '\0';
			}
			break;
		}
	}

	if (ifname[0] == '\0') {
		if_indextoname(ifi->ifi_index, ifname);
	}

	if (ifname[0] == '\0') {
		return 0;
	}

	const char *action = NULL;
	if (nh->nlmsg_type == RTM_DELLINK) {
		action = "ifdown";
	} else {
#ifdef IFF_LOWER_UP
		action = ((ifi->ifi_flags & IFF_RUNNING) || (ifi->ifi_flags & IFF_LOWER_UP)) ? "ifup" : "ifdown";
#else
		action = (ifi->ifi_flags & IFF_RUNNING) ? "ifup" : "ifdown";
#endif
	}

	return hotplug_emit_event(ifname, action);
}

static int
handle_rtnl_addr_msg(struct nlmsghdr *nh)
{
	struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nh);
	char ifname[IFNAMSIZ] = {0};

	if (!if_indextoname(ifa->ifa_index, ifname)) {
		return 0;
	}

	const char *action = (nh->nlmsg_type == RTM_NEWADDR) ? "ifup" : "ifdown";
	return hotplug_emit_event(ifname, action);
}

static int
handle_rtnl_route_msg(struct nlmsghdr *nh)
{
	struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
	int len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rtm));
	int oif = 0;

	if (rtm->rtm_dst_len != 0 || rtm->rtm_table != RT_TABLE_MAIN) {
		return 0;
	}

	for (struct rtattr *attr = RTM_RTA(rtm); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		if (attr->rta_type == RTA_OIF) {
			oif = *(int *)RTA_DATA(attr);
			break;
		}
	}

	if (oif <= 0) {
		return 0;
	}

	char ifname[IFNAMSIZ] = {0};
	if (!if_indextoname(oif, ifname)) {
		return 0;
	}

	const char *action = (nh->nlmsg_type == RTM_NEWROUTE) ? "ifup" : "ifdown";
	return hotplug_emit_event(ifname, action);
}

static int
run_rtnetlink_listener(void)
{
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		debug(LOG_WARNING, "Failed to create netlink socket: %s", strerror(errno));
		return -1;
	}

	struct sockaddr_nl local;
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

	if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
		debug(LOG_WARNING, "Failed to bind netlink socket: %s", strerror(errno));
		close(sock);
		return -1;
	}

	debug(LOG_INFO, "Hotplug listener started via rtnetlink");

	char buf[HOTPLUG_EVENT_BUF_SIZE];
	while (1) {
		ssize_t n = recv(sock, buf, sizeof(buf), 0);
		if (n < 0) {
			if (errno == EINTR) {
				continue;
			}
			debug(LOG_WARNING, "Netlink recv failed: %s", strerror(errno));
			close(sock);
			return -1;
		}

		for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (unsigned int)n); nh = NLMSG_NEXT(nh, n)) {
			if (nh->nlmsg_type == NLMSG_DONE) {
				break;
			}
			if (nh->nlmsg_type == NLMSG_ERROR) {
				continue;
			}

			switch (nh->nlmsg_type) {
			case RTM_NEWLINK:
			case RTM_DELLINK:
				handle_rtnl_link_msg(nh);
				break;
			case RTM_NEWADDR:
			case RTM_DELADDR:
				handle_rtnl_addr_msg(nh);
				break;
			case RTM_NEWROUTE:
			case RTM_DELROUTE:
				handle_rtnl_route_msg(nh);
				break;
			default:
				break;
			}
		}
	}
}

/* ubus fallback removed: use kernel rtnetlink listener only. */

static bool
parse_ip_address(const char *ip_str, unsigned int *parts)
{
	if (!ip_str || !parts) return false;
	int consumed = 0;
	unsigned int a, b, c, d;
	int cnt = sscanf(ip_str, "%u.%u.%u.%u%n", &a, &b, &c, &d, &consumed);
	if (cnt != 4) return false;
	if (ip_str[consumed] != '\0') return false;
	if (a > 255 || b > 255 || c > 255 || d > 255) return false;
	parts[0] = a; parts[1] = b; parts[2] = c; parts[3] = d;
	return true;
}

static bool
check_network_conflict(const unsigned int *net1, const unsigned int *net2)
{
	if (!net1 || !net2) return false;
	for (int i = 0; i < 4; i++) {
		if (net1[i] != net2[i]) return false;
	}
	return true;
}

static bool
get_network_config(char *ip, size_t ip_size, char *mask, size_t mask_size)
{
	char cmd[256];
	FILE *fp;
	bool success = true;

	snprintf(cmd, sizeof(cmd), "uci -q get network.lan.ipaddr");
	if (!(fp = popen(cmd, "r")) || !fgets(ip, ip_size, fp)) {
		debug(LOG_ERR, "Failed to get LAN IP address");
		success = false;
	}
	if (fp) pclose(fp);
	if (success) ip[strcspn(ip, "\n")] = 0;

	if (success) {
		snprintf(cmd, sizeof(cmd), "uci -q get network.lan.netmask");
		if (!(fp = popen(cmd, "r")) || !fgets(mask, mask_size, fp)) {
			debug(LOG_ERR, "Failed to get LAN netmask");
			success = false;
		}
		if (fp) pclose(fp);
		if (success) mask[strcspn(mask, "\n")] = 0;
	}

	return success;
}

void
hotplug_handle_event(struct bufferevent *fd, const char *event_json_data)
{
	json_object *root = NULL;
	json_object *event_obj = NULL;
	bool success = true;
	char *wan_ip = NULL;
	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Hotplugin events are only supported on OpenWrt platform");
		if (fd) {
			bufferevent_write(fd, "Not Support", strlen("Not Support"));
		}
		return;
	}

	if (!event_json_data) {
		debug(LOG_ERR, "Null event json data received");
		success = false;
		goto cleanup;
	}

	root = json_tokener_parse(event_json_data);
	if (!root || json_object_get_type(root) != json_type_object) {
		debug(LOG_ERR, "Failed to parse event json data: %s", event_json_data ? event_json_data : "(null)");
		success = false;
		goto cleanup;
	}

	json_object *nested = NULL;
	if (json_object_object_get_ex(root, "network.interface", &nested)
		&& nested
		&& json_object_get_type(nested) == json_type_object) {
		event_obj = nested;
	} else {
		event_obj = root;
	}

	json_object *interface_jo = NULL, *action_jo = NULL, *device_jo = NULL;
	if (!json_object_object_get_ex(event_obj, "interface", &interface_jo) ||
		!json_object_object_get_ex(event_obj, "action", &action_jo)) {
		debug(LOG_ERR, "Missing required fields in event json");
		success = false;
		goto cleanup;
	}
	json_object_object_get_ex(event_obj, "device", &device_jo);

	const char *interface = json_object_get_string(interface_jo);
	const char *action = json_object_get_string(action_jo);
	const char *device = device_jo ? json_object_get_string(device_jo) : NULL;
	const char *effective_interface = resolve_effective_interface(interface, device);
	if (!action) {
		debug(LOG_ERR, "Event action is missing or not a string");
		success = false;
		goto cleanup;
	}

	if (!effective_interface
		|| (strcmp(action, "ifup") != 0 && strcmp(action, "ifdown") != 0)) {
		debug(LOG_DEBUG, "Ignoring event for interface %s device %s action %s",
			interface ? interface : "-",
			device ? device : "-",
			action ? action : "-");
		goto cleanup;
	}

	if (get_ws_server()) {
		ws_request_reconnect();
		debug(LOG_INFO, "Triggered WS reconnect for hotplugin event: interface=%s device=%s action=%s",
			effective_interface,
			device ? device : "-",
			action);
	} else if (get_mqtt_server()) {
		mqtt_request_reconnect();
		debug(LOG_INFO, "Triggered MQTT reconnect for hotplugin event: interface=%s device=%s action=%s",
			effective_interface,
			device ? device : "-",
			action);
	} else {
		debug(LOG_WARNING, "No WS/MQTT transport configured for hotplugin reconnect: interface=%s device=%s action=%s",
			effective_interface,
			device ? device : "-",
			action);
	}

	if (strcmp(action, "ifdown") == 0) {
		goto cleanup;
	}

	if (!device || device[0] == '\0') {
		debug(LOG_WARNING, "Hotplugin ifup event has no device field, skip LAN conflict handling");
		goto cleanup;
	}

	wan_ip = get_iface_ip(device);
	char lan_ip[16] = {0}, lan_mask[16] = {0};
	if (!wan_ip || !get_network_config(lan_ip, sizeof(lan_ip), lan_mask, sizeof(lan_mask))) {
		debug(LOG_ERR, "Failed to get network configuration");
		success = false;
		goto cleanup;
	}

	unsigned int wwan_ip_parts[4], lan_ip_parts[4], mask_parts[4];
	unsigned int wwan_network[4], lan_network[4];

	if (!parse_ip_address(wan_ip, wwan_ip_parts) ||
		!parse_ip_address(lan_ip, lan_ip_parts) ||
		!parse_ip_address(lan_mask, mask_parts)) {
		debug(LOG_ERR, "Failed to parse IP addresses");
		success = false;
		goto cleanup;
	}

	for (int i = 0; i < 4; i++) {
		wwan_network[i] = wwan_ip_parts[i] & mask_parts[i];
		lan_network[i] = lan_ip_parts[i] & mask_parts[i];
	}

	if (check_network_conflict(wwan_network, lan_network)) {
		debug(LOG_NOTICE, "Network conflict detected, adjusting LAN IP");

		lan_ip_parts[2] = (lan_ip_parts[2] + 1) % 256;
		if (lan_ip_parts[2] == 0) {
			lan_ip_parts[1] = (lan_ip_parts[1] + 1) % 256;
		}

		char cmd[256], new_ip[16];
		snprintf(new_ip, sizeof(new_ip), "%u.%u.%u.%u",
				lan_ip_parts[0], lan_ip_parts[1],
				lan_ip_parts[2], lan_ip_parts[3]);

		snprintf(cmd, sizeof(cmd), "uci set network.lan.ipaddr='%s' && uci commit network && reboot",
				new_ip);

		if (system(cmd) != 0) {
			debug(LOG_ERR, "Failed to update network configuration");
			success = false;
			goto cleanup;
		}

		debug(LOG_NOTICE, "Changed LAN IP to %s", new_ip);
	}

cleanup:
	if (root) json_object_put(root);
	if (wan_ip) free(wan_ip);
	if (fd) {
		bufferevent_write(fd, success ? "Yes" : "No", success ? 3 : 2);
	}
}

void
thread_hotplug_listener(void *arg)
{
	(void)arg;

	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Hotplug listener disabled: not running on OpenWrt");
		return;
	}

	while (1) {
		if (run_rtnetlink_listener() == 0) {
			continue;
		}

		debug(LOG_WARNING, "rtnetlink listener unavailable, retrying in 1 second");
		sleep(1);
	}
}
