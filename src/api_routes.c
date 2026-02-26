// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"

/**
 * @brief Unified API routing table
 *
 * This table maps operation/message type names to their handler functions.
 * Used by both MQTT and WebSocket protocols.
 *
 * Note: Some operations have aliases (e.g., "connect" and "heartbeat" both map to the same handler)
 */
static const api_route_entry_t api_routes[] = {
	// System info & status
	{"heartbeat",                   handle_get_sys_info_request},
	{"connect",                     handle_get_sys_info_request},
	{"bootstrap",                   handle_get_sys_info_request},
    {"get_sys_info",                handle_get_sys_info_request},
    {"get_status",                  handle_get_aw_status_request},

	// Authentication & client management
	{"auth",                        handle_auth_request},
	{"kickoff",                     handle_kickoff_request},
	{"tmp_pass",                    handle_tmp_pass_request},
	{"get_client_info",             handle_get_client_info_request},
	{"get_clients",                 handle_get_clients_request},
    {"shell",                       handle_shell_request},

	// Firmware management
	{"get_firmware_info",           handle_get_firmware_info_request},
	{"firmware_upgrade",            handle_firmware_upgrade_request},
	{"ota",                         handle_firmware_upgrade_request},

	// Device configuration
    {"update_device_info",          handle_update_device_info_request},
    {"get_device_info",             handle_get_device_info_request},
	{"set_auth_serv",               handle_set_auth_server_request},
    {"get_auth_serv",               handle_get_auth_server_request},
    {"reboot_device",               handle_reboot_device_request},

	// WiFi management
	{"get_wifi_info",               handle_get_wifi_info_request},
    {"set_wifi_info",               handle_set_wifi_info_request},
    {"scan_wifi",                   handle_scan_wifi_request},
    {"set_wifi_relay",              handle_set_wifi_relay_request},
    {"delete_wifi_relay",           handle_delete_wifi_relay_request},
    {"unset_wifi_relay",            handle_delete_wifi_relay_request},

    // VPN management
    {"get_ipsec_vpn",               handle_get_ipsec_vpn_request},
    {"set_ipsec_vpn",               handle_set_ipsec_vpn_request},
    {"get_ipsec_vpn_status",        handle_get_ipsec_vpn_status_request},
    {"get_wireguard_vpn",           handle_get_wireguard_vpn_request},
    {"set_wireguard_vpn",           handle_set_wireguard_vpn_request},
    {"get_wireguard_vpn_status",    handle_get_wireguard_vpn_status_request},

    // Flow control / BPF management (aw-bpfctl wrapper)
    {"bpf_add",                     handle_bpf_add_request},
    {"bpf_del",                     handle_bpf_del_request},
    {"bpf_flush",                   handle_bpf_flush_request},
    {"bpf_json",                    handle_bpf_json_request},
    {"bpf_update",                  handle_bpf_update_request},
    {"bpf_update_all",              handle_bpf_update_all_request},

    // Trusted domains
    // Note: Use `sync_trusted_domain` as the canonical operation name.
    {"sync_trusted_domain",         handle_sync_trusted_domain_request},
	{"get_trusted_domains",         handle_get_trusted_domains_request},
	{"sync_trusted_wildcard_domains", handle_sync_trusted_wildcard_domains_request},
    {"get_trusted_wildcard_domains",  handle_get_trusted_wildcard_domains_request},
    // Trusted MACs (added)
    {"sync_trusted_mac",            handle_sync_trusted_mac_request},
    {"get_trusted_mac",             handle_get_trusted_mac_request},

	// End marker
	{NULL, NULL}
};

const api_route_entry_t*
api_get_routes(void)
{
	return api_routes;
}
