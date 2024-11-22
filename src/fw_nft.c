
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>
#include <libnftnl/object.h>

#include "debug.h"
#include "util.h"
#include "wd_util.h"
#include "firewall.h"
#include "fw_nft.h"
#include "client_list.h"
#include "conf.h"
#include "dns_forward.h"
#include "gateway.h"
#include "safe.h"

#define NFPROTO_INET        1
#define NFT_MSG_GETCHAIN    4

#define NFT_CONF_FILENAME "/etc/fw4_apfree-wifiodg_init.conf"
#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"
#define NFT_WIFIDOGX_CLIENT_LIST "/tmp/nftables_wifidogx_client_list"

static int fw_quiet = 0;
static void nft_statistical_helper(const char *cmd, char **output, uint32_t *output_len);

const char *nft_wifidogx_init_script[] = {
    "add table inet wifidogx",
    "add chain  inet wifidogx prerouting{ type nat hook prerouting priority 0; policy accept; }",
    "add chain  inet wifidogx mangle_prerouting { type filter hook postrouting priority 0; policy accept; }",
    "add set inet fw4 set_wifidogx_auth_servers { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_auth_servers_v6 { type ipv6_addr; }",
    "add set inet fw4 set_wifidogx_gateway { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_gateway_v6 { type ipv6_addr; }",
    "add set inet fw4 set_wifidogx_trust_domains { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_trust_domains_v6 { type ipv6_addr; }",
    "add set inet fw4 set_wifidogx_inner_trust_domains { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_inner_trust_domains_v6 { type ipv6_addr; }",
    "add set inet fw4 set_wifidogx_bypass_clients { type ipv4_addr; flags interval; }",
    "add set inet fw4 set_wifidogx_bypass_clients_v6 { type ipv6_addr; flags interval; }",
    "add set inet fw4 set_wifidogx_trust_clients { type ether_addr; }",
    "add set inet fw4 set_wifidogx_tmp_trust_clients { type ether_addr; flags timeout; timeout 1m; }",
    "add chain inet fw4 dstnat_wifidogx_auth_server",
    "add chain inet fw4 dstnat_wifidogx_wan",
    "add chain inet fw4 dstnat_wifidogx_outgoing",
    "add chain inet fw4 dstnat_wifidogx_trust_domains",
    "add chain inet fw4 dstnat_wifidogx_unknown",
    "add rule inet fw4 dstnat_wifidogx_outgoing ip daddr @set_wifidogx_gateway accept",
    "add rule inet fw4 dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_gateway_v6 accept",
    "add rule inet fw4 dstnat_wifidogx_outgoing jump dstnat_wifidogx_wan",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_trust_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ip6 saddr @set_wifidogx_bypass_clients_v6 accept",
    "add rule inet fw4 dstnat_wifidogx_wan meta mark 0x20000 accept",
    "add rule inet fw4 dstnat_wifidogx_wan meta mark 0x10000 accept",
    "add rule inet fw4 dstnat_wifidogx_wan jump dstnat_wifidogx_unknown",
    "add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_auth_server",
    "add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_trust_domains",
    "add rule inet fw4 dstnat_wifidogx_unknown tcp dport 443 redirect to  8443",
    "add rule inet fw4 dstnat_wifidogx_unknown udp dport 443 drop",
    "add rule inet fw4 dstnat_wifidogx_unknown tcp dport 80 redirect to  2060",
    "add rule inet fw4 dstnat_wifidogx_unknown udp dport 80 drop",
    "add rule inet fw4 dstnat_wifidogx_auth_server ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet fw4 dstnat_wifidogx_auth_server ip6 daddr @set_wifidogx_auth_servers_v6 accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip6 daddr @set_wifidogx_trust_domains_v6 accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip6 daddr @set_wifidogx_inner_trust_domains_v6 accept",
    "add chain inet fw4 forward_wifidogx_auth_servers",
    "add chain inet fw4 forward_wifidogx_wan",
    "add chain inet fw4 forward_wifidogx_trust_domains",
    "add chain inet fw4 forward_wifidogx_unknown",
    "add chain inet fw4 mangle_prerouting_wifidogx_outgoing",
    "add chain inet fw4 mangle_postrouting_wifidogx_incoming",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_auth_servers",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_trust_domains",
    "add rule inet fw4 forward_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet fw4 forward_wifidogx_wan ether saddr @set_wifidogx_trust_clients accept",
    "add rule inet fw4 forward_wifidogx_wan ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet fw4 forward_wifidogx_wan ip6 saddr @set_wifidogx_bypass_clients_v6 accept",
    "add rule inet fw4 forward_wifidogx_wan meta mark 0x10000 accept",
    "add rule inet fw4 forward_wifidogx_wan meta mark 0x20000 accept",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_unknown",
    "add rule inet fw4 forward_wifidogx_unknown jump handle_reject",
    "add rule inet fw4 forward_wifidogx_auth_servers ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet fw4 forward_wifidogx_auth_servers ip6 daddr @set_wifidogx_auth_servers_v6 accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip6 daddr @set_wifidogx_trust_domains_v6 accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip6 daddr @set_wifidogx_inner_trust_domains_v6 accept",
    "insert rule inet fw4 accept_to_wan jump forward_wifidogx_wan",
};

const char *nft_wifidogx_dhcp_pass_script[] = {
    "insert rule inet fw4 forward_wifidogx_unknown udp dport 67 counter accept",
    "insert rule inet fw4 forward_wifidogx_unknown tcp dport 67 counter accept",
};

const char *nft_wifidogx_dns_pass_script[] = {
    "insert rule inet fw4 forward_wifidogx_unknown udp dport 53 counter accept",
    "insert rule inet fw4 forward_wifidogx_unknown tcp dport 53 counter accept",
};

const char *nft_wifidogx_dhcp_redirect_script[] = {
    "add rule inet wifidogx prerouting iifname $interface$ udp dport 67 counter redirect to  15867",
    "add rule inet wifidogx prerouting iifname $interface$ tcp dport 67 counter redirect to  15867",
};

const char *nft_wifidogx_dns_redirect_script[] = {
    "add rule inet wifidogx prerouting iifname $interface$ udp dport 53 counter redirect to  " DNS_FORWARD_PORT_STR,
    "add rule inet wifidogx prerouting iifname $interface$ tcp dport 53 counter redirect to " DNS_FORWARD_PORT_STR,
};

/** Replace occurrences of a substring in a string
 * @param content The source string to perform replacement on
 * @param old_str The substring to be replaced
 * @param new_str The string to replace old_str with
 * @param out Buffer to store the resulting string
 * @param out_len Length of the output buffer
 * 
 * This function safely replaces the first occurrence of old_str with new_str
 * in content and stores the result in out. It handles buffer boundaries to
 * prevent overflow.
 */
static void
replace_str(const char *content, const char *old_str, const char *new_str, 
           char *out, int out_len)
{
    if (!content || !old_str || !new_str || !out || out_len <= 0) {
        return;
    }

    // Find first occurrence of old_str
    const char *p = strstr(content, old_str); 
    if (p == NULL) {
        // No match found - copy original string
        strncpy(out, content, out_len);
        return;
    }

    // Calculate prefix length before replacement point
    size_t prefix_len = p - content;
    if (prefix_len >= (size_t)out_len) {
        return; // Output buffer too small
    }

    // Copy prefix
    memcpy(out, content, prefix_len);
    out[prefix_len] = '\0';

    // Append replacement string
    strncat(out, new_str, out_len - prefix_len - 1);

    // Append remainder of original string after old_str
    size_t remaining = out_len - prefix_len - strlen(new_str) - 1;
    strncat(out, p + strlen(old_str), remaining);
}

/**
 * Generate nftables initialization script for wifidogx
 * 
 * This function generates the nftables configuration script by:
 * 1. Writing base initialization rules
 * 2. Adding DNS and DHCP pass rules
 * 3. Adding DNS redirection rules if DNS forwarding is enabled
 * 
 * The generated script is written to NFT_FILENAME_OUT file.
 */
static void
generate_nft_wifidogx_init_script()
{
    s_config *config = config_get_config();
    t_gateway_setting *gw_settings = get_gateway_settings();
    FILE* output_file = NULL;
    char buf[1024] = {0};

    // Open output file
    output_file = fopen(NFT_FILENAME_OUT, "w");
    if (output_file == NULL) {
        debug(LOG_ERR, "Failed to open %s for writing", NFT_FILENAME_OUT);
        termination_handler(0);
    }

    // Write base initialization rules
    for (size_t i = 0; i < sizeof(nft_wifidogx_init_script) / sizeof(nft_wifidogx_init_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_init_script[i]);
    }

    // Add DNS pass rules
    for (size_t i = 0; i < sizeof(nft_wifidogx_dns_pass_script) / sizeof(nft_wifidogx_dns_pass_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_dns_pass_script[i]);
    }

    // Add DHCP pass rules 
    for (size_t i = 0; i < sizeof(nft_wifidogx_dhcp_pass_script) / sizeof(nft_wifidogx_dhcp_pass_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_dhcp_pass_script[i]);
    }
    
    // Add DNS redirection rules if enabled
    if (config->enable_dns_forward) {
        while (gw_settings) {
            for (size_t i = 0; i < sizeof(nft_wifidogx_dns_redirect_script) / sizeof(nft_wifidogx_dns_redirect_script[0]); i++) {
                const char *rule = nft_wifidogx_dns_redirect_script[i];
                if (strstr(rule, "$interface$")) {
                    // Replace interface placeholder with actual interface
                    replace_str(rule, "$interface$", gw_settings->gw_interface, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                    memset(buf, 0, sizeof(buf));
                } else {
                    fprintf(output_file, "%s\n", rule);
                }
            }
            gw_settings = gw_settings->next;
        }
    }

    fclose(output_file);
}

// the function run_cmd is used to run the nftables command
static int 
run_cmd(char *cmd, ...)
{
#define CMDBUFLEN 1024
    va_list ap;//声明命名参数
    char buf[CMDBUFLEN] = {0};
    va_start(ap, cmd);//va_start宏允许访问命名参数parmN后面的变量参数。
    vsnprintf(buf, CMDBUFLEN, cmd, ap);// 将结果写入buf
    va_end(ap);

    debug(LOG_DEBUG, "EXEC: %s\n", buf);
    
    int nret = execute(buf, 0);
    if (nret != 0) {
        debug(LOG_ERR, "Failed to execute (%d) %s", nret,  buf);
    }
    return nret;
}
/* end of utils function */

// run nft script
static void 
nft_do_init_script_command()
{
	run_cmd("nft -f %s", NFT_FILENAME_OUT);
}

/** @internal
 * 
*/
static int
nftables_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	safe_asprintf(&cmd, "nft %s", fmt_cmd);
	free(fmt_cmd);

	debug(LOG_DEBUG, "Executing command: %s", cmd);

	rc = execute(cmd, fw_quiet);

	if (rc != 0) {
		// If quiet, do not display the error
		if (fw_quiet == 0)
			debug(LOG_ERR, "nft command failed(%d): %s", rc, cmd);
		else if (fw_quiet == 1)
			debug(LOG_DEBUG, "nft command failed(%d): %s", rc, cmd);
	}

	free(cmd);

	return rc;
}

#include <nftables/libnftables.h>

/**
 * @brief Helper function to execute nftables commands using libnftables
 *
 * This helper function uses libnftables to execute commands and capture output
 * 
 * @param cmd The nftables command to execute
 * @param output Pointer to store the command output
 * @param output_len Pointer to store output length
 */
static void 
nft_statistical_helper(const char *cmd, char **output, uint32_t *output_len) 
{
    if (!cmd || !output || !output_len) {
        debug(LOG_ERR, "Invalid parameters");
        return;
    }

    *output = NULL;
    *output_len = 0;

    // Open netlink socket
    struct mnl_socket *nl;
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        debug(LOG_ERR, "mnl_socket_open: %s", strerror(errno));
        return;
    }

    // Bind to netlink
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        debug(LOG_ERR, "mnl_socket_bind: %s", strerror(errno));
        mnl_socket_close(nl);
        return;
    }

    // Create list request message
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nftnl_chain *chain;
    uint32_t seq = time(NULL);

    chain = nftnl_chain_alloc();
    if (!chain) {
        debug(LOG_ERR, "nftnl_chain_alloc failed");
        mnl_socket_close(nl);
        return;
    }

    // Parse chain name from command
    char table[32], chain_name[32];
    if (sscanf(cmd, "list chain inet %s %s", table, chain_name) != 2) {
        debug(LOG_ERR, "Failed to parse command: %s", cmd);
        nftnl_chain_free(chain);
        mnl_socket_close(nl);
        return;
    }

    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, NFPROTO_INET);

    nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETCHAIN, NFPROTO_INET,
                                     NLM_F_DUMP, seq);
    nftnl_chain_nlmsg_build_payload(nlh, chain);

    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        debug(LOG_ERR, "mnl_socket_sendto: %s", strerror(errno));
        nftnl_chain_free(chain);
        mnl_socket_close(nl);
        return;
    }

    // Allocate buffer for output
    struct json_object *json = json_object_new_object();
    struct json_object *rules_array = json_object_new_array();
    json_object_object_add(json, "nftables", rules_array);

    // Receive response 
    int ret;
    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        ret = mnl_cb_run(buf, ret, seq, mnl_socket_get_portid(nl), NULL, NULL);
        if (ret <= 0)
            break;
    }

    // Convert output to JSON string
    const char *json_str = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY);
    if (json_str) {
        *output = strdup(json_str);
        *output_len = strlen(json_str);
    }

    json_object_put(json);
    nftnl_chain_free(chain);
    mnl_socket_close(nl);
}

/**
 * @brief Get outgoing traffic statistics using libnftables
 *
 * Retrieves statistics for outgoing traffic from the 
 * mangle_prerouting_wifidogx_outgoing chain using libnftables API
 *
 * @param[out] outgoing Pointer to store output string
 * @param[out] outgoing_len Length of output
 */
void 
nft_statistical_outgoing(char **outgoing, uint32_t *outgoing_len)
{
    const char *cmd = "list chain inet fw4 mangle_prerouting_wifidogx_outgoing";
    nft_statistical_helper(cmd, outgoing, outgoing_len);
}

/**
 * @brief Get incoming traffic statistics using libnftables
 * 
 * Retrieves statistics for incoming traffic from the
 * mangle_postrouting_wifidogx_incoming chain using libnftables API
 *
 * @param[out] incoming Pointer to store output string  
 * @param[out] incoming_len Length of output
 */
void
nft_statistical_incoming(char **incoming, uint32_t *incoming_len)
{
    const char *cmd = "list chain inet fw4 mangle_postrouting_wifidogx_incoming";
    nft_statistical_helper(cmd, incoming, incoming_len);
}

void
nft_add_gw()
{
    t_gateway_setting *gw_settings = get_gateway_settings();
    if (gw_settings == NULL) {
        debug(LOG_ERR, "gateway settings is NULL");
        return;
    }

    while(gw_settings) {
        if (gw_settings->auth_mode) {
            debug(LOG_DEBUG, "add gateway %s to auth", gw_settings->gw_interface);
            run_cmd("nft add rule inet fw4 dstnat iifname %s jump dstnat_wifidogx_outgoing", gw_settings->gw_interface);
            run_cmd("nft add rule inet fw4 mangle_prerouting iifname %s jump mangle_prerouting_wifidogx_outgoing", gw_settings->gw_interface);
            run_cmd("nft add rule inet fw4 mangle_postrouting oifname %s jump mangle_postrouting_wifidogx_incoming", gw_settings->gw_interface);
            if (gw_settings->gw_address_v4)
                run_cmd("nft add element inet fw4 set_wifidogx_gateway { %s }", gw_settings->gw_address_v4);
            if (gw_settings->gw_address_v6)
                run_cmd("nft add element inet fw4 set_wifidogx_gateway_v6 { %s }", gw_settings->gw_address_v6);
        }
        gw_settings = gw_settings->next;
    }
}

static void
delete_wifidogx_rules(const char *chain_name, const char *rule_name)
{
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "nft -a list chain inet fw4 %s", chain_name);

    FILE *r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, "popen failed");
        return;
    }

    char buf[4096] = {0};
    while (fgets(buf, sizeof(buf), r_fp) != NULL) {
        if (strstr(buf, rule_name)) {
            char *p = strstr(buf, "handle");
            if (p) {
                int handle;
                sscanf(p, "handle %d", &handle);
                run_cmd("nft delete rule inet fw4 %s handle %d", chain_name, handle);
                debug(LOG_DEBUG, "delete chain %s rule hanle %d", chain_name, handle);
            }
        }
    }
}

void
nft_del_gw()
{
    delete_wifidogx_rules("dstnat", "dstnat_wifidogx_outgoing");
    delete_wifidogx_rules("mangle_prerouting", "mangle_prerouting_wifidogx_outgoing");
    delete_wifidogx_rules("mangle_postrouting", "mangle_postrouting_wifidogx_incoming");

    run_cmd("nft flush set inet fw4 set_wifidogx_gateway");
    run_cmd("nft flush set inet fw4 set_wifidogx_gateway_v6");
}

void
nft_reload_gw()
{
    nft_del_gw();
    nft_add_gw();
}


static void
nft_set_ext_interface()
{
    s_config *config = config_get_config();
    if (!config->external_interface) {
        debug(LOG_ERR, "ext_interface is NULL");
        return;
    }

    // get ext_interface's ip address
    char *ip = get_iface_ip(config->external_interface);
    if (ip == NULL) {
        debug(LOG_ERR, "get_iface_ip [%s] failed", config->external_interface);
        return;
    }
    run_cmd("nft add element inet fw4 set_wifidogx_bypass_clients { %s }", ip);
    free(ip);

    ip = get_iface_ip6(config->external_interface);
    if (ip == NULL) {
        debug(LOG_ERR, "get_iface_ip6 [%s] failed", config->external_interface);
        return;
    }
    run_cmd("nft add element inet fw4 set_wifidogx_bypass_clients_v6 { %s }", ip);
    free(ip);
}

/** Initialize the firewall rules
*/
int 
nft_fw_init()
{
	generate_nft_wifidogx_init_script();
	nft_do_init_script_command();
    nft_add_gw();
    nft_set_ext_interface();
    nft_fw_set_authservers();

    return 1;
}

int
nft_fw_destroy(void)
{
	FILE *fp;
    char buffer[128];
    int table_exists = 0;

    // Check if the inet wifidogx table exists
    fp = popen("nft list tables", "r");
    if (fp == NULL) {
		debug(LOG_ERR, "Failed to list tables");
        return -1;
    }

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (strstr(buffer, "inet wifidogx") != NULL) {
            table_exists = 1;
            break;
        }
    }

    pclose(fp);

    // If the table exists, delete it
    if (table_exists) {
        execute("nft delete table inet wifidogx", 0);
    }

    return execute("fw4 restart", 0);
}

static int
check_nft_expr_json_array_object(json_object *jobj, const char *ip, const char *mac)
{
    int arraylen = json_object_array_length(jobj);
    int ip_flag = (ip == NULL) ? 1 : 0;
    int mac_flag = (mac == NULL) ? 1 : 0;

    for (int i = 0; i < arraylen; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj, i);
        json_object *jobj_item_match = NULL;

        if (json_object_object_get_ex(jobj_item, "match", &jobj_item_match)) {
            json_object *jobj_item_match_left = NULL;
            json_object *jobj_item_match_right = NULL;

            if (json_object_object_get_ex(jobj_item_match, "left", &jobj_item_match_left) &&
                json_object_object_get_ex(jobj_item_match, "right", &jobj_item_match_right)) {

                json_object *jobj_item_match_left_payload = NULL;
                if (json_object_object_get_ex(jobj_item_match_left, "payload", &jobj_item_match_left_payload)) {
                    json_object *jobj_item_match_left_payload_protocol = NULL;
                    if (json_object_object_get_ex(jobj_item_match_left_payload, "protocol", &jobj_item_match_left_payload_protocol)) {
                        const char *protocol = json_object_get_string(jobj_item_match_left_payload_protocol);
                        const char *right = json_object_get_string(jobj_item_match_right);

                        if (strcmp(protocol, "ether") == 0 && mac && strcmp(right, mac) == 0) {
                            mac_flag = 1;
                        } else if (strcmp(protocol, "ip") == 0 && ip && strcmp(right, ip) == 0) {
                            ip_flag = 1;
                        }
                    }
                }
            }
        }

        if (ip_flag && mac_flag) {
            return 1;
        }
    }

    return 0;
}

/*
 * delete client from firewall
 */
static void
nft_fw_del_rule_by_ip_and_mac(const char *ip, const char *mac, const char *chain)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "nft -j list chain inet fw4 %s", chain);
    debug(LOG_DEBUG, "cmd: %s", cmd);

    char *buf = NULL;
    uint32_t buf_len = 0;
    nft_statistical_helper(cmd, &buf, &buf_len);
    if (buf == NULL) {
        debug(LOG_ERR, "nft_statistical_helper failed");
        return;
    }

    json_object *jobj = json_tokener_parse(buf);
    if (jobj == NULL) {
        debug(LOG_ERR, "json_tokener_parse failed");
        free(buf);
        return;
    }
    free(buf);

    json_object *jobj_nftables;
    if (!json_object_object_get_ex(jobj, "nftables", &jobj_nftables)) {
        debug(LOG_ERR, "json_object_object_get_ex failed for nftables");
        json_object_put(jobj);
        return;
    }

    int len = json_object_array_length(jobj_nftables);
    for (int i = 0; i < len; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj_nftables, i);
        if (jobj_item == NULL) {
            debug(LOG_ERR, "json_object_array_get_idx failed for index %d", i);
            continue;
        }

        json_object *jobj_rule;
        if (!json_object_object_get_ex(jobj_item, "rule", &jobj_rule)) {
            debug(LOG_ERR, "json_object_object_get_ex failed for rule");
            continue;
        }

        json_object *jobj_rule_expr;
        if (!json_object_object_get_ex(jobj_rule, "expr", &jobj_rule_expr)) {
            debug(LOG_ERR, "json_object_object_get_ex failed for expr");
            continue;
        }

        if (check_nft_expr_json_array_object(jobj_rule_expr, ip, mac)) {
            json_object *jobj_rule_handle;
            if (!json_object_object_get_ex(jobj_rule, "handle", &jobj_rule_handle)) {
                debug(LOG_ERR, "json_object_object_get_ex failed for handle");
                continue;
            }

            const char *handle = json_object_get_string(jobj_rule_handle);
            snprintf(cmd, sizeof(cmd), "nft delete rule inet fw4 %s handle %s", chain, handle);
            run_cmd(cmd);
        }
    }

    json_object_put(jobj);
}

/** Set if a specific client has access through the firewall */
int
nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    s_config *config = config_get_config();
    switch(type) {
        case FW_ACCESS_ALLOW:
            nftables_do_command("add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s counter mark set 0x20000 accept", mac, ip);
            nftables_do_command("add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter mark set 0x20000 accept", ip);
            break;
        case FW_ACCESS_DENY:
            nft_fw_del_rule_by_ip_and_mac(ip, mac, "mangle_prerouting_wifidogx_outgoing");
            nft_fw_del_rule_by_ip_and_mac(ip, NULL, "mangle_postrouting_wifidogx_incoming");
            if (config->enable_del_conntrack) {
                run_cmd("conntrack -D -s %s", ip);
            }
            break;
        default:
            debug(LOG_ERR, "Unknown fw_access type %d", type);
            return 1;
    }
    return 0;
}

int 
nft_fw_access_host(fw_access_t type, const char *ip)
{
    return 0;
}

/** Reload client's firewall rules */
int 
nft_fw_reload_client()
{
    t_client *first_client = client_get_first_client();
    if (first_client == NULL) {
        debug(LOG_INFO, "No clients in list!");
        return 1;
    }

    FILE *fp = fopen(NFT_WIFIDOGX_CLIENT_LIST, "w");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to open %s", NFT_WIFIDOGX_CLIENT_LIST);
        return 1;
    }
    fprintf(fp, "flush chain inet fw4 mangle_prerouting_wifidogx_outgoing\n");
    fprintf(fp, "flush chain inet fw4 mangle_postrouting_wifidogx_incoming\n");
    
    t_client *current = first_client;
    char line[256] = {0};
    do {
        snprintf(line, sizeof(line), 
            "add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter packets %llu bytes %llu mark set 0x20000 accept\n", 
            current->mac, current->ip, current->counters.outgoing_packets, current->counters.outgoing);
        fprintf(fp, "%s", line);
        memset(line, 0, sizeof(line));
        snprintf(line, sizeof(line), 
            "add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter packets %llu bytes %llu accept\n", 
            current->ip, current->counters.incoming_packets, current->counters.incoming);
        fprintf(fp, "%s", line);
        memset(line, 0, sizeof(line));
        current = current->next;
    } while (current != NULL);
    fclose(fp);

    run_cmd("nft -f %s", NFT_WIFIDOGX_CLIENT_LIST);

    return 0;
}


static void 
update_client_counters(t_client *client, uint64_t packets, uint64_t bytes, int is_outgoing)
{
    if (client) {
        if (client->name == NULL) {
            debug(LOG_INFO, "fw4_counters_update(): client->name is NULL");
            __get_client_name(client);
        }

        if (client->wired == -1) {
            client->wired = br_is_device_wired(client->mac);
        }

        if (is_outgoing) {
            client->counters.outgoing_history = client->counters.outgoing;
            client->counters.outgoing = bytes;
            client->counters.outgoing_packets = packets;
        } else {
            client->counters.incoming_history = client->counters.incoming;
            client->counters.incoming = bytes;
            client->counters.incoming_packets = packets;
        }

        client->counters.last_updated = time(NULL);
        client->is_online = 1;
    } else {
        debug(LOG_INFO, "fw4_counters_update(): client is NULL");
    }
}

static void
process_nftables_expr(json_object *jobj_expr, int is_outgoing)
{
    uint64_t packets = 0, bytes = 0;
    t_client *p1 = NULL;
    int expr_arraylen = json_object_array_length(jobj_expr);
    for (int j = 0; j < expr_arraylen; j++) {
        json_object *jobj_expr_item = json_object_array_get_idx(jobj_expr, j);
        if (jobj_expr_item == NULL) continue;

        json_object *jobj_counter = NULL;
        json_object *jobj_match = NULL;
        if (json_object_object_get_ex(jobj_expr_item, "counter", &jobj_counter)) {
            json_object *jobj_packets = NULL;
            json_object *jobj_bytes = NULL;
            if (json_object_object_get_ex(jobj_counter, "packets", &jobj_packets) &&
                json_object_object_get_ex(jobj_counter, "bytes", &jobj_bytes)) {
                packets = json_object_get_int64(jobj_packets);
                bytes = json_object_get_int64(jobj_bytes);
            }
        } else if (p1 == NULL && json_object_object_get_ex(jobj_expr_item, "match", &jobj_match)) {
            json_object *jobj_match_right = NULL;
            if (json_object_object_get_ex(jobj_match, "right", &jobj_match_right)) {
                const char *ip_or_mac = json_object_get_string(jobj_match_right);
                if (ip_or_mac) {
                    if (is_valid_ip(ip_or_mac)) {
                        p1 = client_list_find_by_ip(ip_or_mac);
                    } else if (is_valid_mac(ip_or_mac)) {
                        p1 = client_list_find_by_mac(ip_or_mac);
                    } else {
                        debug(LOG_INFO, "process_nftables_expr(): ip_or_mac is not ip address or mac address");
                    }
                }
            }
        }
    }
    update_client_counters(p1, packets, bytes, is_outgoing);
}

static void 
process_nftables_json(json_object *jobj, int is_outgoing)
{
    json_object *jobj_nftables = NULL;
    if (!json_object_object_get_ex(jobj, "nftables", &jobj_nftables)) {
        debug(LOG_ERR, "process_nftables_json(): jobj_nftables is NULL");
        return;
    }

    int arraylen = json_object_array_length(jobj_nftables);
    for (int i = 0; i < arraylen; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj_nftables, i);
        if (jobj_item == NULL) continue;

        json_object *jobj_rule = NULL;
        if (!json_object_object_get_ex(jobj_item, "rule", &jobj_rule)) continue;

        json_object *jobj_expr = NULL;
        if (!json_object_object_get_ex(jobj_rule, "expr", &jobj_expr)) continue;

        process_nftables_expr(jobj_expr, is_outgoing);
    }
}

int 
nft_fw_counters_update()
{
    reset_client_list();

    // get client outgoing traffic
    char *outgoing = NULL;
    uint32_t outgoing_len = 0;
    nft_statistical_outgoing(&outgoing, &outgoing_len);
    if (outgoing == NULL) {
        debug(LOG_ERR, "nft_fw_counters_update(): outgoing is NULL");
        return -1;
    }
    json_object *jobj_outgoing = json_tokener_parse(outgoing);
    if (jobj_outgoing == NULL) {
        free(outgoing);
        debug(LOG_ERR, "nft_fw_counters_update(): jobj_outgoing is NULL");
        return -1;
    }
    free(outgoing);
    process_nftables_json(jobj_outgoing, 1);

    // get client incoming traffic
    char *incoming = NULL;
    uint32_t incoming_len = 0;
    nft_statistical_incoming(&incoming, &incoming_len);
    if (incoming == NULL) {
        debug(LOG_ERR, "nft_fw_counters_update(): incoming is NULL");
        json_object_put(jobj_outgoing);
        return -1;
    }
    json_object *jobj_incoming = json_tokener_parse(incoming);
    if (jobj_incoming == NULL) {
        debug(LOG_ERR, "nft_fw_counters_update(): jobj_incoming is NULL");
        free(incoming);
        json_object_put(jobj_outgoing);
        return -1;
    }
    free(incoming);
    process_nftables_json(jobj_incoming, 0);

    json_object_put(jobj_outgoing);
    json_object_put(jobj_incoming);

    return 0;
}

int 
nft_fw_auth_unreachable(int tag)
{
    return 0;
}

int 
nft_fw_auth_reachable()
{
    return 0;
}

void
nft_fw_clear_authservers()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_auth_servers");
    nftables_do_command("flush set inet fw4 set_wifidogx_auth_servers_v6");
}


void
nft_fw_set_authservers()
{
    t_auth_serv *auth_server = get_auth_server();
    if (auth_server == NULL) {
        debug(LOG_INFO, "auth_server is NULL, maybe local auth mode");
        return;
    }
    t_ip_trusted *ips = auth_server->ips_auth_server;
    if (ips == NULL) {
        debug(LOG_INFO, "auth_server->ips_auth_server is NULL");
        return;
    }
    while(ips) {
        if (ips->ip_type == IP_TYPE_IPV4) {
            nftables_do_command("add element inet fw4 set_wifidogx_auth_servers { %s }", ips->ip);
        } else if (ips->ip_type == IP_TYPE_IPV6) {
            nftables_do_command("add element inet fw4 set_wifidogx_auth_servers_v6 { %s }", ips->ip);
        }
        ips = ips->next;
    }
}

void
nft_fw_clear_inner_domains_trusted()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_inner_trust_domains");
    nftables_do_command("flush set inet fw4 set_wifidogx_inner_trust_domains_v6");
}

void
nft_fw_set_inner_domains_trusted()
{
    const s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;

	LOCK_DOMAIN();

	for (domain_trusted = config->inner_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		t_ip_trusted *ip_trusted = NULL;
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
			if (ip_trusted->ip_type == IP_TYPE_IPV4)
				nftables_do_command("add element inet fw4 set_wifidogx_inner_trust_domains { %s }", ip_trusted->ip);
			else if (ip_trusted->ip_type == IP_TYPE_IPV6)
				nftables_do_command("add element inet fw4 set_wifidogx_inner_trust_domains_v6 { %s }", ip_trusted->ip);
		}
	}

	UNLOCK_DOMAIN();
}

void
nft_fw_refresh_inner_domains_trusted()
{
    nft_fw_clear_inner_domains_trusted();
    nft_fw_set_inner_domains_trusted();
}

void
nft_fw_set_user_domains_trusted()
{
    const s_config *config = config_get_config();
	t_domain_trusted *domain_trusted = NULL;

	LOCK_DOMAIN();

	for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
		t_ip_trusted *ip_trusted = NULL;
		for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
			nftables_do_command("add element inet fw4 set_wifidogx_trust_domains { %s }", ip_trusted->ip);
		}
	}

	UNLOCK_DOMAIN();
}

void
nft_fw_clear_user_domains_trusted()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_domains");
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_domains_v6");
}

void
nft_fw_refresh_user_domains_trusted()
{
    nft_fw_clear_user_domains_trusted();
    nft_fw_set_user_domains_trusted();
}

void
nft_fw_set_trusted_maclist()
{
    const s_config *config = config_get_config();
	t_trusted_mac *p = NULL;

	LOCK_CONFIG();
	for (p = config->trustedmaclist; p != NULL; p = p->next)
		nftables_do_command("add element inet fw4 set_wifidogx_trust_clients { %s }", p->mac);
	UNLOCK_CONFIG();
}

void
nft_fw_clear_trusted_maclist()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_clients");
}

void 
nft_fw_set_mac_temporary(const char *mac, int which)
{
    if (which == 0) {
		nftables_do_command("add element inet fw4 set_wifidogx_tmp_trust_clients { %s }", mac);
	} else if(which > 0) { // trusted
		if (which > 60*5)
			which = 60*5;
		nftables_do_command("add element inet fw4 set_wifidogx_tmp_trust_clients { %s timeout %ds}", mac, which);
	} else if(which < 0) { // untrusted
		// TODO
	}
}