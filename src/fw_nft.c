
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <errno.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

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

#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"
#define NFT_WIFIDOGX_CLIENT_LIST "/tmp/nftables_wifidogx_client_list"

#define NFT_WIFIDOGX_BYPASS_MODE()    \
if (is_bypass_mode()) { \
    debug(LOG_DEBUG, "Bypass mode is enabled, skip nftables rules"); \
    return; \
}

#define NFT_WIFIDOGX_BYPASS_MODE_RETURN(val)    \
if (is_bypass_mode()) { \
    debug(LOG_DEBUG, "Bypass mode is enabled, skip nftables rules"); \
    return val; \
}

static int fw_quiet = 0;
static void nft_statistical_helper(const char *tab, const char *chain, char **output, uint32_t *output_len);

const char *nft_wifidogx_init_script[] = {
    "add table inet wifidogx",
    "add set inet wifidogx set_wifidogx_local_trust_clients { type ether_addr; counter; }",
    "add chain inet wifidogx prerouting{ type nat hook prerouting priority 0; policy accept; }",
    "add chain inet wifidogx mangle_prerouting { type filter hook postrouting priority 0; policy accept; }",
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
    "add set inet fw4 set_wifidogx_trust_clients_out { type ether_addr; flags timeout; timeout 1d; counter; }",
    "add set inet fw4 set_wifidogx_tmp_trust_clients { type ether_addr; flags timeout; timeout 1m; counter; }",
    "add chain inet fw4 dstnat_wifidogx_auth_server",
    "add chain inet fw4 dstnat_wifidogx_wan",
    "add chain inet fw4 dstnat_wifidogx_outgoing",
    "add chain inet fw4 dstnat_wifidogx_trust_domains",
    "add chain inet fw4 dstnat_wifidogx_unknown",
    "add rule inet fw4 dstnat_wifidogx_outgoing ip daddr @set_wifidogx_gateway accept",
    "add rule inet fw4 dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_gateway_v6 accept",
    "add rule inet fw4 dstnat_wifidogx_outgoing jump dstnat_wifidogx_wan",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_trust_clients_out accept",
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
    "add rule inet fw4 forward_wifidogx_wan ether saddr @set_wifidogx_trust_clients_out accept",
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

const char *nft_wifidogx_anti_nat_script[] = {
    "add rule inet wifidogx prerouting iifname $interface$ ether saddr @set_wifidogx_local_trust_clients accept",
    "add rule inet wifidogx prerouting iifname $interface$ ip ttl != { $ttlvalues$ } counter drop",
    "add rule inet wifidogx prerouting iifname $interface$ ip6 hoplimit != { $ttlvalues$ } counter drop",
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
    
    if (config->enable_anti_nat) {
        while(gw_settings) {
            for (size_t i = 0; i < sizeof(nft_wifidogx_anti_nat_script) / sizeof(nft_wifidogx_anti_nat_script[0]); i++) {
                const char *p = nft_wifidogx_anti_nat_script[i];
                memset(buf, 0, sizeof(buf));

                if (strstr(p, "$interface$") && strstr(p, "$ttlvalues$")) {
                    // First replace interface
                    replace_str(p, "$interface$", gw_settings->gw_interface, buf, sizeof(buf));
                    // Then replace ttlvalues in the result
                    char tmp[1024] = {0};
                    replace_str(buf, "$ttlvalues$", config->ttl_values, tmp, sizeof(tmp));
                    fprintf(output_file, "%s\n", tmp);
                    debug(LOG_DEBUG, "anti nat script: %s", tmp);
                } else if (strstr(p, "$interface$")) {
                    replace_str(p, "$interface$", gw_settings->gw_interface, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                } else if (strstr(p, "$ttlvalues$")) {
                    replace_str(p, "$ttlvalues$", config->ttl_values, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                } else {
                    fprintf(output_file, "%s\n", p);
                }
            }
            gw_settings = gw_settings->next;
        }
    }

    gw_settings = get_gateway_settings();

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

static void 
nft_do_init_script_command()
{
    if (access(NFT_FILENAME_OUT, F_OK) == -1) {
        debug(LOG_ERR, "nftables rule file %s not found", NFT_FILENAME_OUT);
        termination_handler(0);
    }

	nftables_do_command("-f %s", NFT_FILENAME_OUT);
}



// Callback function to process Netlink responses
static int 
parse_nft_chain_cb(const struct nlmsghdr *nlh, void *data) 
{
    struct nftnl_rule *rule;
    rule = nftnl_rule_alloc();
    if (!rule) {
        debug(LOG_ERR, "nftnl_rule_alloc failed");
        return MNL_CB_ERROR;
    }

    if (nftnl_rule_nlmsg_parse(nlh, rule) < 0) {
        debug(LOG_ERR, "nftnl_chain_nlmsg_parse failed");
        nftnl_rule_free(rule);
        return MNL_CB_ERROR;
    }

    nftnl_rule_free(rule);
    return MNL_CB_OK;
}

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
nft_mnl_statistical_helper(const char *tab, const char *chain_name, char **output, uint32_t *output_len) 
{
    if (!chain_name || !output || !output_len) {
        debug(LOG_ERR, "Invalid parameters");
        return;
    }
    debug(LOG_DEBUG, "nft_statistical_helper: %s", chain_name);

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

    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, tab);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, NFPROTO_INET);

    nlh = nftnl_chain_nlmsg_build_hdr(buf, NFT_MSG_GETRULE, NFPROTO_INET,
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
        ret = mnl_cb_run(buf, ret, seq, mnl_socket_get_portid(nl), parse_nft_chain_cb, rules_array);
        if (ret <= 0)
            break;
    }

    // Convert output to JSON string
    const char *json_str = json_object_to_json_string_ext(json, JSON_C_TO_STRING_PRETTY);
    debug(LOG_DEBUG, "nft_statistical_helper: %s", json_str);
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
static void 
nft_statistical_helper(const char *tab, const char *chain, char **output, uint32_t *output_len)
{
    if (!tab || !chain || !output || !output_len) {
        debug(LOG_ERR, "Invalid parameters");
        return;
    }

    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "nft -j list chain inet %s %s", tab, chain);
    debug(LOG_DEBUG, "Running command: %s", cmd);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        debug(LOG_ERR, "Failed to run command: %s", strerror(errno));
        return;
    }

    // Read output in chunks
    char *buf = NULL;
    size_t total_len = 0;
    size_t chunk_size = 4096;
    
    while (1) {
        char *new_buf = realloc(buf, total_len + chunk_size);
        if (!new_buf) {
            debug(LOG_ERR, "Memory allocation failed");
            free(buf);
            pclose(fp);
            return;
        }
        buf = new_buf;

        size_t bytes_read = fread(buf + total_len, 1, chunk_size, fp);
        total_len += bytes_read;

        if (bytes_read < chunk_size) {
            if (feof(fp)) {
                break;
            }
            if (ferror(fp)) {
                debug(LOG_ERR, "Error reading command output: %s", strerror(errno));
                free(buf);
                pclose(fp);
                return;
            }
        }
    }

    pclose(fp);

    // Ensure buffer is null terminated
    char *final_buf = realloc(buf, total_len + 1);
    if (!final_buf) {
        debug(LOG_ERR, "Final buffer allocation failed");
        free(buf);
        return;
    }
    final_buf[total_len] = '\0';

    *output = final_buf;
    *output_len = total_len;
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
static void 
nft_statistical_outgoing(char **outgoing, uint32_t *outgoing_len)
{
    nft_statistical_helper("fw4", "mangle_prerouting_wifidogx_outgoing", outgoing, outgoing_len);
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
static void
nft_statistical_incoming(char **incoming, uint32_t *incoming_len)
{
    nft_statistical_helper("fw4", "mangle_postrouting_wifidogx_incoming", incoming, incoming_len);
}

static void
__nft_add_gw()
{
    t_gateway_setting *gw_settings = get_gateway_settings();
    if (gw_settings == NULL) {
        debug(LOG_ERR, "gateway settings is NULL");
        return;
    }

    while(gw_settings) {
        if (gw_settings->auth_mode) {
            debug(LOG_DEBUG, "add gateway %s to auth", gw_settings->gw_interface);
            nftables_do_command("add rule inet fw4 dstnat iifname %s jump dstnat_wifidogx_outgoing", gw_settings->gw_interface);
            nftables_do_command("add rule inet fw4 mangle_prerouting iifname %s jump mangle_prerouting_wifidogx_outgoing", gw_settings->gw_interface);
            nftables_do_command("add rule inet fw4 mangle_postrouting oifname %s jump mangle_postrouting_wifidogx_incoming", gw_settings->gw_interface);
            if (gw_settings->gw_address_v4)
                nftables_do_command("add element inet fw4 set_wifidogx_gateway { %s }", gw_settings->gw_address_v4);
            if (gw_settings->gw_address_v6)
                nftables_do_command("add element inet fw4 set_wifidogx_gateway_v6 { %s }", gw_settings->gw_address_v6);
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
                nftables_do_command("delete rule inet fw4 %s handle %d", chain_name, handle);
                debug(LOG_DEBUG, "delete chain %s rule hanle %d", chain_name, handle);
            }
        }
    }
}

static void
__nft_del_gw()
{
    delete_wifidogx_rules("dstnat", "dstnat_wifidogx_outgoing");
    delete_wifidogx_rules("mangle_prerouting", "mangle_prerouting_wifidogx_outgoing");
    delete_wifidogx_rules("mangle_postrouting", "mangle_postrouting_wifidogx_incoming");

    nftables_do_command("flush set inet fw4 set_wifidogx_gateway");
    nftables_do_command("flush set inet fw4 set_wifidogx_gateway_v6");
}

void
nft_reload_gw()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_del_gw();
    __nft_add_gw();
    UNLOCK_CONFIG();
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
    nftables_do_command("add element inet fw4 set_wifidogx_bypass_clients { %s }", ip);
    free(ip);

    ip = get_iface_ip6(config->external_interface);
    if (ip == NULL) {
        debug(LOG_ERR, "get_iface_ip6 [%s] failed", config->external_interface);
        return;
    }
    nftables_do_command("add element inet fw4 set_wifidogx_bypass_clients_v6 { %s }", ip);
    free(ip);
}

int
nft_fw_destroy(void)
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);

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
    char *buf = NULL;
    uint32_t buf_len = 0;
    nft_statistical_helper("fw4", chain, &buf, &buf_len);
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
    char cmd[128] = {0};
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
            nftables_do_command(cmd);
            memset(cmd, 0, sizeof(cmd));
        }
    }

    json_object_put(jobj);
}

/**
 * Control client firewall access
 *
 * @param type          Access type - allow or deny
 * @param ip           Client IP address
 * @param mac          Client MAC address 
 * @param tag          Tag for marking rules (unused)
 *
 * @return 0 on success, 1 on failure
 *
 * This function controls client network access by:
 * - FW_ACCESS_ALLOW: Adding rules to allow traffic for the client
 * - FW_ACCESS_DENY: Removing existing rules and optionally clearing conntrack entries
 */
int
nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    if (is_bypass_mode()) {
        if (!ip) {
            debug(LOG_ERR, "Invalid parameters: ip is NULL");
            return 1;
        }

        char cmd[128] = {0};
        switch(type) {
            case FW_ACCESS_ALLOW:
                snprintf(cmd, sizeof(cmd), "vppctl redirect set auth user %s", ip);
                break;
            case FW_ACCESS_DENY:
                snprintf(cmd, sizeof(cmd), "vppctl redirect set auth user %s del", ip);
                break;
            default:
                debug(LOG_ERR, "Unknown fw_access type %d", type);
                return 1;
        }
        execute(cmd, 0);
        return 0;
    }

    if (!ip || !mac) {
        debug(LOG_ERR, "Invalid parameters: ip or mac is NULL");
        return 1;
    }

    switch(type) {
        case FW_ACCESS_ALLOW:
            // Add outgoing traffic rule with counter and mark
            nftables_do_command("add rule inet fw4 mangle_prerouting_wifidogx_outgoing "
                              "ether saddr %s ip saddr %s counter mark set 0x20000 accept", 
                              mac, ip);

            // Add incoming traffic rule with counter
            nftables_do_command("add rule inet fw4 mangle_postrouting_wifidogx_incoming "
                              "ip daddr %s counter accept", ip);
            break;

        case FW_ACCESS_DENY:
            // Remove client rules from outgoing chain
            nft_fw_del_rule_by_ip_and_mac(ip, mac, "mangle_prerouting_wifidogx_outgoing");
            
            // Remove client rules from incoming chain
            nft_fw_del_rule_by_ip_and_mac(ip, NULL, "mangle_postrouting_wifidogx_incoming");

            // Optionally clear connection tracking entries
            if (config_get_config()->enable_del_conntrack) {
                char cmd[128] = {0};
                snprintf(cmd, sizeof(cmd), "conntrack -D -s %s", ip);
                execute(cmd, 0);
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


/**
 * Reload all client firewall rules and counters
 *
 * This function:
 * 1. Gets first client from client list
 * 2. Creates a temporary file to store nftables rules
 * 3. Flushes existing client chains
 * 4. For each client:
 *    - Adds outgoing traffic rule with packet/byte counters and mark
 *    - Adds incoming traffic rule with packet/byte counters
 * 5. Applies the rules using nft command
 *
 * @return 0 on success, 1 on failure
 */
int 
nft_fw_reload_client()
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);

    t_client *first_client = client_get_first_client();
    if (first_client == NULL) {
        debug(LOG_INFO, "No clients in list!");
        return 1;
    }

    // Open temporary file to store rules
    FILE *fp = fopen(NFT_WIFIDOGX_CLIENT_LIST, "w");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to open %s: %s", 
              NFT_WIFIDOGX_CLIENT_LIST, strerror(errno));
        return 1;
    }

    // Flush existing client chains
    fprintf(fp, "flush chain inet fw4 mangle_prerouting_wifidogx_outgoing\n");
    fprintf(fp, "flush chain inet fw4 mangle_postrouting_wifidogx_incoming\n");
    
    // Add rules for each client
    t_client *current = first_client;
    char rule[256];
    do {
        // Add outgoing rule with counters
        snprintf(rule, sizeof(rule), 
                "add rule inet fw4 mangle_prerouting_wifidogx_outgoing "
                "ether saddr %s ip saddr %s counter packets %llu bytes %llu "
                "mark set 0x20000 accept\n",
                current->mac, current->ip,
                current->counters.outgoing_packets,
                current->counters.outgoing);
        fprintf(fp, "%s", rule);

        // Add incoming rule with counters
        snprintf(rule, sizeof(rule),
                "add rule inet fw4 mangle_postrouting_wifidogx_incoming "
                "ip daddr %s counter packets %llu bytes %llu accept\n",
                current->ip,
                current->counters.incoming_packets,
                current->counters.incoming);
        fprintf(fp, "%s", rule);

        current = current->next;
    } while (current != NULL);

    fclose(fp);

    // Apply the rules
    return nftables_do_command(" -f %s", NFT_WIFIDOGX_CLIENT_LIST);
}


/** 
 * Update traffic counters for a client
 *
 * This function updates the traffic statistics for a given client,
 * including packet and byte counts for incoming/outgoing traffic.
 * It also updates the client's online status and wired connection type.
 *
 * @param client        Pointer to client structure to update
 * @param packets       Number of packets counted
 * @param bytes        Number of bytes counted 
 * @param is_outgoing  1 if outgoing traffic, 0 if incoming traffic
 */
static void 
update_client_counters(t_client *client, uint64_t packets, uint64_t bytes, int is_outgoing)
{
    if (!client) {
        debug(LOG_INFO, "Client is NULL, cannot update counters");
        return;
    }

    // Get client name if not already set
    if (!client->name) {
        debug(LOG_INFO, "Client name not set, retrieving name");
        get_client_name(client); 
    }

    // Determine if client is on wired connection
    if (client->wired == -1) {
        client->wired = br_is_device_wired(client->mac);
    }

    // Update traffic counters
    if (is_outgoing) {
        // Save previous outgoing count and update with new values
        client->counters.outgoing_history = client->counters.outgoing;
        client->counters.outgoing = bytes;
        client->counters.outgoing_packets = packets;
    } else {
        // Save previous incoming count and update with new values
        client->counters.incoming_history = client->counters.incoming;
        client->counters.incoming = bytes;
        client->counters.incoming_packets = packets;
    }

    // Update timestamp and online status
    client->counters.last_updated = time(NULL);
    client->is_online = 1;
}

/**
 * @brief Process nftables expressions to extract counter data and client information
 *
 * This function parses a JSON object containing nftables expressions to extract:
 * 1. Counter data (packets and bytes)
 * 2. Client information based on IP or MAC address
 * 
 * The function then updates the client counters with the extracted information.
 *
 * @param jobj_expr JSON object array containing nftables expressions
 * @param is_outgoing Flag indicating if the traffic is outgoing (1) or incoming (0)
 *
 * The function performs the following:
 * - Iterates through expression array
 * - Extracts packet and byte counters if present
 * - Identifies client by IP or MAC address from match expressions
 * - Updates client counters with accumulated data
 *
 * @note The function expects the JSON object to follow nftables JSON format
 * @note Client identification stops after finding the first valid IP/MAC match
 */
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

/**
 * @brief Process JSON representation of nftables rules
 *
 * Parses a JSON object containing nftables rules and processes each rule's expressions.
 * The function traverses the JSON structure to extract rule expressions for either
 * incoming or outgoing traffic.
 *
 * @param jobj The root JSON object containing nftables configuration
 * @param is_outgoing Flag indicating if processing outgoing (1) or incoming (0) rules
 * 
 * @details
 * The expected JSON structure should be:
 * {
 *   "nftables": [
 *     {
 *       "rule": {
 *         "expr": [...]
 *       }
 *     },
 *     ...
 *   ]
 * }
 *
 * The function will:
 * 1. Extract the "nftables" array
 * 2. Iterate through each array element
 * 3. Extract "rule" and "expr" objects
 * 4. Process expressions through process_nftables_expr()
 *
 * @note Function silently returns if required JSON objects are not found
 */
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

/**
 * @brief Updates firewall counters by processing nftables statistics
 * 
 * This function performs the following operations:
 * 1. Resets the client list
 * 2. Retrieves and processes outgoing traffic statistics from nftables
 * 3. Retrieves and processes incoming traffic statistics from nftables
 * 
 * The function uses JSON parsing to process the nftables statistics data.
 * Both incoming and outgoing traffic data are handled separately through
 * the process_nftables_json function.
 * 
 * @return 0 on success, -1 on failure
 *         Failures can occur if:
 *         - Unable to get outgoing traffic statistics
 *         - Unable to parse outgoing traffic JSON
 *         - Unable to get incoming traffic statistics
 *         - Unable to parse incoming traffic JSON
 */
int 
nft_fw_counters_update()
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);

    reset_client_list();

    // get client outgoing traffic
    char *outgoing = NULL;
    uint32_t outgoing_len = 0;
    nft_statistical_outgoing(&outgoing, &outgoing_len);
    if (outgoing == NULL) {
        debug(LOG_ERR, "nft_fw_counters_update(): outgoing is NULL");
        return -1;
    }
    debug(LOG_DEBUG, "outgoing: %s", outgoing);
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
    debug(LOG_DEBUG, "incoming: %s", incoming);
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

static void
__nft_fw_clear_authservers()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_auth_servers");
    nftables_do_command("flush set inet fw4 set_wifidogx_auth_servers_v6");
}

void
nft_fw_clear_authservers()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_clear_authservers();
    UNLOCK_CONFIG();
}

static void
__nft_fw_set_authservers()
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
nft_fw_set_authservers()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_set_authservers();
    UNLOCK_CONFIG();
}

static void
__nft_fw_clear_inner_domains_trusted()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_inner_trust_domains");
    nftables_do_command("flush set inet fw4 set_wifidogx_inner_trust_domains_v6");
}

void
nft_fw_clear_inner_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_clear_inner_domains_trusted();
    UNLOCK_CONFIG();
}

static void
__nft_fw_set_inner_domains_trusted()
{
    const s_config *config = config_get_config();
    t_domain_trusted *domain_trusted = NULL;

    for (domain_trusted = config->inner_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        t_ip_trusted *ip_trusted = NULL;
        for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
            if (ip_trusted->ip_type == IP_TYPE_IPV4)
                nftables_do_command("add element inet fw4 set_wifidogx_inner_trust_domains { %s }", ip_trusted->ip);
            else if (ip_trusted->ip_type == IP_TYPE_IPV6)
                nftables_do_command("add element inet fw4 set_wifidogx_inner_trust_domains_v6 { %s }", ip_trusted->ip);
        }
    }
}

void
nft_fw_set_inner_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_set_inner_domains_trusted();
    UNLOCK_CONFIG();
}

void
nft_fw_refresh_inner_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_clear_inner_domains_trusted();
    __nft_fw_set_inner_domains_trusted();
    UNLOCK_CONFIG();
}

static void
__nft_fw_set_user_domains_trusted()
{
    const s_config *config = config_get_config();
    t_domain_trusted *domain_trusted = NULL;

    for (domain_trusted = config->domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        t_ip_trusted *ip_trusted = NULL;
        for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
            nftables_do_command("add element inet fw4 set_wifidogx_trust_domains { %s }", ip_trusted->ip);
        }
    }
}

void
nft_fw_set_user_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

	LOCK_DOMAIN();
	__nft_fw_set_user_domains_trusted();
	UNLOCK_DOMAIN();
}

static void
__nft_fw_clear_user_domains_trusted()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_domains");
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_domains_v6");
}

void
nft_fw_clear_user_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_DOMAIN();
    __nft_fw_clear_user_domains_trusted();
    UNLOCK_DOMAIN();
}

void
nft_fw_refresh_user_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_DOMAIN();
    __nft_fw_clear_user_domains_trusted();
    __nft_fw_set_user_domains_trusted();
    UNLOCK_DOMAIN();
}

static void
__nft_fw_add_trusted_mac(const char *mac, int timeout)
{
    if (timeout == 0)
        nftables_do_command("add element inet fw4 set_wifidogx_trust_clients_out { %s }", mac);
    else
        nftables_do_command("add element inet fw4 set_wifidogx_trust_clients_out { %s timeout %ds}", mac, timeout);
}

static void
__nft_fw_del_trusted_mac(const char *mac)
{
    nftables_do_command("delete element inet fw4 set_wifidogx_trust_clients_out { %s }", mac);
}

void
nft_fw_del_trusted_mac(const char *mac)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_del_trusted_mac(mac);
    UNLOCK_CONFIG();
}

void
nft_fw_add_trusted_mac(const char *mac, int timeout)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_add_trusted_mac(mac, timeout);
    UNLOCK_CONFIG();
}

void
nft_fw_update_trusted_mac(const char *mac, int timeout)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_del_trusted_mac(mac);
    __nft_fw_add_trusted_mac(mac, timeout);
    UNLOCK_CONFIG();
}

static void
__nft_fw_set_trusted_maclist()
{
    const s_config *config = config_get_config();
    for (t_trusted_mac *p = config->trustedmaclist; p != NULL; p = p->next)
        __nft_fw_add_trusted_mac(p->mac, p->remaining_time);
}

void
nft_fw_set_trusted_maclist()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_set_trusted_maclist();
    UNLOCK_CONFIG();
}

static void
__nft_fw_clear_trusted_maclist()
{
    nftables_do_command("flush set inet fw4 set_wifidogx_trust_clients_out");
}

void
nft_fw_clear_trusted_maclist()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_clear_trusted_maclist();
    UNLOCK_CONFIG();
}

void
nft_fw_refresh_trusted_maclist()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_clear_trusted_maclist();
    __nft_fw_set_trusted_maclist();
    UNLOCK_CONFIG();
}

void 
nft_fw_set_mac_temporary(const char *mac, int which)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    if (which == 0) {
		nftables_do_command("add element inet fw4 set_wifidogx_tmp_trust_clients { %s }", mac);
	} else if(which > 0) { // trusted
		if (which > 60*5)
			which = 60*5;
		nftables_do_command("add element inet fw4 set_wifidogx_tmp_trust_clients { %s timeout %ds}", mac, which);
	} else if(which < 0) { // untrusted
		// TODO
	}
    UNLOCK_CONFIG();
}

void
nft_fw_add_anti_nat_permit(const char *mac)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    nftables_do_command("add element inet wifidogx set_wifidogx_local_trust_clients { %s }", mac);
    UNLOCK_CONFIG();
}

void
nft_fw_del_anti_nat_permit(const char *mac)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    nftables_do_command("delete element inet wifidogx set_wifidogx_local_trust_clients { %s }", mac);
    UNLOCK_CONFIG();
}

static void
__nft_fw_set_anti_nat_permit()
{
    const s_config *config = config_get_config();
    if (config->anti_nat_permit_macs == NULL) {
        debug(LOG_WARNING, "anti_nat_permit_macs is NULL");
        return;
    }

    nftables_do_command("add element inet wifidogx set_wifidogx_local_trust_clients { %s }", config->anti_nat_permit_macs);
}

void
nft_fw_set_anti_nat_permit()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    __nft_fw_set_anti_nat_permit();
    UNLOCK_CONFIG();
}

/**
 * @brief Initializes the nftables firewall rules for WiFiDog
 * 
 * This function performs the complete initialization of nftables firewall rules by:
 * 1. Generating the initial nftables script
 * 2. Executing the initialization script
 * 3. Setting up external interface rules
 * 4. Adding gateway rules
 * 5. Configuring authentication server rules
 * 6. Setting up trusted MAC address list
 * 7. Configuring anti-NAT permit rules
 *
 * @return Returns 1 upon successful completion
 */
int 
nft_fw_init()
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(1);

	generate_nft_wifidogx_init_script();
	nft_do_init_script_command();
    nft_set_ext_interface();
    __nft_add_gw();
    __nft_fw_set_authservers();
    __nft_fw_set_trusted_maclist();
    __nft_fw_set_anti_nat_permit();

    return 1;
}

void
nft_fw_conntrack_flush()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    execute("conntrack -F", 0);
}