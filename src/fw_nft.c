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
#include <bpf/bpf.h>

#include "debug.h"
#include "util.h"
#include "wd_util.h"
#include "firewall.h"
#include "fw_nft.h"
#include "client_list.h"
#include "conf.h"
#include "gateway.h"
#include "safe.h"

// Include the eBPF header for required structures
#include "../ebpf/aw-bpf.h"

#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"
#define NFT_WIFIDOGX_CLIENT_LIST "/tmp/nftables_wifidogx_client_list"
#define NFT_WIFIDOGX_TRUST_CLIENTS "/tmp/nftables_wifidogx_trust_clients"

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
static int nft_fw_counters_update_ebpf(void);
static int nft_fw_counters_update_nftables(void);
static void nft_statistical_helper(const char *tab, const char *chain, char **output, uint32_t *output_len);

const char *nft_wifidogx_init_script[] = {
    "add table inet wifidogx",
    "add set inet wifidogx set_wifidogx_antinat_local_macs { type ether_addr; counter; }",
    "add set inet wifidogx set_wifidogx_auth_servers { type ipv4_addr; }",
    "add set inet wifidogx set_wifidogx_auth_servers_v6 { type ipv6_addr; }",
    "add set inet wifidogx set_wifidogx_gateway { type ipv4_addr; }",
    "add set inet wifidogx set_wifidogx_gateway_v6 { type ipv6_addr; }",
    "add set inet wifidogx set_wifidogx_trust_domains { type ipv4_addr; }",
    "add set inet wifidogx set_wifidogx_trust_domains_v6 { type ipv6_addr; }",
    "add set inet wifidogx set_wifidogx_wildcard_trust_domains { type ipv4_addr; }",
    "add set inet wifidogx set_wifidogx_wildcard_trust_domains_v6 { type ipv6_addr; }",
    "add set inet wifidogx set_wifidogx_inner_trust_domains { type ipv4_addr; }",
    "add set inet wifidogx set_wifidogx_inner_trust_domains_v6 { type ipv6_addr; }",
    "add set inet wifidogx set_wifidogx_bypass_clients { type ipv4_addr; flags interval; }",
    "add set inet wifidogx set_wifidogx_bypass_clients_v6 { type ipv6_addr; flags interval; }",
    "add set inet wifidogx set_wifidogx_trust_clients_out { type ether_addr; flags timeout; timeout 1d; counter; }",
    "add set inet wifidogx set_wifidogx_tmp_trust_clients { type ether_addr; flags timeout; timeout 1m; counter; }",
    "add chain inet wifidogx prerouting { type nat hook prerouting priority -100; policy accept; }",
    "add chain inet wifidogx forward { type filter hook forward priority -100; policy accept; }",
    "add chain inet wifidogx mangle_prerouting { type filter hook prerouting priority -100; policy accept; }",
    "add chain inet wifidogx mangle_postrouting { type filter hook postrouting priority mangle; policy accept; }",
    "add chain inet wifidogx wifidogx_antinat",
    "add chain inet wifidogx wifidogx_redirect",
    "add chain inet wifidogx dstnat_wifidogx_outgoing",
    "add chain inet wifidogx dstnat_wifidogx_unknown",
    "add chain inet wifidogx forward_wifidogx_wan",
    "add chain inet wifidogx forward_wifidogx_unknown",
    "add chain inet wifidogx mangle_prerouting_wifidogx_outgoing",
    "add chain inet wifidogx mangle_postrouting_wifidogx_incoming",
    "add rule inet wifidogx dstnat_wifidogx_unknown jump wifidogx_redirect",
    "add rule inet wifidogx wifidogx_redirect tcp dport 443 redirect to $HTTPS_PORT$",
    "add rule inet wifidogx wifidogx_redirect udp dport 443 drop",
    "add rule inet wifidogx wifidogx_redirect tcp dport 80 redirect to $HTTP_PORT$",
    "add rule inet wifidogx wifidogx_redirect udp dport 80 drop",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip daddr @set_wifidogx_gateway accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_gateway_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ether saddr @set_wifidogx_trust_clients_out accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 saddr @set_wifidogx_bypass_clients_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing meta mark 0x20000 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing meta mark 0x10000 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_auth_servers_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_trust_domains_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip daddr @set_wifidogx_inner_trust_domains accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_inner_trust_domains_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip daddr @set_wifidogx_wildcard_trust_domains accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing ip6 daddr @set_wifidogx_wildcard_trust_domains_v6 accept",
    "add rule inet wifidogx dstnat_wifidogx_outgoing jump dstnat_wifidogx_unknown",
    "add rule inet wifidogx forward_wifidogx_wan ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet wifidogx forward_wifidogx_wan ip6 daddr @set_wifidogx_auth_servers_v6 accept",
    "add rule inet wifidogx forward_wifidogx_wan ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet wifidogx forward_wifidogx_wan ip6 daddr @set_wifidogx_trust_domains_v6 accept",
    "add rule inet wifidogx forward_wifidogx_wan ip daddr @set_wifidogx_inner_trust_domains accept",
    "add rule inet wifidogx forward_wifidogx_wan ip6 daddr @set_wifidogx_inner_trust_domains_v6 accept",
    "add rule inet wifidogx forward_wifidogx_wan ip daddr @set_wifidogx_wildcard_trust_domains accept",
    "add rule inet wifidogx forward_wifidogx_wan ip6 daddr @set_wifidogx_wildcard_trust_domains_v6 accept",
    "add rule inet wifidogx forward_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet wifidogx forward_wifidogx_wan ether saddr @set_wifidogx_trust_clients_out accept",
    "add rule inet wifidogx forward_wifidogx_wan ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet wifidogx forward_wifidogx_wan ip6 saddr @set_wifidogx_bypass_clients_v6 accept",
    "add rule inet wifidogx forward_wifidogx_wan meta mark 0x10000 accept",
    "add rule inet wifidogx forward_wifidogx_wan meta mark 0x20000 accept",
    "add rule inet wifidogx forward_wifidogx_wan jump forward_wifidogx_unknown",
    "add rule inet wifidogx forward_wifidogx_unknown reject",
};

const char *nft_wifidogx_anti_nat_script[] = {
    "add rule inet wifidogx wifidogx_antinat iifname $interface$ ether saddr @set_wifidogx_antinat_local_macs accept",
    "add rule inet wifidogx wifidogx_antinat iifname $interface$ ip ttl != { $ttlvalues$ } counter drop",
    "add rule inet wifidogx wifidogx_antinat iifname $interface$ ip6 hoplimit != { $ttlvalues$ } counter drop",
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

    // Write base initialization rules with port substitution
    for (size_t i = 0; i < sizeof(nft_wifidogx_init_script) / sizeof(nft_wifidogx_init_script[0]); i++) {
        const char *rule = nft_wifidogx_init_script[i];
        memset(buf, 0, sizeof(buf));
        
        if (strstr(rule, "$HTTPS_PORT$") && strstr(rule, "$HTTP_PORT$")) {
            // Replace both ports in same rule (shouldn't happen with current rules)
            char tmp[1024] = {0};
            snprintf(tmp, sizeof(tmp), "%d", config->gw_https_port);
            replace_str(rule, "$HTTPS_PORT$", tmp, buf, sizeof(buf));
            memset(tmp, 0, sizeof(tmp));
            snprintf(tmp, sizeof(tmp), "%d", config->gw_port);
            char final_rule[1024] = {0};
            replace_str(buf, "$HTTP_PORT$", tmp, final_rule, sizeof(final_rule));
            fprintf(output_file, "%s\n", final_rule);
        } else if (strstr(rule, "$HTTPS_PORT$")) {
            char port_str[16] = {0};
            snprintf(port_str, sizeof(port_str), "%d", config->gw_https_port);
            replace_str(rule, "$HTTPS_PORT$", port_str, buf, sizeof(buf));
            fprintf(output_file, "%s\n", buf);
        } else if (strstr(rule, "$HTTP_PORT$")) {
            char port_str[16] = {0};
            snprintf(port_str, sizeof(port_str), "%d", config->gw_port);
            replace_str(rule, "$HTTP_PORT$", port_str, buf, sizeof(buf));
            fprintf(output_file, "%s\n", buf);
        } else {
            fprintf(output_file, "%s\n", rule);
        }
    }
    
    if (config->enable_anti_nat) {
        t_gateway_setting *curr_gw = gw_settings;
        while(curr_gw) {
            for (size_t i = 0; i < sizeof(nft_wifidogx_anti_nat_script) / sizeof(nft_wifidogx_anti_nat_script[0]); i++) {
                const char *p = nft_wifidogx_anti_nat_script[i];
                memset(buf, 0, sizeof(buf));

                if (strstr(p, "$interface$") && strstr(p, "$ttlvalues$")) {
                    replace_str(p, "$interface$", curr_gw->gw_interface, buf, sizeof(buf));
                    char tmp[1024] = {0};
                    replace_str(buf, "$ttlvalues$", config->ttl_values, tmp, sizeof(tmp));
                    fprintf(output_file, "%s\n", tmp);
                } else if (strstr(p, "$interface$")) {
                    replace_str(p, "$interface$", curr_gw->gw_interface, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                } else if (strstr(p, "$ttlvalues$")) {
                    replace_str(p, "$ttlvalues$", config->ttl_values, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                } else {
                    fprintf(output_file, "%s\n", p);
                }
            }
            curr_gw = curr_gw->next;
        }
    }

    // Add per-interface jumps
    t_gateway_setting *curr_gw = gw_settings;
    while(curr_gw) {
        fprintf(output_file, "add rule inet wifidogx prerouting iifname \"%s\" jump wifidogx_antinat\n", curr_gw->gw_interface);
        fprintf(output_file, "add rule inet wifidogx prerouting iifname \"%s\" jump dstnat_wifidogx_outgoing\n", curr_gw->gw_interface);
        fprintf(output_file, "add rule inet wifidogx forward iifname \"%s\" jump forward_wifidogx_wan\n", curr_gw->gw_interface);
        fprintf(output_file, "add rule inet wifidogx mangle_prerouting iifname \"%s\" jump mangle_prerouting_wifidogx_outgoing\n", curr_gw->gw_interface);
        fprintf(output_file, "add rule inet wifidogx mangle_postrouting oifname \"%s\" jump mangle_postrouting_wifidogx_incoming\n", curr_gw->gw_interface);
        curr_gw = curr_gw->next;
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
    nft_statistical_helper("wifidogx", "mangle_prerouting_wifidogx_outgoing", outgoing, outgoing_len);
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
    nft_statistical_helper("wifidogx", "mangle_postrouting_wifidogx_incoming", incoming, incoming_len);
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
            if (gw_settings->gw_address_v4)
                nftables_do_command("add element inet wifidogx set_wifidogx_gateway { %s }", gw_settings->gw_address_v4);
            if (gw_settings->gw_address_v6)
                nftables_do_command("add element inet wifidogx set_wifidogx_gateway_v6 { %s }", gw_settings->gw_address_v6);
        }
        gw_settings = gw_settings->next;
    }
}


static void
__nft_del_gw()
{
    nftables_do_command("flush set inet wifidogx set_wifidogx_gateway");
    nftables_do_command("flush set inet wifidogx set_wifidogx_gateway_v6");
}

void
nft_reload_gw()
{
    NFT_WIFIDOGX_BYPASS_MODE();
    
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_DEBUG, "Portal authentication is disabled, skip reload_gw operation");
        return;
    }

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
    nftables_do_command("add element inet wifidogx set_wifidogx_bypass_clients { %s }", ip);
    free(ip);

    ip = get_iface_ip6(config->external_interface);
    if (ip == NULL) {
        debug(LOG_ERR, "get_iface_ip6 [%s] failed", config->external_interface);
        return;
    }
    nftables_do_command("add element inet wifidogx set_wifidogx_bypass_clients_v6 { %s }", ip);
    free(ip);
}

int
nft_fw_destroy(void)
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);
    
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_DEBUG, "Portal authentication is disabled, skip fw_destroy operation");
        return 0;
    }

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

    return 0;
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
                        } else if (strcmp(protocol, "ip6") == 0 && ip && strcmp(right, ip) == 0) {
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
    nft_statistical_helper("wifidogx", chain, &buf, &buf_len);
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
            continue;
        }

        debug(LOG_DEBUG, "jobj_rule: %s", json_object_to_json_string(jobj_rule));
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
            snprintf(cmd, sizeof(cmd), "delete rule inet wifidogx %s handle %s", chain, handle);
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
    char cmd[128] = {0};
    
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_DEBUG, "Portal authentication is disabled, skip fw_access operation");
        return 0;
    }
    
    if (!ip || !mac) {
        debug(LOG_ERR, "Invalid parameters: ip or mac is NULL");
        return 1;
    }

    switch(type) {
        case FW_ACCESS_ALLOW:
            // Add outgoing traffic rule with counter and mark
            if (is_valid_ip(ip)) {
                nftables_do_command("add rule inet wifidogx mangle_prerouting_wifidogx_outgoing "
                                "ether saddr %s ip saddr %s counter mark set 0x20000 accept", 
                                mac, ip);

                // Add incoming traffic rule with counter
                nftables_do_command("add rule inet wifidogx mangle_postrouting_wifidogx_incoming "
                                "ip daddr %s counter accept", ip);

                snprintf(cmd, sizeof(cmd), "aw-bpfctl ipv4 add %s", ip);
                execute(cmd, 0);
            } else if (is_valid_ip6(ip)){
                nftables_do_command("add rule inet wifidogx mangle_prerouting_wifidogx_outgoing "
                                "ether saddr %s ip6 saddr %s counter mark set 0x20000 accept", 
                                mac, ip);

                // Add incoming traffic rule with counter
                nftables_do_command("add rule inet wifidogx mangle_postrouting_wifidogx_incoming "
                                "ip6 daddr %s counter accept", ip);

                snprintf(cmd, sizeof(cmd), "aw-bpfctl ipv6 add %s", ip);
                execute(cmd, 0);
            } else {
                debug(LOG_ERR, "Invalid IP address: %s", ip);
            }
            
            if (is_valid_mac(mac)) {
                snprintf(cmd, sizeof(cmd), "aw-bpfctl mac add %s", mac);
                execute(cmd, 0);
            } 

            break;

        case FW_ACCESS_DENY:
            // Remove client rules from outgoing chain
            nft_fw_del_rule_by_ip_and_mac(ip, mac, "mangle_prerouting_wifidogx_outgoing");
            
            // Remove client rules from incoming chain
            nft_fw_del_rule_by_ip_and_mac(ip, NULL, "mangle_postrouting_wifidogx_incoming");

            if (is_valid_ip(ip)) {
                snprintf(cmd, sizeof(cmd), "aw-bpfctl ipv4 del %s", ip);
                execute(cmd, 0);
            } else if (is_valid_ip6(ip)) {
                snprintf(cmd, sizeof(cmd), "aw-bpfctl ipv6 del %s", ip);
                execute(cmd, 0);
            } else {
                debug(LOG_ERR, "Invalid IP address: %s", ip);
            }

            if (is_valid_mac(mac)) {
                snprintf(cmd, sizeof(cmd), "aw-bpfctl mac del %s", mac);
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
    fprintf(fp, "flush chain inet wifidogx mangle_prerouting_wifidogx_outgoing\n");
    fprintf(fp, "flush chain inet wifidogx mangle_postrouting_wifidogx_incoming\n");
    
    // Add rules for each client
    t_client *current = first_client;
    char rule[256];
    do {
        // Add outgoing rule with counters
        snprintf(rule, sizeof(rule), 
                "add rule inet wifidogx mangle_prerouting_wifidogx_outgoing "
                "ether saddr %s ip saddr %s counter packets %llu bytes %llu "
                "mark set 0x20000 accept\n",
                current->mac, current->ip,
                current->counters.outgoing_packets,
                current->counters.outgoing_bytes);
        fprintf(fp, "%s", rule);

        // Add incoming rule with counters
        snprintf(rule, sizeof(rule),
                "add rule inet wifidogx mangle_postrouting_wifidogx_incoming "
                "ip daddr %s counter packets %llu bytes %llu accept\n",
                current->ip,
                current->counters.incoming_packets,
                current->counters.incoming_bytes);
        fprintf(fp, "%s", rule);

        current = current->next;
    } while (current != NULL);

    fclose(fp);

    // Apply the rules
    return nftables_do_command(" -f %s", NFT_WIFIDOGX_CLIENT_LIST);
}

/**
 * Reload trusted mac list
 */
int
nft_fw_reload_trusted_maclist()
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);

    s_config *config = config_get_config();
    t_trusted_mac *mac_list = config->trustedmaclist;
    
    // Open temporary file
    FILE *fp = fopen(NFT_WIFIDOGX_TRUST_CLIENTS, "w");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to open %s: %s", 
                NFT_WIFIDOGX_TRUST_CLIENTS, strerror(errno));
        return 1;
    }

    // Flush existing trust client set
    fprintf(fp, "flush set inet wifidogx set_wifidogx_trust_clients_out\n");
    
    // Add rules for each trusted MAC
    while (mac_list != NULL) {
        if (mac_list->remaining_time == 0) {
            fprintf(fp, "add element inet wifidogx set_wifidogx_trust_clients_out { %s }\n", 
                    mac_list->mac);
        } else {
            fprintf(fp, "add element inet wifidogx set_wifidogx_trust_clients_out { %s timeout %ds }\n",
                    mac_list->mac, mac_list->remaining_time);
        }
        mac_list = mac_list->next;
    }

    fclose(fp);

    // Apply the rules
    return nftables_do_command(" -f %s", NFT_WIFIDOGX_TRUST_CLIENTS);
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
update_client_counters(t_client *client, uint64_t packets, uint64_t bytes, int is_outgoing, int is_ip6)
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
    if (is_outgoing) {            // Update with new values
            if (is_ip6) {
                uint64_t delta_bytes = bytes - client->counters6.outgoing_bytes;
                client->counters6.outgoing_bytes = bytes;
                client->counters6.outgoing_packets = packets;
                
                // Calculate outgoing rate
                // We need to estimate the rate based on current bytes and previous values
                // Since we don't have direct access to the traffic_stats structure here,
                // we'll use a simple calculation based on time difference
                time_t now = time(NULL);
                time_t time_diff = now - client->counters6.last_updated;
                if (time_diff > 0 && client->counters6.last_updated > 0) {
                    // Calculate bytes per second
                    client->counters6.outgoing_rate = delta_bytes / time_diff;
                }
            } else {
                uint64_t delta_bytes = bytes - client->counters.outgoing_bytes;
                client->counters.outgoing_bytes = bytes;
                client->counters.outgoing_packets = packets;
                
                // Calculate outgoing rate
                time_t now = time(NULL);
                time_t time_diff = now - client->counters.last_updated;
                if (time_diff > 0 && client->counters.last_updated > 0) {
                    // Calculate bytes per second
                    client->counters.outgoing_rate = delta_bytes / time_diff;
                }
            }
    } else {            // Update with new values
            if (is_ip6) {

                uint64_t delta_bytes = bytes - client->counters6.incoming_bytes;
                client->counters6.incoming_bytes = bytes;
                client->counters6.incoming_packets = packets;
                
                // Calculate incoming rate
                time_t now = time(NULL);
                time_t time_diff = now - client->counters6.last_updated;
                if (time_diff > 0 && client->counters6.last_updated > 0) {
                    // Calculate bytes per second
                    client->counters6.incoming_rate = delta_bytes / time_diff;
                }
            } else {
                uint64_t delta_bytes = bytes - client->counters.incoming_bytes;
                client->counters.incoming_bytes = bytes;
                client->counters.incoming_packets = packets;
                
                // Calculate incoming rate
                time_t now = time(NULL);
                time_t time_diff = now - client->counters.last_updated;
                if (time_diff > 0 && client->counters.last_updated > 0) {
                    // Calculate bytes per second
                    client->counters.incoming_rate = delta_bytes / time_diff;
                }
            }
    }

    // Update timestamp and online status
    if (is_ip6) {
        client->counters6.last_updated = time(NULL);
    } else {
        client->counters.last_updated = time(NULL);
    }
    client->is_online = 1;

    debug(LOG_INFO, "Updated counters for client: %s, IP: %s, MAC: %s, "
            "Packets: %llu, Bytes: %llu, Outgoing: %d, IP6: %d",
            client->name, client->ip, client->mac, packets, bytes, is_outgoing, is_ip6);
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
    if (!jobj_expr) {
        debug(LOG_ERR, "Invalid input: jobj_expr is NULL");
        return;
    }

    uint64_t packets = 0, bytes = 0;
    const char *mac = NULL, *ip = NULL;
    int is_ip6 = 0;
    bool has_counter = false;

    // Get array length of expressions
    int expr_arraylen = json_object_array_length(jobj_expr);
    if (expr_arraylen <= 0) {
        debug(LOG_DEBUG, "Empty expression array");
        return;
    }

    // First pass: collect counter data
    // Second pass: collect client identifiers
    for (int pass = 1; pass <= 2; pass++) {
        for (int j = 0; j < expr_arraylen; j++) {
            json_object *expr_item = json_object_array_get_idx(jobj_expr, j);
            if (!expr_item) continue;

            if (pass == 1) {
                // Process counter information
                json_object *counter_obj = NULL;
                if (json_object_object_get_ex(expr_item, "counter", &counter_obj)) {
                    json_object *packets_obj = NULL, *bytes_obj = NULL;
                    if (json_object_object_get_ex(counter_obj, "packets", &packets_obj) &&
                        json_object_object_get_ex(counter_obj, "bytes", &bytes_obj)) {
                        packets = json_object_get_int64(packets_obj);
                        bytes = json_object_get_int64(bytes_obj);
                        has_counter = true;
                    }
                }
            } else {
                // Process match information for client identification
                json_object *match_obj = NULL;
                if (json_object_object_get_ex(expr_item, "match", &match_obj)) {
                    json_object *left = NULL, *right = NULL;
                    if (!json_object_object_get_ex(match_obj, "left", &left) ||
                        !json_object_object_get_ex(match_obj, "right", &right)) {
                        continue;
                    }

                    json_object *payload = NULL;
                    if (!json_object_object_get_ex(left, "payload", &payload)) {
                        continue;
                    }

                    json_object *protocol_obj = NULL;
                    if (!json_object_object_get_ex(payload, "protocol", &protocol_obj)) {
                        continue;
                    }

                    const char *protocol = json_object_get_string(protocol_obj);
                    const char *value = json_object_get_string(right);

                    if (!protocol || !value) continue;

                    if (strcmp(protocol, "ip") == 0) {
                        ip = value;
                    } else if (strcmp(protocol, "ip6") == 0) {
                        ip = value;
                        is_ip6 = 1;
                    } else if (strcmp(protocol, "ether") == 0) {
                        mac = value;
                    }
                }
            }
        }
    }

    // Only update counters if we found both counter data and client identifiers
    if (has_counter && ip) {
        t_client *client = mac?client_list_find(ip, mac):client_list_find_by_ip(ip);
        if (client) {
            update_client_counters(client, packets, bytes, is_outgoing, is_ip6);
        } else {
            debug(LOG_DEBUG, "No client found for IP: %s, MAC: %s", 
                  ip ? ip : "N/A", mac ? mac : "N/A");
        }
    }
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
 * @brief Updates firewall counters by processing eBPF map statistics or nftables
 * 
 * This function first checks if eBPF maps are available in /sys/fs/bpf/tc/globals/
 * If eBPF maps are available, it uses them to get client traffic statistics.
 * If not, it falls back to the original nftables implementation.
 * 
 * @return 0 on success, -1 on failure
 */
int 
nft_fw_counters_update()
{
    NFT_WIFIDOGX_BYPASS_MODE_RETURN(0);

    if (is_portal_auth_disabled()) {
        debug(LOG_DEBUG, "Portal authentication is disabled, skip counters update");
        return 0;
    }

    LOCK_CLIENT_LIST();
    reset_client_list();

    // Check if eBPF maps are available
    if (access("/sys/fs/bpf/tc/globals/ipv4_map", F_OK) == 0) {
        debug(LOG_INFO, "Using eBPF maps for traffic statistics");
        return nft_fw_counters_update_ebpf();
    } else {
        debug(LOG_INFO, "eBPF maps not available, using nftables for traffic statistics");
        return nft_fw_counters_update_nftables();
    }
}

/**
 * @brief Updates firewall counters using eBPF map statistics
 * 
 * This function retrieves traffic statistics from the eBPF maps in the
 * /sys/fs/bpf/tc/globals/ directory and updates the client list accordingly.
 * 
 * @return 0 on success, -1 on failure
 */
static int
nft_fw_counters_update_ebpf()
{
    // Open IPv4 map
    int ipv4_map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/ipv4_map");
    if (ipv4_map_fd < 0) {
        debug(LOG_ERR, "Failed to open IPv4 map: %s", strerror(errno));
        UNLOCK_CLIENT_LIST();
        return -1;
    }

    // Process IPv4 traffic statistics
    __be32 ipv4_key = 0, next_ipv4_key = 0;
    struct traffic_stats ipv4_stats;
    
    while (bpf_map_get_next_key(ipv4_map_fd, ipv4_key ? &ipv4_key : NULL, &next_ipv4_key) == 0) {
        if (bpf_map_lookup_elem(ipv4_map_fd, &next_ipv4_key, &ipv4_stats) == 0) {
            // Convert IPv4 address to string
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &next_ipv4_key, ip_str, sizeof(ip_str))) {
                // Find client by IP
                t_client *client = client_list_find_by_ip(ip_str);
                if (client) {
                    // Update client counters
                    client->counters.incoming_bytes = ipv4_stats.incoming.total_bytes;
                    client->counters.incoming_packets = ipv4_stats.incoming.total_packets;
                    client->counters.incoming_rate = calc_rate_estimator(&ipv4_stats, true);
                    
                    client->counters.outgoing_bytes = ipv4_stats.outgoing.total_bytes;
                    client->counters.outgoing_packets = ipv4_stats.outgoing.total_packets;
                    client->counters.outgoing_rate = calc_rate_estimator(&ipv4_stats, false);
                    
                    client->counters.last_updated = time(NULL);
                    client->is_online = 1;
                    
                    // Initialize name if not set
                    if (!client->name) {
                        get_client_name(client);
                    }
                    
                    // Determine if client is on wired connection
                    if (client->wired == -1) {
                        client->wired = br_is_device_wired(client->mac);
                    }
                    
                    debug(LOG_DEBUG, "Updated IPv4 client: %s, IN: %llu bytes, OUT: %llu bytes", 
                          ip_str, ipv4_stats.incoming.total_bytes, ipv4_stats.outgoing.total_bytes);
                }
            }
        }
        ipv4_key = next_ipv4_key;
    }
    close(ipv4_map_fd);

    // Open IPv6 map
    int ipv6_map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/ipv6_map");
    if (ipv6_map_fd >= 0) {
        // Process IPv6 traffic statistics
        struct in6_addr ipv6_key, next_ipv6_key;
        struct traffic_stats ipv6_stats;
        int first_key = 1;
        
        memset(&ipv6_key, 0, sizeof(ipv6_key));
        
        while (bpf_map_get_next_key(ipv6_map_fd, first_key ? NULL : &ipv6_key, &next_ipv6_key) == 0) {
            first_key = 0;
            
            if (bpf_map_lookup_elem(ipv6_map_fd, &next_ipv6_key, &ipv6_stats) == 0) {
                // Convert IPv6 address to string
                char ip_str[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, &next_ipv6_key, ip_str, sizeof(ip_str))) {
                    // Find client by IPv6
                    t_client *client = client_list_find_by_ip(ip_str);
                    if (client) {
                        // Update client counters for IPv6
                        client->counters6.incoming_bytes = ipv6_stats.incoming.total_bytes;
                        client->counters6.incoming_packets = ipv6_stats.incoming.total_packets;
                        client->counters6.incoming_rate = calc_rate_estimator(&ipv6_stats, true);
                        
                        client->counters6.outgoing_bytes = ipv6_stats.outgoing.total_bytes;
                        client->counters6.outgoing_packets = ipv6_stats.outgoing.total_packets;
                        client->counters6.outgoing_rate = calc_rate_estimator(&ipv6_stats, false);
                        
                        client->counters6.last_updated = time(NULL);
                        client->is_online = 1;
                        
                        // Initialize name if not set
                        if (!client->name) {
                            get_client_name(client);
                        }
                        
                        // Determine if client is on wired connection
                        if (client->wired == -1) {
                            client->wired = br_is_device_wired(client->mac);
                        }
                        
                        debug(LOG_DEBUG, "Updated IPv6 client: %s, IN: %llu bytes, OUT: %llu bytes", 
                              ip_str, ipv6_stats.incoming.total_bytes, ipv6_stats.outgoing.total_bytes);
                    }
                }
            }
            memcpy(&ipv6_key, &next_ipv6_key, sizeof(ipv6_key));
        }
        close(ipv6_map_fd);
    } else {
        debug(LOG_WARNING, "Failed to open IPv6 map: %s", strerror(errno));
    }

    UNLOCK_CLIENT_LIST();
    return 0;
}

/**
 * @brief Updates firewall counters using nftables (original implementation)
 * 
 * This function uses the nftables JSON parsing approach to extract
 * traffic statistics. It's used as a fallback when eBPF maps are not available.
 * 
 * @return 0 on success, -1 on failure
 */
static int
nft_fw_counters_update_nftables()
{
    // get client outgoing traffic
    char *outgoing = NULL;
    uint32_t outgoing_len = 0;
    nft_statistical_outgoing(&outgoing, &outgoing_len);
    if (outgoing == NULL) {
        debug(LOG_ERR, "Failed to get outgoing traffic");
        UNLOCK_CLIENT_LIST();
        return -1;
    }
    debug(LOG_DEBUG, "outgoing: %s", outgoing);
    json_object *jobj_outgoing = json_tokener_parse(outgoing);
    if (jobj_outgoing == NULL) {
        debug(LOG_ERR, "Failed to parse outgoing json");
        free(outgoing);
        UNLOCK_CLIENT_LIST();
        return -1;
    }

    // Process outgoing traffic statistics
    process_nftables_json(jobj_outgoing, 0);
    json_object_put(jobj_outgoing);
    free(outgoing);

    // get client incoming traffic
    char *incoming = NULL;
    uint32_t incoming_len = 0;
    nft_statistical_incoming(&incoming, &incoming_len);
    if (incoming == NULL) {
        debug(LOG_ERR, "Failed to get incoming traffic");
        UNLOCK_CLIENT_LIST();
        return -1;
    }
    debug(LOG_DEBUG, "incoming: %s", incoming);
    json_object *jobj_incoming = json_tokener_parse(incoming);
    if (jobj_incoming == NULL) {
        debug(LOG_ERR, "Failed to parse incoming json");
        free(incoming);
        UNLOCK_CLIENT_LIST();
        return -1;
    }

    // Process incoming traffic statistics
    process_nftables_json(jobj_incoming, 1);
    json_object_put(jobj_incoming);
    free(incoming);

    UNLOCK_CLIENT_LIST();
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
    nftables_do_command("flush set inet wifidogx set_wifidogx_auth_servers");
    nftables_do_command("flush set inet wifidogx set_wifidogx_auth_servers_v6");
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
            nftables_do_command("add element inet wifidogx set_wifidogx_auth_servers { %s }", ips->ip);
        } else if (ips->ip_type == IP_TYPE_IPV6) {
            nftables_do_command("add element inet wifidogx set_wifidogx_auth_servers_v6 { %s }", ips->ip);
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
    nftables_do_command("flush set inet wifidogx set_wifidogx_inner_trust_domains");
    nftables_do_command("flush set inet wifidogx set_wifidogx_inner_trust_domains_v6");
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
                nftables_do_command("add element inet wifidogx set_wifidogx_inner_trust_domains { %s }", ip_trusted->ip);
            else if (ip_trusted->ip_type == IP_TYPE_IPV6)
                nftables_do_command("add element inet wifidogx set_wifidogx_inner_trust_domains_v6 { %s }", ip_trusted->ip);
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
            nftables_do_command("add element inet wifidogx set_wifidogx_trust_domains { %s }", ip_trusted->ip);
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
    nftables_do_command("flush set inet wifidogx set_wifidogx_trust_domains");
    nftables_do_command("flush set inet wifidogx set_wifidogx_trust_domains_v6");
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
__nft_fw_clear_wildcard_domains_trusted()
{
    nftables_do_command("flush set inet wifidogx set_wifidogx_wildcard_trust_domains");
    nftables_do_command("flush set inet wifidogx set_wifidogx_wildcard_trust_domains_v6");
}

static void
__nft_fw_set_wildcard_domains_trusted()
{
    const s_config *config = config_get_config();
    t_domain_trusted *domain_trusted = NULL;

    for (domain_trusted = config->wildcard_domains_trusted; domain_trusted != NULL; domain_trusted = domain_trusted->next) {
        t_ip_trusted *ip_trusted = NULL;
        for(ip_trusted = domain_trusted->ips_trusted; ip_trusted != NULL; ip_trusted = ip_trusted->next) {
            if (ip_trusted->ip_type == IP_TYPE_IPV4) {
                nftables_do_command("add element inet wifidogx set_wifidogx_wildcard_trust_domains { %s }", ip_trusted->ip);
            } else if (ip_trusted->ip_type == IP_TYPE_IPV6) {
                nftables_do_command("add element inet wifidogx set_wifidogx_wildcard_trust_domains_v6 { %s }", ip_trusted->ip);
            }
        }
    }
}

void
nft_fw_clear_wildcard_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_DOMAIN();
    __nft_fw_clear_wildcard_domains_trusted();
    UNLOCK_DOMAIN();
}

void
nft_fw_set_wildcard_domains_trusted()
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_DOMAIN();
    __nft_fw_clear_wildcard_domains_trusted();
    __nft_fw_set_wildcard_domains_trusted();
    UNLOCK_DOMAIN();
}

static void
__nft_fw_add_trusted_mac(const char *mac, int timeout)
{
    if (timeout == 0)
        nftables_do_command("add element inet wifidogx set_wifidogx_trust_clients_out { %s }", mac);
    else
        nftables_do_command("add element inet wifidogx set_wifidogx_trust_clients_out { %s timeout %ds}", mac, timeout);
    
    char cmd[128] = {0};
    snprintf(cmd, sizeof(cmd), "aw-bpfctl mac add %s", mac);
    execute(cmd, 0);
}

static void
__nft_fw_del_trusted_mac(const char *mac)
{
    nftables_do_command("delete element inet wifidogx set_wifidogx_trust_clients_out { %s }", mac);

    char cmd[128] = {0};
    snprintf(cmd, sizeof(cmd), "aw-bpfctl mac del %s", mac);
    execute(cmd, 0);
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
    nftables_do_command("flush set inet wifidogx set_wifidogx_trust_clients_out");
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
		nftables_do_command("add element inet wifidogx set_wifidogx_tmp_trust_clients { %s }", mac);
	} else if(which > 0) { // trusted
		if (which > 60*5)
			which = 60*5;
		nftables_do_command("add element inet wifidogx set_wifidogx_tmp_trust_clients { %s timeout %ds}", mac, which);
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
    nftables_do_command("add element inet wifidogx set_wifidogx_antinat_local_macs { %s }", mac);
    UNLOCK_CONFIG();
}

void
nft_fw_del_anti_nat_permit(const char *mac)
{
    NFT_WIFIDOGX_BYPASS_MODE();

    LOCK_CONFIG();
    nftables_do_command("delete element inet wifidogx set_wifidogx_antinat_local_macs { %s }", mac);
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

    nftables_do_command("add element inet wifidogx set_wifidogx_antinat_local_macs { %s }", config->anti_nat_permit_macs);
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
    
    // Check if portal auth is disabled
    if (is_portal_auth_disabled()) {
        debug(LOG_INFO, "Portal authentication is disabled, skip firewall initialization");
        return 1;
    }

	generate_nft_wifidogx_init_script();
	nft_do_init_script_command();
    nft_set_ext_interface();
    __nft_add_gw();
    __nft_fw_set_authservers();
    __nft_fw_set_trusted_maclist();
    __nft_fw_set_anti_nat_permit();
    
    // Add domain whitelist settings
    __nft_fw_set_user_domains_trusted();
    __nft_fw_set_wildcard_domains_trusted();
    __nft_fw_set_inner_domains_trusted();

    return 1;
}

int 
nft_check_core_rules(void)
{
    // Check if wifidogx table and core chains exist
    int ret = system("nft list table inet wifidogx > /dev/null 2>&1");
    if (ret != 0) return 0;
    
    // Check key chains
    if (system("nft list chain inet wifidogx prerouting > /dev/null 2>&1") != 0) return 0;
    if (system("nft list chain inet wifidogx forward > /dev/null 2>&1") != 0) return 0;
    if (system("nft list chain inet wifidogx wifidogx_redirect > /dev/null 2>&1") != 0) return 0;
    if (system("nft list chain inet wifidogx dstnat_wifidogx_unknown > /dev/null 2>&1") != 0) return 0;
    
    // Check forward sub-chains
    if (system("nft list chain inet wifidogx forward_wifidogx_wan > /dev/null 2>&1") != 0) return 0;
    if (system("nft list chain inet wifidogx forward_wifidogx_unknown > /dev/null 2>&1") != 0) return 0;

    // Check critical rules in wifidogx_redirect (redirects)
    if (system("nft list chain inet wifidogx wifidogx_redirect | grep -q 'redirect' > /dev/null 2>&1") != 0) return 0;

    // Check critical accept rules in forward_wifidogx_wan
    if (system("nft list chain inet wifidogx forward_wifidogx_wan | grep -q '@set_wifidogx_auth_servers' > /dev/null 2>&1") != 0) return 0;
    if (system("nft list chain inet wifidogx forward_wifidogx_wan | grep -q '@set_wifidogx_trust_domains' > /dev/null 2>&1") != 0) return 0;
    
    return 1; // Ready
}

int 
nft_reconcile_rules(void)
{
    debug(LOG_INFO, "Reconciling firewall rules...");
    return nft_fw_init();
}
