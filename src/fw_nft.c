/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
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
  @file fw_nft.c
  @brief firewall nftables functions
  @author Copyright (C) 2024 liudengfeng <liudf0716@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "debug.h"
#include "util.h"
#include "wd_util.h"
#include "fw_iptables.h"
#include "fw_nft.h"
#include "client_list.h"
#include "conf.h"
#include "dns_forward.h"
#include "gateway.h"


#define NFT_CONF_FILENAME "/etc/fw4_apfree-wifiodg_init.conf"
#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"


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

static void
replace_str(const char *content, const char *old_str, const char *new_str, char *out, int out_len)
{
    char *p = strstr(content, old_str);
    if (p == NULL) {
        strncpy(out, content, out_len);
        return;
    }

    int len = p - content;
    strncpy(out, content, len);
    out[len] = '\0';
    strncat(out, new_str, strlen(new_str));
    strncat(out, p + strlen(old_str), out_len - len - strlen(new_str));
}

static void
generate_nft_wifidogx_init_script()
{
    s_config *config = config_get_config();
    t_gateway_setting *gw_settings = get_gateway_settings();
    FILE* output_file = NULL;
    int i;
    char buf[1024] = {0};

    // Open the output file for writing
    output_file = fopen(NFT_FILENAME_OUT, "w");
    if (output_file == NULL) {
        debug(LOG_ERR, "Failed to open %s for writing", NFT_FILENAME_OUT);
        termination_handler(0);
    }

    for (i = 0; i < sizeof(nft_wifidogx_init_script) / sizeof(nft_wifidogx_init_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_init_script[i]);
        memset(buf, 0, sizeof(buf));
    }

    for (i = 0; i < sizeof(nft_wifidogx_dns_pass_script) / sizeof(nft_wifidogx_dns_pass_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_dns_pass_script[i]);
    }

    for (i = 0; i < sizeof(nft_wifidogx_dhcp_pass_script) / sizeof(nft_wifidogx_dhcp_pass_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_dhcp_pass_script[i]);
    }
    
    if (config->enable_dns_forward) {
        while(gw_settings) {
           
            for (i = 0; i < sizeof(nft_wifidogx_dns_redirect_script) / sizeof(nft_wifidogx_dns_redirect_script[0]); i++) {
                const char *p = nft_wifidogx_dns_redirect_script[i];
                if (strstr(p, "$interface$")) {
                    replace_str(p, "$interface$", gw_settings->gw_interface, buf, sizeof(buf));
                    fprintf(output_file, "%s\n", buf);
                } else {
                    fprintf(output_file, "%s\n", p);
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

// statistical outgoing information,must free when statistical is over
void
nft_statistical_outgoing(char *outgoing, uint32_t outgoing_len)
{
	FILE *r_fp = NULL;
	char *cmd = "nft -j list chain inet fw4 mangle_prerouting_wifidogx_outgoing";
    debug(LOG_DEBUG, "nft -j list chain inet fw4 mangle_prerouting_wifidogx_outgoing");
	r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, "popen failed");
        return;
    }
	fgets(outgoing, outgoing_len, r_fp);
	pclose(r_fp);
}

void
nft_statistical_incoming(char *incoming, uint32_t incoming_len)
{
	FILE *r_fp = NULL;
	char *cmd = "nft -j list chain inet fw4 mangle_postrouting_wifidogx_incoming";
    debug(LOG_DEBUG, "nft -j list chain inet fw4 mangle_postrouting_wifidogx_incoming");
	r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, "popen failed");
        return;
    }
	fgets(incoming, incoming_len, r_fp);
	pclose(r_fp);
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
nft_init()
{
	generate_nft_wifidogx_init_script();
	nft_do_init_script_command();
    nft_add_gw();
    nft_set_ext_interface();
    iptables_fw_set_authservers(NULL);

    return 1;
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

    FILE *r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, "popen failed");
        return;
    }

    char buf[4096];
    if (fgets(buf, sizeof(buf), r_fp) == NULL) {
        debug(LOG_ERR, "fgets failed");
        pclose(r_fp);
        return;
    }
    pclose(r_fp);

    debug(LOG_DEBUG, "buf: %s", buf);

    json_object *jobj = json_tokener_parse(buf);
    if (jobj == NULL) {
        debug(LOG_ERR, "json_tokener_parse failed");
        return;
    }

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
            run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s counter mark set 0x20000 accept", mac, ip);
            run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter mark set 0x20000 accept", ip);
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

/** Reload client's firewall rules */
int 
nft_fw_reload_client()
{
#define NFT_WIFIDOGX_CLIENT_LIST "/tmp/nftables_wifidogx_client_list"

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
