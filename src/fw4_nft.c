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
  @file fw3_iptc.h
  @brief libiptc api.
  @author Copyright (C) 2023 helintongh <agh6399@gmail.com>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "debug.h"
#include "util.h"
#include "wd_util.h"
#include "fw_iptables.h"
#include "fw4_nft.h"
#include "client_list.h"
#include "conf.h"


#define NFT_CONF_FILENAME "/etc/fw4_apfree-wifiodg_init.conf"
#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"

/*
 * change the following script to char * array
 * 
 * `add set inet fw4 set_wifidogx_auth_servers { type ipv4_addr; }
add set inet fw4 set_wifidogx_gateway { type ipv4_addr; }
add set inet fw4 set_wifidogx_trust_domains { type ipv4_addr; }
add set inet fw4 set_wifidogx_inner_trust_domains { type ipv4_addr; }
add set inet fw4 set_wifidogx_trust_clients { type ether_addr; }
add set inet fw4 set_wifidogx_tmp_trust_clients { type ether_addr; flags timeout; timeout 5m; }

add chain inet fw4 dstnat_wifidogx_auth_server
add chain inet fw4 dstnat_wifidogx_wan
add chain inet fw4 dstnat_wifidogx_outgoing
add chain inet fw4 dstnat_wifidogx_trust_domains
add chain inet fw4 dstnat_wifidogx_unknown
add rule inet fw4 dstnat iifname $interface$ jump dstnat_wifidogx_outgoing
add rule inet fw4 dstnat_wifidogx_outgoing ip daddr @set_wifidogx_gateway accept
add rule inet fw4 dstnat_wifidogx_outgoing jump dstnat_wifidogx_wan
add rule inet fw4 dstnat_wifidogx_wan meta mark 0x20000 accept
add rule inet fw4 dstnat_wifidogx_wan meta mark 0x10000 accept
add rule inet fw4 dstnat_wifidogx_wan jump dstnat_wifidogx_unknown
add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_auth_server
add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_trust_domains
add rule inet fw4 dstnat_wifidogx_unknown tcp dport 443 redirect to  8443
add rule inet fw4 dstnat_wifidogx_unknown tcp dport 80 redirect to  2060
add rule inet fw4 dstnat_wifidogx_auth_server ip daddr @set_wifidogx_auth_servers accept
add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept
add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept

add chain inet fw4 forward_wifidogx_auth_servers
add chain inet fw4 forward_wifidogx_wan
add chain inet fw4 forward_wifidogx_trust_domains
add chain inet fw4 forward_wifidogx_unknown
add chain inet fw4 mangle_prerouting_wifidogx_outgoing
add chain inet fw4 mangle_postrouting_wifidogx_incoming
insert rule inet fw4 accept_to_wan jump forward_wifidogx_wan
add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_auth_servers
add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_trust_domains
add rule inet fw4 forward_wifidogx_wan meta mark 0x10000 accept
add rule inet fw4 forward_wifidogx_wan meta mark 0x20000 accept
add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_unknown
add rule inet fw4 forward_wifidogx_auth_servers ip daddr @set_wifidogx_auth_servers accept
add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept
add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept
add rule inet fw4 forward_wifidogx_unknown udp dport 53 accept
add rule inet fw4 forward_wifidogx_unknown tcp dport 53 accept
add rule inet fw4 forward_wifidogx_unknown udp dport 67 accept
add rule inet fw4 forward_wifidogx_unknown tcp dport 67 accept

add rule inet fw4 mangle_prerouting iifname "br-lan" udp dport 67 queue num 42

add rule inet fw4 mangle_prerouting iifname $interface$ jump mangle_prerouting_wifidogx_outgoing
add rule inet fw4 mangle_postrouting oifname $interface$ jump mangle_postrouting_wifidogx_incoming` 
 */
const char *nft_wifidogx_init_script[] = {
    "add table inet wifidogx",
    "add chain  inet wifidogx prerouting{ type nat hook prerouting priority 0; policy accept; }",
    "add chain  inet wifidogx mangle_prerouting { type filter hook postrouting priority 0; policy accept; }",
    "add set inet fw4 set_wifidogx_auth_servers { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_gateway { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_trust_domains { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_inner_trust_domains { type ipv4_addr; }",
    "add set inet fw4 set_wifidogx_bypass_clients { type ipv4_addr; flags interval; }",
    "add set inet fw4 set_wifidogx_trust_clients { type ether_addr; }",
    "add set inet fw4 set_wifidogx_tmp_trust_clients { type ether_addr; flags timeout; timeout 5m; }",
    "add chain inet fw4 dstnat_wifidogx_auth_server",
    "add chain inet fw4 dstnat_wifidogx_wan",
    "add chain inet fw4 dstnat_wifidogx_outgoing",
    "add chain inet fw4 dstnat_wifidogx_trust_domains",
    "add chain inet fw4 dstnat_wifidogx_unknown",
    "add rule inet fw4 dstnat iifname $interface$ jump dstnat_wifidogx_outgoing",
    "add rule inet fw4 dstnat_wifidogx_outgoing ip daddr @set_wifidogx_gateway accept",
    "add rule inet fw4 dstnat_wifidogx_outgoing jump dstnat_wifidogx_wan",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ether saddr @set_wifidogx_trust_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet fw4 dstnat_wifidogx_wan meta mark 0x20000 accept",
    "add rule inet fw4 dstnat_wifidogx_wan meta mark 0x10000 accept",
    "add rule inet fw4 dstnat_wifidogx_wan jump dstnat_wifidogx_unknown",
    "add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_auth_server",
    "add rule inet fw4 dstnat_wifidogx_unknown jump dstnat_wifidogx_trust_domains",
    "add rule inet fw4 dstnat_wifidogx_unknown tcp dport 443 redirect to  8443",
    "add rule inet fw4 dstnat_wifidogx_unknown tcp dport 80 redirect to  2060",
    "add rule inet fw4 dstnat_wifidogx_auth_server ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet fw4 dstnat_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept",
    "add chain inet fw4 forward_wifidogx_auth_servers",
    "add chain inet fw4 forward_wifidogx_wan",
    "add chain inet fw4 forward_wifidogx_trust_domains",
    "add chain inet fw4 forward_wifidogx_unknown",
    "add chain inet fw4 mangle_prerouting_wifidogx_dhcp_cpi",
    "add chain inet fw4 mangle_prerouting_wifidogx_outgoing",
    "add chain inet fw4 mangle_postrouting_wifidogx_incoming",
    "insert rule inet fw4 accept_to_wan jump forward_wifidogx_wan",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_auth_servers",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_trust_domains",
    "add rule inet fw4 forward_wifidogx_wan ether saddr @set_wifidogx_tmp_trust_clients accept",
    "add rule inet fw4 forward_wifidogx_wan ether saddr @set_wifidogx_trust_clients accept",
    "add rule inet fw4 forward_wifidogx_wan ip saddr @set_wifidogx_bypass_clients accept",
    "add rule inet fw4 forward_wifidogx_wan meta mark 0x10000 accept",
    "add rule inet fw4 forward_wifidogx_wan meta mark 0x20000 accept",
    "add rule inet fw4 forward_wifidogx_wan jump forward_wifidogx_unknown",
    "add rule inet fw4 forward_wifidogx_auth_servers ip daddr @set_wifidogx_auth_servers accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_trust_domains accept",
    "add rule inet fw4 forward_wifidogx_trust_domains ip daddr @set_wifidogx_inner_trust_domains accept",
    "add rule inet fw4 mangle_prerouting iifname $interface$ jump mangle_prerouting_wifidogx_dhcp_cpi", 
    "add rule inet fw4 mangle_prerouting iifname $interface$ jump mangle_prerouting_wifidogx_outgoing",
    "add rule inet fw4 mangle_postrouting oifname $interface$ jump mangle_postrouting_wifidogx_incoming",
    "add element inet fw4 set_wifidogx_gateway { $gateway_ip$ }",
};

const char *nft_wifidogx_dhcp_pass_script[] = {
    "add rule inet fw4 forward_wifidogx_unknown udp dport 67 accept",
    "add rule inet fw4 forward_wifidogx_unknown tcp dport 67 accept",
};

const char *nft_wifidogx_dns_pass_script[] = {
    "add rule inet fw4 forward_wifidogx_unknown udp dport 53 accept",
    "add rule inet fw4 forward_wifidogx_unknown tcp dport 53 accept",
};

const char *nft_wifidogx_dhcp_redirect_script[] = {
    "add rule inet wifidogx prerouting iifname $interface$ udp dport 67 counter redirect to  15367",
    "add rule inet wifidogx prerouting iifname $interface$ tcp dport 67 counter redirect to  15367",
};

const char *nft_wifidogx_dns_redirect_script[] = {
    "add rule inet wifidogx prerouting iifname $interface$ udp dport 53 counter redirect to  15353",
    "add rule inet wifidogx prerouting iifname $interface$ tcp dport 53 counter redirect to  15353",
};

static void
replace_str(const char *content, const char *old_str, const char *new_str, char *out, int out_len)
{
    // find the old_str in content
    // if found, replace the old_str with new_str
    // and copy the result to out

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

// the nftables script for wifidogx
// the script is used to configure the nftables
// the script is generated by the function generate_nft_wifidogx_init_script
// the function generate NFT_FILENAME_OUT file which is used to configure the nftables
// the NFT_FILENAME_OUT file come from nft_wifidogx_init_script
// in nft_wifidogx_init_script, the variables $interface$ is replaced by the real values
// the real value from the input parameters
static int
generate_nft_wifidogx_init_script(const char* gateway_ip, const char* interface)
{
    s_config *config = config_get_config();
    // if gateway_ip is invalid ip address, return -1
    if (is_valid_ip(gateway_ip) == 0) {
        debug(LOG_ERR, "Invalid gateway ip address: %s", gateway_ip);
        return -1;
    }

    FILE* output_file = NULL;
    int i;
    char buf[1024] = {0};

    // Open the output file for writing
    output_file = fopen(NFT_FILENAME_OUT, "w");
    if (output_file == NULL) {
        debug(LOG_ERR, "Failed to open %s for writing", NFT_FILENAME_OUT);
        return -1;
    }

    // write the nftables script to the output file
    for (i = 0; i < sizeof(nft_wifidogx_init_script) / sizeof(nft_wifidogx_init_script[0]); i++) {
        const char *p = nft_wifidogx_init_script[i];
        // if p contains $gateway_ip$, replace $gateway_ip$ with the real value
        if (strstr(p, "$gateway_ip$")) {
            replace_str(p, "$gateway_ip$", gateway_ip, buf, sizeof(buf));
            fprintf(output_file, "%s\n", buf);
        } else if (strstr(p, "$interface$")) {
            // if p contains $interface$, replace $interface$ with the real value
            replace_str(p, "$interface$", interface, buf, sizeof(buf));
            fprintf(output_file, "%s\n", buf);
        } else {
            // if p does not contain $gateway_ip$ and $interface$, write p to the output file
            fprintf(output_file, "%s\n", p);
        }
        memset(buf, 0, sizeof(buf));
    }

    if (!config->enable_dns_forward) {
        for (i = 0; i < sizeof(nft_wifidogx_dns_pass_script) / sizeof(nft_wifidogx_dns_pass_script[0]); i++) {
            fprintf(output_file, "%s\n", nft_wifidogx_dns_pass_script[i]);
        }
    } else {
        for (i = 0; i < sizeof(nft_wifidogx_dns_redirect_script) / sizeof(nft_wifidogx_dns_redirect_script[0]); i++) {
            const char *p = nft_wifidogx_dns_redirect_script[i];
            if (strstr(p, "$interface$")) {
                replace_str(p, "$interface$", interface, buf, sizeof(buf));
                fprintf(output_file, "%s\n", buf);
            } else {
                fprintf(output_file, "%s\n", p);
            }
        }
    }

    for (i = 0; i < sizeof(nft_wifidogx_dhcp_pass_script) / sizeof(nft_wifidogx_dhcp_pass_script[0]); i++) {
        fprintf(output_file, "%s\n", nft_wifidogx_dhcp_pass_script[i]);
    }

    fclose(output_file);
    return 0;
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
    
    int nret = system(buf);
    // if nret is -1, it means the system call failed
    if (nret == -1) {
        debug(LOG_ERR, "system call failed");
        return -1;
    }
    return nret;
}
/* end of utils function */

// run nft script
static int 
nft_do_init_script_command()
{
	run_cmd("nft -f %s", NFT_FILENAME_OUT);
    return 1;
}

static void
nft_set_dhcp_cpi(const char *interface)
{
    // add rule inet fw4 mangle_prerouting iifname $interface$ udp dport 67 queue num 42
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), 
        "nft add rule inet wifidogx mangle_prerouting iifname %s udp dport 67 queue num 42", interface);
    debug (LOG_DEBUG, "cmd: %s", cmd);
    int nret = system(cmd);
    if (nret == -1) {
        debug(LOG_ERR, "system call [%s] failed", cmd);
    }
}

static void
nft_set_bypass_auth(const char *gateway_ip)
{
    // add gateway_ip to set_wifidogx_bypass_clients
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_bypass_clients { %s/24 }", gateway_ip);
    debug (LOG_DEBUG, "cmd: %s", cmd);
    int nret = system(cmd);
    if (nret == -1) {
        debug(LOG_ERR, "system call [%s] failed", cmd);
    }
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



/** Initialize the firewall rules
*/
int 
nft_init(const char *gateway_ip, const char* interface)
{
    s_config *config = config_get_config();
	// generate nftables wifidogx init script
	int ret = generate_nft_wifidogx_init_script(gateway_ip, interface);
	if (ret != 0) {
        debug(LOG_ERR, "Failed to replace variables in %s", NFT_CONF_FILENAME);
        return 0;
    }

	nft_do_init_script_command();

    // add auth server ip to firewall
    iptables_fw_set_authservers(NULL);

    if (config->enable_dhcp_cpi)
        nft_set_dhcp_cpi(interface);

    if (config->enable_bypass_auth)
        nft_set_bypass_auth(gateway_ip);

    return 1;
}

/*
 * the function is used to parse the json array object
 * the json array object is like this:
`
    [
        {
            "match": {
            "op": "==",
            "left": {
                "payload": {
                    "protocol": "ip",
                    "field": "daddr"
                }
            },
            "right": "192.168.1.18"
            }
        },
        {
            "match": {
            "op": "==",
            "left": {
                "payload": {
                    "protocol": "ether",
                    "field": "daddr"
                }
            },
            "right": "00:00:00:00:00:00"
        },
        {
            "counter": {
            "packets": 0,
            "bytes": 0
            }
        },
        {
        "accept": null
        }
    ]
      
`
 * the function has three parameters:
 * 1. the json array object
 * 2. the ip address
 * 3. the mac address
 * the function will return 1 if the json array object contains the ip address and mac address
 * the function will return 0 if the json array object does not contain the ip address and mac address
 */
static int
check_nft_expr_json_array_object(json_object *jobj, const char *ip, const char *mac)
{
    // get the array length
    int arraylen = json_object_array_length(jobj);
    int i = 0;
    int ip_flag = 0;
    int mac_flag = 0;
    if (mac == NULL) {
        // do not check mac address
        mac_flag = 1;
    }
    // iterate the array
    for (i = 0; i < arraylen; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj, i);
        json_object *jobj_item_match = NULL;
        if (json_object_object_get_ex(jobj_item, "match", &jobj_item_match)) {
            // if the item contains "match", get the "match" object
            json_object *jobj_item_match_left = NULL;
            json_object *jobj_item_match_right = NULL;
            if (json_object_object_get_ex(jobj_item_match, "left", &jobj_item_match_left)) {
                // if the "match" object contains "left", get the "left" object
                json_object *jobj_item_match_left_payload = NULL;
                if (json_object_object_get_ex(jobj_item_match_left, "payload", &jobj_item_match_left_payload)) {
                    // if the "left" object contains "payload", get the "payload" object
                    json_object *jobj_item_match_left_payload_protocol = NULL;
                    if (json_object_object_get_ex(jobj_item_match_left_payload, "protocol", &jobj_item_match_left_payload_protocol)) {
                        // if the "payload" object contains "protocol", get the "protocol" value
                        const char *protocol = json_object_get_string(jobj_item_match_left_payload_protocol);
                        if (strcmp(protocol, "ether") == 0) {
                            // if the "protocol" value is "ether", get the "right" value
                            if (json_object_object_get_ex(jobj_item_match, "right", &jobj_item_match_right)) {
                                const char *right = json_object_get_string(jobj_item_match_right);
                                if (strcmp(right, mac) == 0) {
                                    // if the "right" value is the mac address, return 1
                                    mac_flag = 1;
                                }
                            }
                        } else if (strcmp(protocol, "ip") == 0) {
                            // if the "protocol" value is "ip", get the "right" value
                            if (json_object_object_get_ex(jobj_item_match, "right", &jobj_item_match_right)) {
                                const char *right = json_object_get_string(jobj_item_match_right);
                                if (strcmp(right, ip) == 0) {
                                    // if the "right" value is the ip address, return 1
                                    ip_flag = 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // if ip_flag and mac_flag are both 1, return 1
        if (ip_flag == 1 && mac_flag == 1) {
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
    // iterate chain mangle_prerouting_wifidogx_outgoing, 
    // if the rule contains the ip and mac, delete the rule
    // first get the rule list of chain mangle_prerouting_wifidogx_outgoing
    char cmd[256] = {0};
    snprintf(cmd, sizeof(cmd), "nft -j list chain inet fw4 %s", chain);
    debug(LOG_DEBUG, " cmd: %s", cmd);
    // throught popen, get the rule list of chain mangle_prerouting_wifidogx_outgoing
    FILE *r_fp = popen(cmd, "r");
    if (r_fp == NULL) {
        debug(LOG_ERR, " popen failed");
        return;
    }
    char buf[4096] = {0};
    // read the rule list of chain mangle_prerouting_wifidogx_outgoing
    fgets(buf, sizeof(buf), r_fp);
    pclose(r_fp);
    debug(LOG_DEBUG, " buf: %s", buf);
    // parse the rule list of chain mangle_prerouting_wifidogx_outgoing
    // use libjson-c to parse the rule list of chain mangle_prerouting_wifidogx_outgoing
    json_object *jobj = json_tokener_parse(buf);
    if (jobj == NULL) {
        debug(LOG_ERR, " jobj is NULL");
        return;
    }
    // get the "nftables" json object which is an array of json objects
	json_object *jobj_nftables = NULL;
	if (!json_object_object_get_ex(jobj, "nftables", &jobj_nftables)) {
		debug(LOG_ERR, " jobj_nftables is NULL");
		goto END_DELETE_CLIENT;
	}
    // iterate the array of json objects to find the rule which contains the ip and mac
    int i = 0;
    int len = json_object_array_length(jobj_nftables);
    for (i = 0; i < len; i++) {
        json_object *jobj_item = json_object_array_get_idx(jobj_nftables, i);
        if (jobj_item == NULL) {
            debug(LOG_ERR, " jobj_item is NULL");
            continue;
        }
        // get the "rule" json object which is an array of json objects
        json_object *jobj_rule = NULL;
        if (!json_object_object_get_ex(jobj_item, "rule", &jobj_rule)) {
            debug(LOG_ERR, "jobj_rule is NULL");
            continue;
        }
        // get the "expr" json object which is an array of json objects
        json_object *jobj_rule_expr = NULL;
        if (!json_object_object_get_ex(jobj_rule, "expr", &jobj_rule_expr)) {
            debug(LOG_ERR, "jobj_rule_expr is NULL");
            continue;
        }
        // use the function check_nft_expr_json_array_object to check if the rule contains the ip and mac
        if (check_nft_expr_json_array_object(jobj_rule_expr, ip, mac) == 1) {
            // if the rule contains the ip and mac, get the "handle" value
            json_object *jobj_rule_handle = NULL;
            if (!json_object_object_get_ex(jobj_rule, "handle", &jobj_rule_handle)) {
                debug(LOG_ERR, "jobj_rule_handle is NULL");
                continue;
            }
            const char *handle = json_object_get_string(jobj_rule_handle);
            // delete the rule
            char cmd[256] = {0};
            snprintf(cmd, sizeof(cmd), "nft delete rule inet fw4 %s handle %s", chain, handle);
            run_cmd(cmd);
        }
    }

END_DELETE_CLIENT:
    json_object_put(jobj);
}

/** Set if a specific client has access through the firewall */
int
nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)
{
    // according to type, if type is FW_ACCESS_ALLOW, set the firewall rules to allow the client
    // if type is FW_ACCESS_DENY, set the firewall rules to deny the client

    // the rules are as the following:
    // add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr ab:23:23:ab:23:23 ip saddr
    // add rule inet fw4 mangle_postrouting_wifidogx_incoming ether saddr ab:23:23:ab:23:23 ip saddr
    switch(type) {
        case FW_ACCESS_ALLOW:
            run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s counter mark set 0x20000 accept", mac, ip);
            run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter mark set 0x20000 accept", ip);
            break;
        case FW_ACCESS_DENY:
            nft_fw_del_rule_by_ip_and_mac(ip, mac, "mangle_prerouting_wifidogx_outgoing");
            nft_fw_del_rule_by_ip_and_mac(ip, NULL, "mangle_postrouting_wifidogx_incoming");
            break;
        default:
            debug(LOG_ERR, "Unknown fw_access type %d", type);
            return 1;
    }
    return 0;
}

/** Reload client's firewall rules */
int 
nft_fw_reload_client(int tag)
{
#define NFT_WIFIDOGX_CLIENT_LIST "/tmp/nftables_wifidogx_client_list"
    // the function nft_fw_access is used to set the firewall rules
    // the rules are as the following:
    // add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr ab:23:23:ab:23:23 ip saddr
	// iterate client_list and get its ip and mac
    // using the ip and mac to set the firewall rules
    // the rules are as the following:
    // add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr ab:23:23:ab:23:23 ip saddr 192.168.1.18 counter mark set 0x20000 accept
    // add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr 192.168.1.18 counter accept
    // save the rules to the file /tmp/nftables_wifidogx_client_list
    // afte saving the rules, run the script /tmp/nftables_wifidogx_client_list to set the rules
    // the rules are as the following:
    // nft -f /tmp/nftables_wifidogx_client_list

    t_client *first_client = client_get_first_client();
    if (first_client == NULL) {
        debug(LOG_ERR, "No clients in list!");
        return 1;
    }

    // open the file /tmp/nftables_wifidogx_client_list
    // define the file /tmp/nftables_wifidogx_client_list as NFT_WIFIDOGX_CLIENT_LIST
    FILE *fp = fopen(NFT_WIFIDOGX_CLIENT_LIST, "w");
    if (fp == NULL) {
        debug(LOG_ERR, "Failed to open %s", NFT_WIFIDOGX_CLIENT_LIST);
        return 1;
    }
    // flush the rules in the chain mangle_prerouting_wifidogx_outgoing
    fprintf(fp, "nft flush chain inet fw4 mangle_prerouting_wifidogx_outgoing\n");
    // flush the rules in the chain mangle_postrouting_wifidogx_incoming
    fprintf(fp, "nft flush chain inet fw4 mangle_postrouting_wifidogx_incoming\n");
    // iterate the client_list
    t_client *current = first_client;
    char line[256] = {0};
    do {
        snprintf(line, sizeof(line), "nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter mark set 0x%02x0000/0xff0000 accept\n", current->mac, current->ip, tag&0x000000ff);
        // write the line to the file /tmp/nftables_wifidogx_client_list
        fprintf(fp, "%s", line);
        memset(line, 0, sizeof(line));
        snprintf(line, sizeof(line), "nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter accept\n", current->ip);
        // write the line to the file /tmp/nftables_wifidogx_client_list
        fprintf(fp, "%s", line);
        memset(line, 0, sizeof(line));
        current = current->next;
    } while (current != NULL);
    fclose(fp);

    return 0;
}


