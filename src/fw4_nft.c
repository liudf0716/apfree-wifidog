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


#define NFT_CONF_FILENAME "/etc/fw4_apfree-wifiodg_init.conf"
#define NFT_FILENAME_OUT "/tmp/fw4_apfree-wifiodg_init.conf.out"

/* utils function */
static int 
replace_variables(const char* gateway_ip, const char* interface) 
{
    // check whether the input parameters are valid
    // is auth_server_ip valid ipv4 address?
    if (!is_valid_ip(gateway_ip)) {
        debug(LOG_ERR, "Invalid  gateway_ip: %s", gateway_ip);
        return -3;
    }

    FILE* input_file = NULL;
    FILE* output_file = NULL;
    char line[1024] = {0};
    char buf[1024] = {0};
    int len;
    
    // if file NFT_CONF_FILENAME does not exist, return
    if (access(NFT_CONF_FILENAME, F_OK) != 0) {
        debug(LOG_ERR, "File %s does not exist", NFT_CONF_FILENAME);
        return -1;
    }

    // Open the input file for reading
    input_file = fopen(NFT_CONF_FILENAME, "r");
    if (input_file == NULL) {
        debug(LOG_ERR, "Failed to open file %s", NFT_CONF_FILENAME);
        return -1;
    }
    
    // Open the output file for writing
    output_file = fopen(NFT_FILENAME_OUT, "w");
    if (output_file == NULL) {
        debug(LOG_ERR, "Failed to open file %s", NFT_FILENAME_OUT);
        fclose(input_file);
        return -2;
    }
    
    // Read the input file line by line
    while (fgets(line, sizeof(line), input_file) != NULL) {
        // Replace $auth_server_ip$ with auth_server_ip
        strncpy(buf, line, sizeof(buf));
        len = strlen(buf);
        
        // Replace $gateway_ip$ with gateway_ip
        //len = strlen(buf);
        for (int i = 0; i < len - strlen("$gateway_ip$"); i++) {
            if (strncmp(buf + i, "$gateway_ip$", strlen("$gateway_ip$")) == 0) {
                strncpy(buf + i, gateway_ip, strlen(gateway_ip));
                strncpy(buf + i + strlen(gateway_ip), line + i + strlen("$gateway_ip$"), sizeof(buf));
                break;
            }
        }
        
        // Replace $interface$ with interface
        //len = strlen(buf);
        for (int i = 0; i < len - strlen("$interface$") ; i++) {
            if (strncmp(buf + i, "$interface$", strlen("$interface$")) == 0) {
                strncpy(buf + i, interface, strlen(interface));
                strncpy(buf + i + strlen(interface), line + i + strlen("$interface$"), sizeof(buf));
                break;
            }
        }
        
        // Write the replaced line to the output file
        fputs(buf, output_file);
        memset(line, 0, sizeof(line));
        memset(buf, 0, sizeof(buf));
    }
    
    // Close the input and output files
    fclose(input_file);
    fclose(output_file);
    // Return the output file

    return 0;
}

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
    
    return execute(buf, 1);
}
/* end of utils function */

// run nft script
static int 
nft_do_init_script_command()
{
	return run_cmd("nft -f %s", NFT_FILENAME_OUT);
}


// set ip outgoing clearance
static int 
nft_do_outgoging_allow_command(char *mac_addr, char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter mark set 0x20000 accept", mac_addr, ip_addr);
}
// set ip incoming clearance
static int 
nft_do_incoming_allow_command(char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter accept", ip_addr);
}
// set ip outgoing ban
static int 
nft_do_outgoging_ban_command(char *mac_addr, char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter mark set 0x20000 drop", mac_addr, ip_addr);
}
// set ip incoming ban
static int 
nft_do_incoming_ban_command(char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter drop", ip_addr);
}



// statistical outgoing information,must free when statistical is over
void
nft_statistical_outgoing(char *outgoing, uint32_t outgoing_len)
{
	FILE *r_fp = NULL;
	char *cmd = "nft -j list chain inet fw4 mangle_prerouting_wifidogx_outgoing";
	r_fp = popen(cmd, "r");
	fgets(outgoing, outgoing_len, r_fp);
	pclose(r_fp);
}

void
nft_statistical_incoming(char *incoming, uint32_t incoming_len)
{
	FILE *r_fp = NULL;
	char *cmd = "nft -j list chain inet fw4 mangle_postrouting_wifidogx_incoming";
	r_fp = popen(cmd, "r");
	fgets(incoming, incoming_len, r_fp);
	pclose(r_fp);
}



/** Initialize the firewall rules
*/
int 
nft_init(const char *gateway_ip, const char* interface)
{
	// firewall_init_bak.nft don't modify it
	// system("rm -f /conf/firewall_init.nft && cp -f /conf/firewall_init_bak.nft /conf/firewall_init.nft")
	int ret = replace_variables(gateway_ip, interface);
	if (ret != 0) {
        debug(LOG_ERR, "Failed to replace variables in %s", NFT_CONF_FILENAME);
        return -1;
    }

	nft_do_init_script_command();

    // add auth server ip to firewall
    iptables_fw_set_authservers(NULL);

    return 0;
}


/** Set if a specific client has access through the firewall */
int 
nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag)

{
	int rc = 0;

	switch (type) {
	case FW_ACCESS_ALLOW:
		nft_do_outgoging_allow_command((char*)mac, (char*)ip);
		nft_do_incoming_allow_command((char*)ip);
		break;
	case FW_ACCESS_DENY:
		/* XXX Add looping to really clear? */
		nft_do_outgoging_ban_command((char*)mac, (char*)ip);
		nft_do_incoming_ban_command((char*)ip);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

