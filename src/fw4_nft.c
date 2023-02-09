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
#include "fw4_nft.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define NFT_CONF_FILENAME "/conf/firewall_init.nft"

/* utils function */
int replace_variables(const char* auth_server_ip, const char* gateway_ip, const char* interface, const char* filename) 
{
    // ip check
    if (strlen(auth_server_ip) > 15 && strlen(auth_server_ip) < 7)
        return -3;

    if (strlen(gateway_ip) > 15 && strlen(gateway_ip) < 7)
        return -3;

    FILE* input_file;
    FILE* output_file;
    char line[1024];
    char buf[1024];
    char output_filename[1024];
    int len;
    
    // Open the input file for reading
    input_file = fopen(filename, "r");
    if (input_file == NULL) {
        return -1;
    }
    
    // Create the output file name by appending ".out" to the input file name
    strncpy(output_filename, filename, sizeof(output_filename));
    strncat(output_filename, ".out", 5);
    
    // Open the output file for writing
    output_file = fopen(output_filename, "w");
    if (output_file == NULL) {
        fclose(input_file);
        return -2;
    }
    
    // Read the input file line by line
    while (fgets(line, sizeof(line), input_file) != NULL) {
        // Replace $auth_server_ip$ with auth_server_ip
        strncpy(buf, line, sizeof(buf));
        len = strlen(buf);
        for (int i = 0; i < len - 16; i++) {
            if (strncmp(buf + i, "$auth_server_ip$", 16) == 0) {
                strncpy(buf + i, auth_server_ip, sizeof(buf));
                strncpy(buf + i + strlen(auth_server_ip), line + i + 16, sizeof(buf));
                break;
            }
        }
        
        // Replace $gateway_ip$ with gateway_ip
        //len = strlen(buf);
        for (int i = 0; i < len - 12; i++) {
            if (strncmp(buf + i, "$gateway_ip$", 12) == 0) {
                strncpy(buf + i, gateway_ip, sizeof(buf));
                strncpy(buf + i + strlen(gateway_ip), line + i + 12, sizeof(buf));
                break;
            }
        }
        
        // Replace $interface$ with interface
        //len = strlen(buf);
        for (int i = 0; i < len - 11 ; i++) {
            if (strncmp(buf + i, "$interface$", 11) == 0) {
                strncpy(buf + i, interface, sizeof(buf));
                strncpy(buf + i + strlen(interface), line + i + 11, sizeof(buf));
                break;
            }
        }
        
        // Write the replaced line to the output file
        fputs(buf, output_file);
    }
    
    // Close the input and output files
    fclose(input_file);
    fclose(output_file);
    // Return the output file

    return 0;
}

int run_cmd(char *cmd, ...)
{
    va_list ap;//声明命名参数
    char buf[CMDBUFLEN];
    va_start(ap, cmd);//va_start宏允许访问命名参数parmN后面的变量参数。
    vsnprintf(buf, CMDBUFLEN, cmd, ap);// 将结果写入buf

    va_end(ap);

    if (debug) {
        printf("EXEC: %s\n", buf);
    }

    return system(buf);
}
/* end of utils function */

// run nft script
static int nft_do_init_script_command()
{
	return run_cmd("nft -f /conf/firewall_init.nft");
}


// set ip outgoing clearance
static int nft_do_outgoging_allow_command(char *mac_addr, char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter mark set 0x20000 accept", mac_addr, ip_addr);
}
// set ip incoming clearance
static int nft_do_incoming_allow_command(char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter accept", ip_addr);
}
// set ip outgoing ban
static int nft_do_outgoging_ban_command(char *mac_addr, char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_prerouting_wifidogx_outgoing ether saddr %s ip saddr %s  counter mark set 0x20000 drop", mac_addr, ip_addr);
}
// set ip incoming ban
static int nft_do_incoming_ban_command(char *ip_addr)
{
    return run_cmd("nft add rule inet fw4 mangle_postrouting_wifidogx_incoming ip daddr %s counter drop", ip_addr);
}



// statistical outgoing information,must free when statistical is over
#define MAX_STATISTICAL_LENGTH 2048
char *nft_statistical_outgoing()
{
	FILE *r_fp;
	char *outgoing_buf = malloc(MAX_STATISTICAL_LENGTH);
	char cmd[100] = "nft -j list chain inet fw4 mangle_prerouting_wifidogx_outgoing";
	r_fp = popen(cmd, "r");
	fgets(outgoing_buf, sizeof(outgoing_buf), r_fp);
	pclose(r_fp);
	return outgoing_buf;
}

char *nft_statistical_income()
{
	FILE *r_fp;
	char *income_buf = malloc(MAX_STATISTICAL_LENGTH);
	char cmd[100] = "nft -j list chain inet fw4 mangle_postrouting_wifidogx_incoming";
	r_fp = popen(cmd, "r");
	fgets(income_buf, sizeof(income_buf), r_fp);
	pclose(r_fp);
	return income_buf;
}



/** Initialize the firewall rules
*/
int nft_init(const char* auth_server_ip, const char *gateway_ip, const char* interface, const char* filename)
{
	// firewall_init_bak.nft don't modify it
	system("rm -f /conf/firewall_init.nft && cp -f /conf/firewall_init_bak.nft /conf/firewall_init.nft")
	int ret = replace_variables(auth_server_ip, gateway_ip, interface, NFT_CONF_FILENAME);
	if (ret != 0)
		printf("init nft wrong!\n");

	nft_do_init_script_command();
}


/** Set if a specific client has access through the firewall */
int nft_fw_access(nft_access_t type, const char *ip, const char *mac, int tag)

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

