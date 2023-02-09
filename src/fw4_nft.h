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
#ifndef __FW4_NFT_H
#define __FW4_NFT_H

/**
Used to supress the error output of the firewall during destruction */
static int nft_fw_quiet = 0;

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum nft_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} nft_access_t;

int nft_init(const char* auth_server_ip, const char *gateway_ip, const char* interface, const char* filename);
int nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);
#endif