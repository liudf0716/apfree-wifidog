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

#include <stdint.h>


/** Used by iptables_fw_access to select if the client should be granted of denied access */

int nft_init(const char *gateway_ip, const char* interface);
int nft_fw_reload_client(int tag);
int nft_fw_access(fw_access_t type, const char *ip, const char *mac, int tag);
int nft_fw_access_host(fw_access_t type, const char *ip);
void nft_statistical_outgoing(char *outgoing, uint32_t outgoing_len);
void nft_statistical_incoming(char *incoming, uint32_t incoming_len);

#endif