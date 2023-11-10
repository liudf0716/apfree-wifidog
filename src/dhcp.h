/* 
 * Copyright © 2015–2019 Andreas Misje
 *
 * This file is part of dhcpoptinj.
 *
 * dhcpoptinj is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.  
 *
 * dhcpoptinj is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with dhcpoptinj. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef DHCPOPTINJ_DHCP_H
#define DHCPOPTINJ_DHCP_H

#include <stdint.h>

#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCPOPT_PAD 0
#define DHCPOPT_END 0xff
#define DHCPOPT_TYPE 0x35

#pragma pack(4)
struct BootP
{
	uint8_t op;
	uint8_t hwAddrType;
	uint8_t hwAddrLen;
	uint8_t hops;
	uint32_t xID;
	uint16_t secs;
	uint16_t flags;
	uint32_t clientAddr;
	uint32_t ownAddr;
	uint32_t serverAddr;
	uint32_t gwAddr;
	uint8_t clientHwAddr[16];
	uint8_t serverName[64];
	uint8_t file[128];
	uint32_t cookie;
	// options …
};
#pragma pack()

#pragma pack(1)
struct DHCPOption
{
	uint8_t code;
	uint8_t length;
	uint8_t data[];
};
#pragma pack()

const char *dhcp_msgTypeString(uint8_t msgType);
const char *dhcp_optionString(uint8_t option);

#endif // DHCPOPTINJ_DHCP_H
