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

#ifndef DHCPOPTINJ_IPV4_H
#define DHCPOPTINJ_IPV4_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#pragma pack(2)
struct IPv4Header
{
	uint8_t verIHL;
	uint8_t dscpECN;
	uint16_t totalLen;
	uint16_t id;
	uint16_t flagsFrag;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t sourceAddr;
	uint32_t destAddr;
};
#pragma pack()

uint16_t ipv4_checksum(const struct IPv4Header *ipv4Header);
size_t ipv4_headerLen(const struct IPv4Header *ipv4Header);
bool ipv4_packetFragmented(const struct IPv4Header *ipHeader);

#endif // DHCPOPTINJ_IPV4_H
