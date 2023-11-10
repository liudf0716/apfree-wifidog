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

#include "ipv4.h"
#include <stddef.h>
#include <arpa/inet.h>

uint16_t ipv4_checksum(const struct IPv4Header *ipv4Header)
{
	const uint16_t *data = (const uint16_t *)ipv4Header;
	size_t len = sizeof(*ipv4Header);
	uint32_t checksum = 0;

	while (len > 1)
	{
		checksum += *data++;
		len -= 2;
	}

	if (len > 0)
		checksum += *(const uint8_t *)data;

	while (checksum >> 16)
		checksum = (checksum & 0xffff) + (checksum >> 16);

	return ~checksum;
}

size_t ipv4_headerLen(const struct IPv4Header *ipHeader)
{
	return (ipHeader->verIHL & 0xf) * 4U;
}

bool ipv4_packetFragmented(const struct IPv4Header *ipHeader)
{
	uint16_t field = ntohs(ipHeader->flagsFrag);
	bool fragmentsToCome = (field >> 13) & 4;
	uint16_t fragmentOffset = field & 0x1fff;
	return fragmentsToCome || fragmentOffset;
}
