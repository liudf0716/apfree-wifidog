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

/* This is a small help module for creating and extending a list of DHCP
 * options. When finished, the list can be serialised to a buffer and added to
 * a BOOTP packet, completing a DHCP request.
 */

#ifndef DHCPOPTINJ_OPTIONS_H
#define DHCPOPTINJ_OPTIONS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct DHCPOptList;

struct DHCPOptList *dhcpOpt_createList(void);
void dhcpOpt_destroyList(struct DHCPOptList *list);
bool dhcpOpt_optExists(const struct DHCPOptList *list, int code);
int dhcpOpt_add(struct DHCPOptList *list, int code, const void *data, size_t size);
size_t dhcpOpt_count(struct DHCPOptList *list);
/* Serialise option list to an array (code + length + payload) */
int dhcpOpt_serialise(const struct DHCPOptList *list, uint8_t **buffer, size_t *size);
/* Create an array containg the integer codes of all the DHCP options in the
 * list */
int dhcpOpt_optCodes(const struct DHCPOptList *list, uint8_t **buffer, size_t *size);

#endif // DHCPOPTINJ_OPTIONS_H
