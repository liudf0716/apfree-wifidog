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
  @author Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
  @author Copyright (C) 2017 ZengFei Zhang <zhangzengfei@kunteng.org>
 */
 
#ifndef __FW3_IPTABLES_H
#define __FW3_IPTABLES_H

#include <stdbool.h>
#include <libiptc/libiptc.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

/* libipt*ext.so interfaces */
extern void init_extensions(void);
extern void init_extensions4(void);

enum fw3_table
{
	FW3_TABLE_FILTER = 0,
	FW3_TABLE_NAT    = 1,
	FW3_TABLE_MANGLE = 2,
	FW3_TABLE_RAW    = 3,
};

struct fw3_ipt_handle
{
	enum fw3_table table;
	void *handle;

	int libc;
	void **libv;
};

struct fw3_ipt_rule {
	struct fw3_ipt_handle *h;
	struct ipt_entry e;

	struct xtables_rule_match *matches;
	struct xtables_target *target;

	int argc;
	char **argv;

	uint32_t protocol;
	bool protocol_loaded;
};

struct fw3_device
{
	bool set;
	bool any;
	bool invert;
	char name[32];
	char network[32];
};

struct fw3_address
{
	bool set;
	bool range;
	bool invert;
	bool resolved;
	union {
		struct in_addr v4;
		struct ether_addr mac;
	} address;
	union {
		struct in_addr v4;
		struct ether_addr mac;
	} mask;
};

void *
fw3_alloc(size_t size);

struct fw3_ipt_handle *
fw3_ipt_open(enum fw3_table table);

void
fw3_ipt_close(struct fw3_ipt_handle *h);

int
fw3_ipt_commit(struct fw3_ipt_handle *h);

int
fw3_ipt_rule_append(struct fw3_ipt_handle *handle, char *command);

#endif
