
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */
 
#ifndef __FW3_IPTABLES_H
#define __FW3_IPTABLES_H


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

struct fw3_ipt_handle;
enum fw3_table;

struct fw3_ipt_handle *
fw3_ipt_open(enum fw3_table table);

void
fw3_ipt_close(struct fw3_ipt_handle *h);

int
fw3_ipt_commit(struct fw3_ipt_handle *h);

int
fw3_ipt_rule_append(struct fw3_ipt_handle *handle, char *command);


#endif
