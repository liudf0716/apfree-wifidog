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

#include "options.h"
#include <stdlib.h>
#include <string.h>
#include "dhcp.h"

/* Just like struct DHCPOption in dhcp.h, but with (fixed) storage for option
 * payload) */
struct DHCPOpt
{
	uint8_t code;
	uint8_t length;
	uint8_t data[UINT8_MAX];
};

struct DHCPOptList
{
	struct DHCPOpt *options;
	size_t count;
	size_t capacity;
};

static int resizeList(struct DHCPOptList *list);
/* Total number of bytes needed to serialise list */
static size_t totalSize(const struct DHCPOptList *list);

struct DHCPOptList *dhcpOpt_createList(void)
{
	struct DHCPOptList *list = malloc(sizeof(*list));
	*list = (struct DHCPOptList){0};
	if (resizeList(list))
	{
		dhcpOpt_destroyList(list);
		return NULL;
	}
	return list;
}

void dhcpOpt_destroyList(struct DHCPOptList *list)
{
	free(list->options);
	free(list);
}

bool dhcpOpt_optExists(const struct DHCPOptList *list, int code)
{
	for (size_t i = 0; i < list->count; ++i)
		if (code == list->options[i].code)
			return true;

	return false;
}

int dhcpOpt_add(struct DHCPOptList *list, int code, const void *data, size_t size)
{
	if (resizeList(list))
		return 1;

	struct DHCPOpt *opt = &list->options[list->count];
	opt->code = code;
	opt->length = size;
	if (data && size)
		memcpy(opt->data, data, size);

	++list->count;
	return 0;
}

size_t dhcpOpt_count(struct DHCPOptList *list)
{
	return list->count;
}

int dhcpOpt_serialise(const struct DHCPOptList *list, uint8_t **buffer, size_t *size)
{
	*size = totalSize(list);
	if (!*size)
		return 1;

	*buffer = malloc(*size);
	if (!*buffer)
	{
		*size = 0;
		return 1;
	}

	size_t bufI = 0;
	for (size_t optI = 0; optI < list->count; ++optI)
	{
		struct DHCPOpt *opt = &list->options[optI];
		(*buffer)[bufI++] = opt->code;
		/* Only copy option length and payload if it actually has a payload (the
		 * special options 'pad' and 'end' are one-byte options) */
		if (opt->code != DHCPOPT_PAD && opt->code != DHCPOPT_END)
		{
			(*buffer)[bufI++] = opt->length;
			for (size_t optDataI = 0; optDataI < opt->length; ++optDataI)
				(*buffer)[bufI++] = opt->data[optDataI];
		}
	}

	return 0;
}

int dhcpOpt_optCodes(const struct DHCPOptList *list, uint8_t **buffer, size_t *size)
{
	*size = list->count;
	*buffer = malloc(*size);
	if (!*buffer)
	{
		*size = 0;
		return 1;
	}

	for (size_t i = 0; i < list->count; ++i)
		(*buffer)[i] = list->options[i].code;

	return 0;
}

static int resizeList(struct DHCPOptList *list)
{
	if (list->count < list->capacity)
		return 0;

	/* Inital capacity of 24 options somewhat arbitrary, but should be
	 * sufficient for most cases */
	size_t newCapacity = list->capacity ? list->capacity * 2 : 24;
	struct DHCPOpt *newOptList = realloc(list->options, newCapacity * sizeof(
				struct DHCPOpt));
	if (!newOptList)
		return 1;

	list->options = newOptList;
	list->capacity = newCapacity;
	return 0;
}

static size_t totalSize(const struct DHCPOptList *list)
{
	size_t size = 0;
	for (size_t i = 0; i < list->count; ++i)
	{
		struct DHCPOpt *opt = &list->options[i];
		/* The special options 'pad' and 'end' are only one byte long, whilst
		 * other options are minimum two bytes long */
		if (opt->code == DHCPOPT_PAD || opt->code == DHCPOPT_END)
			++size;
		else
			size += 2U + list->options[i].length;
	}

	return size;
}
