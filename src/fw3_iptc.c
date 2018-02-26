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
  @file fw3_iptc.c
  @brief firewall3 - 3rd OpenWrt firewall implementation
  @author Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
  @author Copyright (C) 2017 ZengFei Zhang <zhangzengfei@kunteng.org>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <dlfcn.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <xtables.h>

#include "fw3_iptc.h"
#include "debug.h"


/* xtables interface */
#if (XTABLES_VERSION_CODE >= 10)
# include "xtables-10.h"
#elif (XTABLES_VERSION_CODE == 5)
# include "xtables-5.h" 
#else
# error "Unsupported xtables version"
#endif


static struct option base_opts[] = {
	{ .name = "match",  .has_arg = 1, .val = 'm' },
	{ .name = "jump",   .has_arg = 1, .val = 'j' },
	{ NULL }
};

static struct xtables_globals xtg = {
	.option_offset = 0,
	.program_version = "4",
	.orig_opts = base_opts,
};

const char *fw3_flag_names[] = {
	"filter",
	"nat",
	"mangle",
	"raw",
};

static const struct {
    const char *name;
    enum fw3_table opcode;
} fw3_keywords[] = {
	{"filter", FW3_TABLE_FILTER},
	{"nat", FW3_TABLE_NAT},
	{"mangle", FW3_TABLE_MANGLE},
	{NULL, FW3_TABLE_RAW}
};

static bool
is_chain(struct fw3_ipt_handle *h, const char *name)
{
	if (!h || !h->handle)
		return false;

	return iptc_is_chain(name, h->handle);
}

static bool
bitlen2netmask(int bits, void *mask)
{
	struct in_addr *v4;

	if (bits < -32 || bits > 32)
		return false;

	v4 = mask;
	v4->s_addr = bits ? htonl(~((1 << (32 - abs(bits))) - 1)) : 0;

	if (bits < 0)
		v4->s_addr = ~v4->s_addr;

	return true;
}

static bool
load_extension(struct fw3_ipt_handle *h, const char *name)
{
	char path[128] = {0};
	void *lib, **tmp;
	const char *pfx = "libipt";
	
	if (!h)
		return false;

	snprintf(path, sizeof(path), "/usr/lib/iptables/libxt_%s.so", name);
	if (!(lib = dlopen(path, RTLD_NOW)))
	{
		snprintf(path, sizeof(path), "/usr/lib/iptables/%s_%s.so", pfx, name);
		lib = dlopen(path, RTLD_NOW);
	}

	if (!lib)
		return false;

	tmp = realloc(h->libv, sizeof(lib) * (h->libc + 1));

	if (!tmp)
		return false;

	h->libv = tmp;
	h->libv[h->libc++] = lib;

	return true;
}

static struct xtables_match *
find_match(struct fw3_ipt_rule *r, const char *name)
{
	struct xtables_match *m = NULL;

	m = xtables_find_match(name, XTF_DONT_LOAD, &r->matches);

	if (!m && load_extension(r->h, name))
		m = xtables_find_match(name, XTF_DONT_LOAD, &r->matches);

	return m;
}

static void
init_match(struct fw3_ipt_rule *r, struct xtables_match *m, bool no_clone)
{
	size_t s;
	struct xtables_globals *g;

	if (!m)
		return;

	s = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;

	m->m = fw3_alloc(s);

	fw3_xt_set_match_name(m);

	m->m->u.user.revision = m->revision;
	m->m->u.match_size = s;

	/* free previous userspace data */
	fw3_xt_free_match_udata(m);

	if (m->init)
		m->init(m->m);

	/* don't merge options if no_clone is set and this match is a clone */
	if (no_clone && (m == m->next))
		return;

	/* merge option table */
	g = &xtg;
	fw3_xt_merge_match_options(g, m);
}

static char *
get_protoname(struct fw3_ipt_rule *r)
{
	const struct xtables_pprot *pp;

	if (r->protocol)
		for (pp = xtables_chain_protos; pp->name; pp++)
			if (pp->num == r->protocol)
				return (char *)pp->name;

	return NULL;
}

static bool
need_protomatch(struct fw3_ipt_rule *r, const char *pname)
{
	if (!pname)
		return false;

	if (!xtables_find_match(pname, XTF_DONT_LOAD, NULL))
		return true;

	return !r->protocol_loaded;
}

static struct xtables_match *
load_protomatch(struct fw3_ipt_rule *r)
{
	const char *pname = get_protoname(r);

	if (!need_protomatch(r, pname))
		return NULL;

	return find_match(r, pname);
}

static struct xtables_target *
fw3_find_target(struct fw3_ipt_rule *r, const char *name)
{
	struct xtables_target *t = NULL;

	if (is_chain(r->h, name))
		return xtables_find_target(XT_STANDARD_TARGET, XTF_LOAD_MUST_SUCCEED);

	t = xtables_find_target(name, XTF_DONT_LOAD);

	if (!t && load_extension(r->h, name))
		t = xtables_find_target(name, XTF_DONT_LOAD);

	return t;
}

static struct xtables_target *
fw3_get_target(struct fw3_ipt_rule *r, const char *name)
{
	size_t s;
	struct xtables_target *t;
	struct xtables_globals *g;

	t = fw3_find_target(r, name);

	if (!t)
		return NULL;

	s = XT_ALIGN(sizeof(struct xt_entry_target)) + t->size;
	t->t = fw3_alloc(s);

	fw3_xt_set_target_name(t, name);

	t->t->u.user.revision = t->revision;
	t->t->u.target_size = s;

	/* free previous userspace data */
	fw3_xt_free_target_udata(t);

	if (t->init)
		t->init(t->t);

	/* merge option table */
	g = &xtg;
	fw3_xt_merge_target_options(g, t);

	r->target = t;

	return t;
}

static char *
fw3_strdup(const char *s)
{
	char *ns;

	ns = strdup(s);

	if (!ns) {
		debug(LOG_ERR, "Out of memory while duplicating string '%s'", s);
		exit(-1);
	}

	return ns;
}

void *
fw3_alloc(size_t size)
{
	void *mem;

	mem = calloc(1, size);

	if (!mem) {
		debug(LOG_ERR, "Out of memory while allocating %d bytes", size);
		exit(-1);
	}

	return mem;
}

/* Can't be zero. */
static int
fw3_parse_rulenumber(const char *rule)
{
	unsigned int rulenum;

	if (!xtables_strtoui(rule, NULL, &rulenum, 1, INT_MAX))
		xtables_error(PARAMETER_PROBLEM,
			   "Invalid rule number `%s'", rule);

	return rulenum;
}

static bool
fw3_parse_option(struct fw3_ipt_rule *r, int optc, bool inv)
{
	struct xtables_rule_match *m;
	struct xtables_match *em;

	/* is a target option */
	if (r->target && fw3_xt_has_target_parse(r->target) &&
		optc >= r->target->option_offset &&
		optc < (r->target->option_offset + 256))
	{
		xtables_option_tpcall(optc, r->argv, inv, r->target, &r->e);
		return false;
	}

	/* try to dispatch argument to one of the match parsers */
	for (m = r->matches; m; m = m->next)
	{
		em = m->match;

		if (m->completed || !fw3_xt_has_match_parse(em))
			continue;

		if (optc < em->option_offset ||
			optc >= (em->option_offset + 256))
			continue;

		xtables_option_mpcall(optc, r->argv, inv, em, &r->e);
		return false;
	}

	/* unhandled option, might belong to a protocol match */
	if ((em = load_protomatch(r)) != NULL)
	{
		init_match(r, em, false);

		r->protocol_loaded = true;
		optind--;

		return true;
	}

	if (optc == ':')
		debug(LOG_WARNING, "fw3_parse_option(): option '%s' needs argument", r->argv[optind-1]);

	if (optc == '?')
		debug(LOG_WARNING, "fw3_parse_option(): unknown option '%s'", r->argv[optind-1]);

	return false;
}

static bool
fw3_parse_address(void *ptr, const char *val)
{
	struct fw3_address addr = { };
	struct in_addr v4;
	char *p = NULL, *m = NULL, *s, *e;
	int bits = -1;

	if (*val == '!')
	{
		addr.invert = true;
		while (isspace(*++val));
	}

	s = strdup(val);

	if (!s)
		return false;

	if ((m = strchr(s, '/')) != NULL)
		*m++ = 0;
	else if ((p = strchr(s, '-')) != NULL)
		*p++ = 0;

	if (inet_pton(AF_INET, s, &v4))
	{
		addr.address.v4 = v4;

		if (m)
		{
			if (!inet_pton(AF_INET, m, &v4))
			{
				bits = strtol(m, &e, 10);

				if ((*e != 0) || !bitlen2netmask(bits, &v4))
					goto fail;
			}

			addr.mask.v4 = v4;
		}
		else if (p)
		{
			if (!inet_pton(AF_INET, p, &addr.mask.v4))
				goto fail;

			addr.range = true;
		}
		else
		{
			addr.mask.v4.s_addr = 0xFFFFFFFF;
		}
	}
	else
	{
		goto fail;
	}

	free(s);
	addr.set = true;
	memcpy(ptr, &addr, sizeof(addr));
	return true;

fail:
	free(s);
	return false;
}

static void
fw3_init_extensions(void)
{
	init_extensions();
	init_extensions4();
}

static void *
fw3_ipt_rule_build(struct fw3_ipt_rule *r)
{
	size_t s, target_size = (r->target) ? r->target->t->u.target_size : 0;
	struct xtables_rule_match *m;

	struct ipt_entry *e;

	s = XT_ALIGN(sizeof(struct ipt_entry));

	for (m = r->matches; m; m = m->next)
		s += m->match->m->u.match_size;

	e = fw3_alloc(s + target_size);

	memcpy(e, &r->e, sizeof(struct ipt_entry));

	e->target_offset = s;
	e->next_offset = s + target_size;

	s = 0;

	for (m = r->matches; m; m = m->next)
	{
		memcpy(e->elems + s, m->match->m, m->match->m->u.match_size);
		s += m->match->m->u.match_size;
	}

	if (target_size)
		memcpy(e->elems + s, r->target->t, target_size);

	return e;
}

static struct fw3_ipt_rule *
fw3_ipt_rule_new(struct fw3_ipt_handle *h)
{
	struct fw3_ipt_rule *r = NULL;

	r = fw3_alloc(sizeof(*r));

	r->h = h;
	r->argv = fw3_alloc(sizeof(char *));
	r->argv[r->argc++] = "fw3";

	return r;
}

static struct fw3_ipt_rule *
fw3_ipt_rule_create(struct fw3_ipt_handle *handle, char *cmd)
{
	char *p = NULL, **tmp;
	struct fw3_ipt_rule *r = NULL;
	char *saveptr = NULL ;

	r = fw3_ipt_rule_new(handle);
	
	p = strtok_r(cmd, " \t", &saveptr);
	while (p) {
		tmp = realloc(r->argv, (r->argc + 1) * sizeof(*r->argv));

		if (!tmp) {
			exit(-1);
		}

		r->argv = tmp;
		r->argv[r->argc++] = fw3_strdup(p);

		p = strtok_r(NULL, " \t", &saveptr);
	}

	return r;
}

static void
fw3_ipt_rule_src_dest(struct fw3_ipt_rule *r,
                      struct fw3_address *src, struct fw3_address *dest)
{

	if (src && src->set)
	{
		r->e.ip.src = src->address.v4;
		r->e.ip.smsk = src->mask.v4;

		r->e.ip.src.s_addr &= r->e.ip.smsk.s_addr;

		if (src->invert)
			r->e.ip.invflags |= IPT_INV_SRCIP;
	}

	if (dest && dest->set)
	{
		r->e.ip.dst = dest->address.v4;
		r->e.ip.dmsk = dest->mask.v4;

		r->e.ip.dst.s_addr &= r->e.ip.dmsk.s_addr;

		if (dest->invert)
			r->e.ip.invflags |= IPT_INV_DSTIP;
	}
}

static void
fw3_ipt_rule_address(struct fw3_ipt_rule *r, const char *address, bool dest)
{
	if (address)
	{
		struct fw3_address addr = { .set = true };
		fw3_parse_address(&addr, address);
		fw3_ipt_rule_src_dest(r, (dest) ? NULL : &addr, (dest) ? &addr : NULL);
	}
}

static void
fw3_ipt_rule_in_out(struct fw3_ipt_rule *r,
                    struct fw3_device *in, struct fw3_device *out)
{
	if (in && !in->any)
	{
		xtables_parse_interface(in->name, r->e.ip.iniface,
										  r->e.ip.iniface_mask);

		if (in->invert)
			r->e.ip.invflags |= IPT_INV_VIA_IN;
	}

	if (out && !out->any)
	{
		xtables_parse_interface(out->name, r->e.ip.outiface,
										   r->e.ip.outiface_mask);

		if (out->invert)
			r->e.ip.invflags |= IPT_INV_VIA_OUT;
	}
}

static void
fw3_ipt_rule_device(struct fw3_ipt_rule *r, const char *device, bool out)
{
	if (device)
	{
		struct fw3_device dev = { .any = false };
		strncpy(dev.name, device, sizeof(dev.name) - 1);
		fw3_ipt_rule_in_out(r, (out) ? NULL : &dev, (out) ? &dev : NULL);
	}
}

static void
fw3_ipt_rule_proto(struct fw3_ipt_rule *r, const char* val)
{
	struct protoent *ent;

	ent = getprotobyname(val);

	if (ent)
	{
		r->e.ip.proto = ent->p_proto;

		if (*val == '!')
			r->e.ip.invflags |= XT_INV_PROTO;

		r->protocol = ent->p_proto;
	}
}

static unsigned char *
fw3_ipt_rule_mask(struct fw3_ipt_rule *r)
{
	size_t s;
	unsigned char *p, *mask = NULL;
	struct xtables_rule_match *m;

#define SZ(x) XT_ALIGN(sizeof(struct x))

	s = SZ(ipt_entry);

	for (m = r->matches; m; m = m->next)
		s += SZ(ipt_entry_match) + m->match->size;

	s += SZ(ipt_entry_target);
	if (r->target)
		s += r->target->size;

	mask = fw3_alloc(s);
	memset(mask, 0xFF, SZ(ipt_entry));
	p = mask + SZ(ipt_entry);

	for (m = r->matches; m; m = m->next)
	{
		memset(p, 0xFF, SZ(ipt_entry_match) + m->match->userspacesize);
		p += SZ(ipt_entry_match) + m->match->size;
	}

	memset(p, 0xFF, SZ(ipt_entry_target) + ((r->target) ? r->target->userspacesize : 0));

	return mask;
}

static int
fw3_ipt_create_chain(struct fw3_ipt_handle *h, const char *chain)
{
	if (!h || !h->handle) {
		debug(LOG_ERR, "h or h->handle is NULL");
		return 0;
	}

	int rv = iptc_create_chain(chain, h->handle);
	if (!rv)
		debug(LOG_ERR, "iptc_create_chain(): %s\n", iptc_strerror(errno));
	
	return rv;
}

static int
fw3_ipt_flush_chain(struct fw3_ipt_handle *h, const char *chain)
{
	if (!h || !h->handle) {
		debug(LOG_ERR, "h or h->handle is NULL");
		return 0;
	}

	int rv = iptc_flush_entries(chain, h->handle);
	if (!rv)
		debug(LOG_ERR, "iptc_flush_chain(): %s\n", iptc_strerror(errno));
	
	return rv;
}

static int
__fw3_ipt_delete_rules(struct fw3_ipt_handle *h, const char *target)
{
	unsigned int num;
	const struct ipt_entry *e;
	const char *chain;
	const char *t;
	bool found;

	for (chain = iptc_first_chain(h->handle);
		 chain != NULL;
		 chain = iptc_next_chain(h->handle))
	{
		do {
			found = false;

			for (num = 0, e = iptc_first_rule(chain, h->handle);
				 e != NULL;
				 num++, e = iptc_next_rule(e, h->handle))
			{
				t = iptc_get_target(e, h->handle);

				if (*t && !strcmp(t, target))
				{
					debug(LOG_DEBUG, "-D %s %u\n", chain, num + 1);

					iptc_delete_num_entry(chain, num, h->handle);
					found = true;
					break;
				}
			}
		} while (found);
	}

	return (found ? 1 : 0 );
}

static int
fw3_ipt_delete_chain(struct fw3_ipt_handle *h, const char *chain)
{
	int rv;
	
	if (!h || !h->handle) {
		debug(LOG_ERR, "h is NULL");
		return 0;
	}
	__fw3_ipt_delete_rules(h, chain);

	rv = iptc_delete_chain(chain, h->handle);
	if (!rv)
		debug(LOG_ERR, "iptc_delete_chain(): %s\n", iptc_strerror(errno));

	return rv;
}

static int
__fw3_ipt_rule_append(struct fw3_ipt_rule *r)
{
	void *rule;
	int i, optc, rv = 0;
	const char *chain = NULL;
	unsigned char *mask;
	char command = 'A';
	unsigned int rule_num = 0;

	bool inv = false;

	struct xtables_rule_match *m = NULL;
	struct xtables_match *em = NULL;
	struct xtables_target *et = NULL;
	struct xtables_globals *g = NULL;

	struct fw3_ipt_handle *handle = NULL;

	g = &xtg;
	g->opts = g->orig_opts;

	optind = 0;
	opterr = 0;

	while ((optc = getopt_long(r->argc, r->argv, "-:t:N:F:X:I:A:D:p:i:o:s:d:m:j:", g->opts,
	                           NULL)) != -1)
	{
		switch (optc)
		{
		case 't':
			if (!r->h)
			{
				enum fw3_table table = FW3_TABLE_FILTER;

				for (i = 0; fw3_keywords[i].name; i++)
					if (strcasecmp(optarg, fw3_keywords[i].name) == 0)
						table = fw3_keywords[i].opcode;

				handle = fw3_ipt_open(table);
				if (handle)
					r->h = handle;
				else 
					goto free; // if failed, no need the following steps
			}

			break;

		case 'N':
			// liudf added 20180226; incase r->h is NULL
			if (!r->h) {
				handle = fw3_ipt_open(FW3_TABLE_FILTER);
				if (handle)
					r->h = handle;
				else
					goto free;
			}
			rv = fw3_ipt_create_chain(r->h, optarg);
			goto free;

		case 'F':
			// liudf added 20180226; incase r->h is NULL
			if (!r->h) {
				handle = fw3_ipt_open(FW3_TABLE_FILTER);
				if (handle)
					r->h = handle;
				else
					goto free;
			}
			rv = fw3_ipt_flush_chain(r->h, optarg);
			goto free;

		case 'X':
			// liudf added 20180226; incase r->h is NULL
			if (!r->h) {
				handle = fw3_ipt_open(FW3_TABLE_FILTER);
				if (handle)
					r->h = handle;
				else
					goto free;
			}
			rv = fw3_ipt_delete_chain(r->h, optarg);
			goto free;

		case 'I':
		case 'A':
		case 'D':
			command = optc;
			if (optc == 'I' || optc == 'D')
			{
				if (optind < r->argc && r->argv[optind][0] != '-'
					&& r->argv[optind][0] != '!')
					rule_num = fw3_parse_rulenumber(r->argv[optind++]);
				else if (optc == 'I') rule_num = 1;
			}

			chain = optarg;
			break;

		case 'p':
			fw3_ipt_rule_proto(r, optarg);
			break;

		case 'i':
			fw3_ipt_rule_device(r, optarg, NULL);
			break;

		case 'o':
			fw3_ipt_rule_device(r, optarg, true);
			break;

		case 's':
			fw3_ipt_rule_address(r, optarg, NULL);
			break;

		case 'd':
			fw3_ipt_rule_address(r, optarg, true);
			break;

		case 'm':
			em = find_match(r, optarg);

			if (!em)
			{
				debug(LOG_WARNING, "fw3_ipt_rule_append(): Can't find match '%s'", optarg);
				goto free;
			}

			init_match(r, em, true);
			break;

		case 'j':
			et = fw3_get_target(r, optarg);

			if (!et)
			{
				debug(LOG_WARNING, "fw3_ipt_rule_append(): Can't find target '%s'", optarg);
				goto free;
			}

			break;

		case 1:
			if ((optarg[0] == '!') && (optarg[1] == '\0'))
			{
				optarg[0] = '\0';
				inv = true;
				continue;
			}

			debug(LOG_WARNING, "fw3_ipt_rule_append(): Bad argument '%s'", optarg);
			goto free;

		default:
			if (fw3_parse_option(r, optc, inv))
				continue;
			break;
		}

		inv = false;
	}
	
	// liudf added 20180226; incase r->h is NULL
	if (!r->h && !handle) {
		handle = fw3_ipt_open(FW3_TABLE_FILTER);
		if (handle)
			r->h = handle;
		else
			goto free;
	}

	for (m = r->matches; m; m = m->next)
		xtables_option_mfcall(m->match);

	if (r->target)
		xtables_option_tfcall(r->target);

	rule = fw3_ipt_rule_build(r);

	if (command == 'A') {
		rv = iptc_append_entry(chain, rule, r->h->handle);
		if (!rv)
			debug(LOG_ERR, "iptc_append_entry(): %s\n", iptc_strerror(errno));
	} else if (command == 'D') {
		if (rule_num > 0) {
			rv = iptc_delete_num_entry(chain, rule_num - 1, r->h->handle);
			if (!rv)
			debug(LOG_ERR, "iptc_delete_num_entry(): %s\n", iptc_strerror(errno));
		} else {
			mask = fw3_ipt_rule_mask(r);
			while (iptc_delete_entry(chain, rule, mask, r->h->handle)){
				rv = 1;
			}

			free(mask);
		}
	} else {
		rv = iptc_insert_entry(chain, rule, rule_num - 1, r->h->handle);
		if (!rv)
			debug(LOG_ERR, "iptc_insert_entry(): %s\n", iptc_strerror(errno));
	}

	free(rule);

free:
	for (i = 1; i < r->argc; i++)
		free(r->argv[i]);

	free(r->argv);

	xtables_rule_matches_free(&r->matches);

	if (r->target)
		free(r->target->t);

	free(r);

	/* reset all targets and matches */
	for (em = xtables_matches; em; em = em->next)
		em->mflags = 0;

	for (et = xtables_targets; et; et = et->next)
	{
		et->tflags = 0;
		et->used = 0;
	}

	xtables_free_opts(1);

	if (handle)
	{
		fw3_ipt_commit(handle);
		fw3_ipt_close(handle);
	}

	return rv;
}

struct fw3_ipt_handle *
fw3_ipt_open(enum fw3_table table)
{
	struct fw3_ipt_handle *h;

	h = fw3_alloc(sizeof(*h));

	xtables_init();

	h->table  = table;
	h->handle = iptc_init(fw3_flag_names[table]);
	if (!h->handle)
	{
		free(h);
		return NULL;
	}

	xtables_set_params(&xtg);
	xtables_set_nfproto(NFPROTO_IPV4);

	

	fw3_xt_reset();
	fw3_init_extensions();

	return h;
}

void
fw3_ipt_close(struct fw3_ipt_handle *h)
{
	if (h->libv)
	{
		while (h->libc > 0)
		{
			h->libc--;
			dlclose(h->libv[h->libc]);
            h->libv[h->libc] = NULL;
		}

		free(h->libv);
        h->libv = NULL;
	}
    iptc_free(h->handle);
    h->handle = NULL;

	free(h);
    h = NULL;
}

int
fw3_ipt_commit(struct fw3_ipt_handle *h)
{
	int rv = 0;
	if (!h || !h->handle) {
		debug(LOG_ERR, "h or h->handle is NULL");
		return rv;
	}

	rv = iptc_commit(h->handle);
	if (!rv)
		debug(LOG_ERR, "iptc_commit(): %s", iptc_strerror(errno));

	return rv;
}

int
fw3_ipt_rule_append(struct fw3_ipt_handle *handle, char *command)
{
	if (!command || !*command) {
		debug(LOG_ERR, "fw3_ipt_rule_append : input parameters is NULL");
		return 0;
	}

	struct fw3_ipt_rule *r = NULL;

	r = fw3_ipt_rule_create(handle, command);

	return __fw3_ipt_rule_append(r);
}
