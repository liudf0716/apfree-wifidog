/*
 * firewall3 - 3rd OpenWrt UCI firewall implementation
 *
 *   Copyright (C) 2013 Jo-Philipp Wich <jow@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __FW3_XTABLES_5_H
#define __FW3_XTABLES_5_H

static inline void
fw3_xt_reset(void)
{
	xtables_matches = NULL;
	xtables_targets = NULL;
}


static inline const char *
fw3_xt_get_match_name(struct xtables_match *m)
{
    return m->m->u.user.name;
}

static inline void
fw3_xt_set_match_name(struct xtables_match *m)
{
    strcpy(m->m->u.user.name, m->name);
}

static inline bool
fw3_xt_has_match_parse(struct xtables_match *m)
{
    return !!m->parse;
}

static inline void
fw3_xt_free_match_udata(struct xtables_match *m)
{
    return;
}

static inline void
fw3_xt_merge_match_options(struct xtables_globals *g, struct xtables_match *m)
{
	g->opts = xtables_merge_options(g->opts, m->extra_opts, &m->option_offset);
}


static inline const char *
fw3_xt_get_target_name(struct xtables_target *t)
{
    return t->t->u.user.name;
}

static inline void
fw3_xt_set_target_name(struct xtables_target *t, const char *name)
{
    strcpy(t->t->u.user.name, name);
}

static inline bool
fw3_xt_has_target_parse(struct xtables_target *t)
{
    return !!t->parse;
}

static inline void
fw3_xt_free_target_udata(struct xtables_target *t)
{
    return;
}

static inline void
fw3_xt_merge_target_options(struct xtables_globals *g, struct xtables_target *t)
{
	g->opts = xtables_merge_options(g->opts, t->extra_opts, &t->option_offset);
}

/* xtables api addons */

static inline void
xtables_option_mpcall(unsigned int c, char **argv, bool invert,
                      struct xtables_match *m, void *fw)
{
	if (m->parse)
		m->parse(c - m->option_offset, argv, invert, &m->mflags, fw, &m->m);
}

static inline void
xtables_option_mfcall(struct xtables_match *m)
{
	if (m->final_check)
		m->final_check(m->mflags);
}

static inline void
xtables_option_tpcall(unsigned int c, char **argv, bool invert,
                      struct xtables_target *t, void *fw)
{
	if (t->parse)
		t->parse(c - t->option_offset, argv, invert, &t->tflags, fw, &t->t);
}

static inline void
xtables_option_tfcall(struct xtables_target *t)
{
	if (t->final_check)
		t->final_check(t->tflags);
}

static inline void
xtables_rule_matches_free(struct xtables_rule_match **matches)
{
	struct xtables_rule_match *mp, *tmp;

	for (mp = *matches; mp;)
	{
		tmp = mp->next;

		if (mp->match->m)
		{
			free(mp->match->m);
			mp->match->m = NULL;
		}

		if (mp->match == mp->match->next)
		{
			free(mp->match);
			mp->match = NULL;
		}

		free(mp);
		mp = tmp;
	}

	*matches = NULL;
}

static inline int
xtables_ipmask_to_cidr(const struct in_addr *mask)
{
	int bits;
	uint32_t m;

	for (m = ntohl(mask->s_addr), bits = 0; m & 0x80000000; m <<= 1)
		bits++;

	return bits;
}

static inline int
xtables_ip6mask_to_cidr(const struct in6_addr *mask)
{
	int bits = 0;
	uint32_t a, b, c, d;

	a = ntohl(mask->s6_addr32[0]);
	b = ntohl(mask->s6_addr32[1]);
	c = ntohl(mask->s6_addr32[2]);
	d = ntohl(mask->s6_addr32[3]);

	while (a & 0x80000000U)
	{
		a <<= 1;
		a  |= (b >> 31) & 1;
		b <<= 1;
		b  |= (c >> 31) & 1;
		c <<= 1;
		c  |= (d >> 31) & 1;
		d <<= 1;

		bits++;
	}

	return bits;
}

#endif
