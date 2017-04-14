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

#ifndef __FW3_XTABLES_10_H
#define __FW3_XTABLES_10_H

extern struct xtables_match *xtables_pending_matches;
extern struct xtables_target *xtables_pending_targets;

static inline void
fw3_xt_reset(void)
{
	xtables_matches = NULL;
	xtables_targets = NULL;

	xtables_pending_matches = NULL;
	xtables_pending_targets = NULL;
}


static inline const char *
fw3_xt_get_match_name(struct xtables_match *m)
{
    if (m->alias)
        return m->alias(m->m);

    return m->m->u.user.name;
}

static inline void
fw3_xt_set_match_name(struct xtables_match *m)
{
    if (m->real_name)
        strcpy(m->m->u.user.name, m->real_name);
    else
        strcpy(m->m->u.user.name, m->name);
}

static inline bool
fw3_xt_has_match_parse(struct xtables_match *m)
{
    return (m->parse || m->x6_parse);
}

static inline void
fw3_xt_free_match_udata(struct xtables_match *m)
{
    if (m->udata_size)
    {
        free(m->udata);
        m->udata = fw3_alloc(m->udata_size);
    }
}

static inline void
fw3_xt_merge_match_options(struct xtables_globals *g, struct xtables_match *m)
{
	if (m->x6_options)
		g->opts = xtables_options_xfrm(g->orig_opts, g->opts,
									   m->x6_options, &m->option_offset);

	if (m->extra_opts)
		g->opts = xtables_merge_options(g->orig_opts, g->opts,
										m->extra_opts, &m->option_offset);
}


static inline const char *
fw3_xt_get_target_name(struct xtables_target *t)
{
    if (t->alias)
        return t->alias(t->t);

    return t->t->u.user.name;
}

static inline void
fw3_xt_set_target_name(struct xtables_target *t, const char *name)
{
    if (t->real_name)
        strcpy(t->t->u.user.name, t->real_name);
    else
        strcpy(t->t->u.user.name, name);
}

static inline bool
fw3_xt_has_target_parse(struct xtables_target *t)
{
    return (t->parse || t->x6_parse);
}

static inline void
fw3_xt_free_target_udata(struct xtables_target *t)
{
    if (t->udata_size)
    {
        free(t->udata);
        t->udata = fw3_alloc(t->udata_size);
    }
}

static inline void
fw3_xt_merge_target_options(struct xtables_globals *g, struct xtables_target *t)
{
	if (t->x6_options)
		g->opts = xtables_options_xfrm(g->orig_opts, g->opts,
		                               t->x6_options, &t->option_offset);
	else
		g->opts = xtables_merge_options(g->orig_opts, g->opts,
		                                t->extra_opts, &t->option_offset);
}

#endif
