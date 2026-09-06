// SPDX-License-Identifier: GPL-3.0-only
#ifndef _DNS_SNOOP_H_
#define _DNS_SNOOP_H_

/* Consumes aw-bpf dns_ringbuf_portal for captive-portal wildcard trust. */
void *thread_dns_snoop(void *arg);

/* Captive domain fast-answer map (captive_domain_map pinned by aw-bpf):
 * set the initial fake IP and learn real IPs from snooped DNS responses. */
int captive_domain_map_set(const char *domain, const char *ip);
int captive_domain_map_learn(const char *domain, const char *ip);

#endif
