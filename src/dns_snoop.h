// SPDX-License-Identifier: GPL-3.0-only
#ifndef _DNS_SNOOP_H_
#define _DNS_SNOOP_H_

/* Consumes aw-bpf dns_ringbuf_portal for captive-portal wildcard trust. */
void *thread_dns_snoop(void *arg);

#endif
