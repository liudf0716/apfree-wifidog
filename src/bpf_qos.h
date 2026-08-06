// SPDX-License-Identifier: GPL-3.0-only
/*
 * bpf_qos.h - Auth-path BPF IP QoS helpers (apply/remove for ipv4/ipv6 maps)
 */

#ifndef _BPF_QOS_H_
#define _BPF_QOS_H_

#include <stdint.h>

/**
 * Upsert client IPv4/IPv6 into aw-bpf maps with rate limits.
 * downrate_bps -> incoming_rate_limit (internet -> client)
 * uprate_bps   -> outgoing_rate_limit (client -> internet)
 * 0 bps means unlimited on that direction but the map entry is still created
 * so traffic stats can be collected.
 *
 * @return 0 if all applicable addresses applied successfully, -1 if any failed
 *         (auth path must not fail authentication on this).
 */
int aw_bpf_qos_apply_client(const char *ipv4, const char *ipv6,
			    uint32_t downrate_bps, uint32_t uprate_bps);

/**
 * Remove client IPv4/IPv6 entries from aw-bpf maps.
 * ENOENT / missing map is treated as success.
 */
int aw_bpf_qos_remove_client(const char *ipv4, const char *ipv6);

#endif /* _BPF_QOS_H_ */
