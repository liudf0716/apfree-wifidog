// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#define KBUILD_MODNAME "aw-bpf"
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

/* 定义 linux/compiler.h 中的常用宏，避免包含该头文件 */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#include "aw-bpf.h"

#define DEBUG 0  // Set to 1 to enable debug prints

#if DEBUG
#define BPF_DEBUG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define BPF_DEBUG(fmt, ...) do {} while (0)
#endif

#define UNKNOWN_SID 7777  // Default SID for unidentified protocols
#define MIN_TCP_DATA_SIZE 10  // Minimum TCP data length for protocol detection

struct bpf_ct_opts {
    __u32 netns_id;
    __u32 error;
    __u8 l4proto;
    __u8 dir;
    __u8 reserved[2];
};

extern int bpf_xdpi_skb_match(struct __sk_buff *skb, int dir) __ksym;

// Map for IPv4 addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, __be32);
    __type(value, struct traffic_stats);
    __uint(max_entries, 1024);
} ipv4_map SEC(".maps");

// Map for IPv6 addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, struct in6_addr);
    __type(value, struct traffic_stats);
    __uint(max_entries, 1024);
} ipv6_map SEC(".maps");

// Map for mac addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, struct mac_addr);
    __type(value, struct traffic_stats);
    __uint(max_entries, 1024);
} mac_map SEC(".maps");

#ifdef ENABLE_XDPI_FEATURE
// Map for TCP connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, struct bpf_sock_tuple);
    __type(value, struct xdpi_nf_conn);
    __uint(max_entries, 10240);
} tcp_conn_map SEC(".maps");

// Map for UDP connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, struct bpf_sock_tuple);
    __type(value, struct xdpi_nf_conn);
    __uint(max_entries, 10240);
} udp_conn_map SEC(".maps");
#endif // ENABLE_XDPI_FEATURE

// Map for xdpi protocol stats
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, __u32);
    __type(value, struct traffic_stats);
    __uint(max_entries, 1024);
} xdpi_l7_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(pinning, 1);
    __uint(max_entries, 1 << 24);
} session_events_map SEC(".maps");

// Program array map for tail calls to dns-bpf
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(pinning, 1);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} prog_array_map SEC(".maps");

static __always_inline __u32 get_current_time(void)
{
    __u32 val = bpf_ktime_get_ns() / 1000000000;
    return val ? val : 1;
}

static __always_inline void update_stats(struct counters *cnt, __u32 len, __u32 est_slot) {
    __u32 old_slot = cnt->est_slot;
    
    if (old_slot == est_slot) {
        cnt->cur_s_bytes += len;
    } else {
        __u32 new_prev = (old_slot == est_slot - 1) ? cnt->cur_s_bytes : 0;
        cnt->prev_s_bytes = new_prev;
        cnt->cur_s_bytes = 0;
        cnt->est_slot = est_slot;
    }

    cnt->total_bytes += len;
    cnt->total_packets += 1;
}

#ifdef __KERNEL__
static __always_inline __u32 calc_rate_estimator(struct counters *cnt, __u32 now, __u32 est_slot) {
	__u32 rate = 0;
	__u32 cur_bytes = 0;
	__u32 delta = RATE_ESTIMATOR - (now % RATE_ESTIMATOR);
	__u32 ratio = RATE_ESTIMATOR * SMOOTH_VALUE / delta;

    if (cnt->est_slot == est_slot) {
        rate = cnt->prev_s_bytes;
        cur_bytes = cnt->cur_s_bytes;
    } else if (cnt->est_slot == est_slot - 1) {
        rate = cnt->cur_s_bytes;
    } else {
        return 0;
    }

    rate = (rate * SMOOTH_VALUE) / ratio;
    rate += cur_bytes;

	return rate * 8 / RATE_ESTIMATOR;
}
#endif

static __always_inline int edt_sched_departure(struct __sk_buff *skb, struct rate_limit *info)
{
	__u64 tokens, now, t_last, elapsed_time, bps;

	now = bpf_ktime_get_ns();
	bps = READ_ONCE(info->bps);
    bps = bps>>3;
    t_last = READ_ONCE(info->t_last);
    tokens = READ_ONCE(info->tokens);
    elapsed_time = now - t_last;
    if (elapsed_time > 0) {
        tokens += elapsed_time * bps / NSEC_PER_SEC;
        if (tokens > bps) {
            tokens = bps;
        }
    } 
    if (tokens >= skb->wire_len) {
        tokens -= skb->wire_len;
    } else {
        return 1;
    }
    WRITE_ONCE(info->tokens, tokens);
    WRITE_ONCE(info->t_last, now);
    return 0;
}

#ifdef ENABLE_XDPI_FEATURE
static __always_inline void set_ip(__u32 *dst, const struct in6_addr *src)
{
    dst[0] = src->in6_u.u6_addr32[0];
    dst[1] = src->in6_u.u6_addr32[1];
    dst[2] = src->in6_u.u6_addr32[2];
    dst[3] = src->in6_u.u6_addr32[3];
}

static __always_inline int tcp_conn_timer_cb(void *map, struct bpf_sock_tuple *key, struct xdpi_nf_conn *val) {
    if (!key || !val) {
        BPF_DEBUG("Timer CB: Invalid arguments\n");
        return 0;
    }

    __u32 now_sec = get_current_time();
    now_sec = now_sec ? now_sec : 1; 

    if (now_sec >= val->last_time + TCP_CONN_TIMEOUT_SEC) {
        bpf_timer_cancel(&val->timer);
        bpf_map_delete_elem(map, key);
    } else {
        bpf_timer_start(&val->timer, TCP_CONN_TIMEOUT_NS, 0);
    }

    return 0;
}

static __always_inline int handle_tcp_packet(struct __sk_buff *skb, direction_t dir, 
                                            struct bpf_sock_tuple *bpf_tuple,
                                            int tcp_data_len, __u32 current_time, __u32 est_slot,
                                            __u8 ip_version)
{
    long err = 0;
    struct xdpi_nf_conn *conn = bpf_map_lookup_elem(&tcp_conn_map, bpf_tuple);
    int sid = 0;
    
    // Check if we already have a connection with SID
    if (conn && conn->sid > 0) {
        conn->last_time = current_time;
        sid = conn->sid; // sid is from existing connection

        if (!conn->event_sent) { // Check if event has been sent
            if (bpf_tuple && sid != 0) { // Ensure sid is valid (it should be, as conn->sid > 0)
                struct session_data_t *event_data;
                event_data = bpf_ringbuf_reserve(&session_events_map, sizeof(*event_data), 0);
                if (event_data) {
                    event_data->sid = sid;
                    event_data->ip_version = ip_version;
                    event_data->proto = IPPROTO_TCP;
                    if (ip_version == 4) {
                        event_data->addrs.v4.saddr_v4 = bpf_tuple->ipv4.saddr;
                        event_data->addrs.v4.daddr_v4 = bpf_tuple->ipv4.daddr;
                        event_data->sport = bpf_tuple->ipv4.sport;
                        event_data->dport = bpf_tuple->ipv4.dport;
                        bpf_ringbuf_submit(event_data, 0);
                        conn->event_sent = 1; // Mark as sent for existing connection
                    } else if (ip_version == 6) {
                        __builtin_memcpy(event_data->addrs.v6.saddr_v6, bpf_tuple->ipv6.saddr, 16);
                        __builtin_memcpy(event_data->addrs.v6.daddr_v6, bpf_tuple->ipv6.daddr, 16);
                        event_data->sport = bpf_tuple->ipv6.sport;
                        event_data->dport = bpf_tuple->ipv6.dport;
                        bpf_ringbuf_submit(event_data, 0);
                        conn->event_sent = 1; // Mark as sent for existing connection
                    } else {
                        // Invalid IP version, discard the reserved space
                        bpf_ringbuf_discard(event_data, 0);
                    }
                } else {
                    BPF_DEBUG("Failed to reserve ring buffer space for event");
                }
            }
        }
    } else {
        // Try to identify protocol
        sid = bpf_xdpi_skb_match(skb, dir); // local sid variable
        struct xdpi_nf_conn new_conn = { .pkt_seen = 1, .last_time = current_time, .event_sent = 0 };
        BPF_DEBUG("sid: %d dir: %d tcp_data_len: %d", sid, dir, tcp_data_len);

        if (sid > 0) {
            new_conn.sid = sid;
        } else {
            new_conn.sid = UNKNOWN_SID;
            sid = UNKNOWN_SID; // Ensure local sid variable also holds UNKNOWN_SID
        }

        // Send event for new connection if SID is valid, before adding to map
        if (bpf_tuple && new_conn.sid != 0) {
            struct session_data_t *event_data;
            event_data = bpf_ringbuf_reserve(&session_events_map, sizeof(*event_data), 0);
            if (event_data) {
                event_data->sid = sid;
                event_data->ip_version = ip_version;
                event_data->proto = IPPROTO_TCP;
                if (ip_version == 4) {
                    event_data->addrs.v4.saddr_v4 = bpf_tuple->ipv4.saddr;
                    event_data->addrs.v4.daddr_v4 = bpf_tuple->ipv4.daddr;
                    event_data->sport = bpf_tuple->ipv4.sport;
                    event_data->dport = bpf_tuple->ipv4.dport;
                    bpf_ringbuf_submit(event_data, 0);
                    new_conn.event_sent = 1; // Mark as sent before adding to map
                } else if (ip_version == 6) {
                    __builtin_memcpy(event_data->addrs.v6.saddr_v6, bpf_tuple->ipv6.saddr, 16);
                    __builtin_memcpy(event_data->addrs.v6.daddr_v6, bpf_tuple->ipv6.daddr, 16);
                    event_data->sport = bpf_tuple->ipv6.sport;
                    event_data->dport = bpf_tuple->ipv6.dport;
                    bpf_ringbuf_submit(event_data, 0);
                    new_conn.event_sent = 1; // Mark as sent before adding to map
                } else {
                    // Invalid IP version, discard the reserved space
                    bpf_ringbuf_discard(event_data, 0);
                }
            } else {
                BPF_DEBUG("Failed to reserve ring buffer space for new connection event");
            }
        }
        
        // Add connection to the map
        err = bpf_map_update_elem(&tcp_conn_map, bpf_tuple, &new_conn, BPF_NOEXIST);
        if (err == 0) {
            struct xdpi_nf_conn *conn = bpf_map_lookup_elem(&tcp_conn_map, bpf_tuple);
            if (conn) {
#ifdef CLOCK_MONOTONIC
                bpf_timer_init(&conn->timer, &tcp_conn_map, CLOCK_MONOTONIC);
#else
                bpf_timer_init(&conn->timer, &tcp_conn_map, 0); // 使用默认时钟
#endif
                bpf_timer_set_callback(&conn->timer, tcp_conn_timer_cb);
                bpf_timer_start(&conn->timer, TCP_CONN_TIMEOUT_NS, 0);
            }
        } else {
            BPF_DEBUG("Failed to update TCP connection map: %ld", err);
        }
    }

    // Update protocol stats based on SID
    // Note: The local 'sid' variable is correctly set by the logic above for both existing and new connections.
    struct traffic_stats *proto_stats = bpf_map_lookup_elem(&xdpi_l7_map, &sid);
    if (!proto_stats) {
        struct traffic_stats new_proto_stats = { 0 };
        bpf_map_update_elem(&xdpi_l7_map, &sid, &new_proto_stats, BPF_NOEXIST);
        proto_stats = bpf_map_lookup_elem(&xdpi_l7_map, &sid);
    }

    // Apply rate limits and update stats based on direction
    if (dir == INGRESS) {
        if (proto_stats && proto_stats->outgoing_rate_limit.bps) {
            if (edt_sched_departure(skb, &proto_stats->outgoing_rate_limit)) {
                return 1;
            }
        }
        if (proto_stats) update_stats(&proto_stats->outgoing, skb->len, est_slot);
    } else {
        if (proto_stats && proto_stats->incoming_rate_limit.bps) {
            if (edt_sched_departure(skb, &proto_stats->incoming_rate_limit)) {
                return 1;
            }
        }
        if (proto_stats) update_stats(&proto_stats->incoming, skb->len, est_slot);
    }
    
    return 0;
}

static __always_inline int udp_conn_timer_cb(void *map, struct bpf_sock_tuple *key, struct xdpi_nf_conn *val) {
    if (!key || !val) {
        BPF_DEBUG("Timer CB: Invalid arguments\n");
        return 0;
    }

    __u32 now_sec = get_current_time();
    now_sec = now_sec ? now_sec : 1; 

    if (now_sec >= val->last_time + UDP_CONN_TIMEOUT_SEC) {
        bpf_timer_cancel(&val->timer);
        bpf_map_delete_elem(map, key);
    } else {
        bpf_timer_start(&val->timer, UDP_CONN_TIMEOUT_NS, 0);
    }

    return 0;
}

static __always_inline int handle_udp_packet(struct __sk_buff *skb, direction_t dir, 
                                           struct bpf_sock_tuple *bpf_tuple,
                                           __u32 current_time, __u32 est_slot,
                                           __u8 ip_version)
{
    long err = 0;
    struct xdpi_nf_conn *conn = bpf_map_lookup_elem(&udp_conn_map, bpf_tuple);
    int sid = 0;
    
    if (conn && conn->sid > 0) {
        conn->last_time = current_time;
        sid = conn->sid;

        if (!conn->event_sent) {
            if (bpf_tuple && sid != 0) {
                struct session_data_t *event_data;
                event_data = bpf_ringbuf_reserve(&session_events_map, sizeof(*event_data), 0);
                if (event_data) {
                    event_data->sid = sid;
                    event_data->ip_version = ip_version;
                    event_data->proto = IPPROTO_UDP;
                    if (ip_version == 4) {
                        event_data->addrs.v4.saddr_v4 = bpf_tuple->ipv4.saddr;
                        event_data->addrs.v4.daddr_v4 = bpf_tuple->ipv4.daddr;
                        event_data->sport = bpf_tuple->ipv4.sport;
                        event_data->dport = bpf_tuple->ipv4.dport;
                        bpf_ringbuf_submit(event_data, 0);
                        conn->event_sent = 1;
                    } else if (ip_version == 6) {
                        __builtin_memcpy(event_data->addrs.v6.saddr_v6, bpf_tuple->ipv6.saddr, 16);
                        __builtin_memcpy(event_data->addrs.v6.daddr_v6, bpf_tuple->ipv6.daddr, 16);
                        event_data->sport = bpf_tuple->ipv6.sport;
                        event_data->dport = bpf_tuple->ipv6.dport;
                        bpf_ringbuf_submit(event_data, 0);
                        conn->event_sent = 1;
                    } else {
                        // Invalid IP version, discard the reserved space
                        bpf_ringbuf_discard(event_data, 0);
                    }
                } else {
                    BPF_DEBUG("Failed to reserve ring buffer space for UDP event");
                }
            }
        }
    } else {
        sid = bpf_xdpi_skb_match(skb, dir);
        struct xdpi_nf_conn new_conn = { .pkt_seen = 1, .last_time = current_time, .event_sent = 0 };
        BPF_DEBUG("sid: %d dir: %d", sid, dir);

        if (sid > 0) {
            new_conn.sid = sid;
        } else {
            new_conn.sid = UNKNOWN_SID;
            sid = UNKNOWN_SID;
        }

        if (bpf_tuple && new_conn.sid != 0) {
            struct session_data_t *event_data;
            event_data = bpf_ringbuf_reserve(&session_events_map, sizeof(*event_data), 0);
            if (event_data) {
                event_data->sid = sid;
                event_data->ip_version = ip_version;
                event_data->proto = IPPROTO_UDP;
                if (ip_version == 4) {
                    event_data->addrs.v4.saddr_v4 = bpf_tuple->ipv4.saddr;
                    event_data->addrs.v4.daddr_v4 = bpf_tuple->ipv4.daddr;
                    event_data->sport = bpf_tuple->ipv4.sport;
                    event_data->dport = bpf_tuple->ipv4.dport;
                    bpf_ringbuf_submit(event_data, 0);
                    new_conn.event_sent = 1;
                } else if (ip_version == 6) {
                    __builtin_memcpy(event_data->addrs.v6.saddr_v6, bpf_tuple->ipv6.saddr, 16);
                    __builtin_memcpy(event_data->addrs.v6.daddr_v6, bpf_tuple->ipv6.daddr, 16);
                    event_data->sport = bpf_tuple->ipv6.sport;
                    event_data->dport = bpf_tuple->ipv6.dport;
                    bpf_ringbuf_submit(event_data, 0);
                    new_conn.event_sent = 1;
                } else {
                    // Invalid IP version, discard the reserved space
                    bpf_ringbuf_discard(event_data, 0);
                }
            } else {
                BPF_DEBUG("Failed to reserve ring buffer space for new UDP connection event");
            }
        }
        
        err = bpf_map_update_elem(&udp_conn_map, bpf_tuple, &new_conn, BPF_NOEXIST);
        if (err == 0) {
            struct xdpi_nf_conn *ret_conn = bpf_map_lookup_elem(&udp_conn_map, bpf_tuple); // Renamed to avoid conflict
            if (ret_conn) { // Check if ret_conn is valid
#ifdef CLOCK_MONOTONIC
                bpf_timer_init(&ret_conn->timer, &udp_conn_map, CLOCK_MONOTONIC);
#else
                bpf_timer_init(&ret_conn->timer, &udp_conn_map, 0);
#endif
                bpf_timer_set_callback(&ret_conn->timer, udp_conn_timer_cb);
                bpf_timer_start(&ret_conn->timer, UDP_CONN_TIMEOUT_NS, 0);
            }
        } else {
            BPF_DEBUG("Failed to update UDP connection map: %ld", err);
        }
    }

    struct traffic_stats *proto_stats = bpf_map_lookup_elem(&xdpi_l7_map, &sid);
    if (proto_stats) {
        if (dir == INGRESS) {
            update_stats(&proto_stats->incoming, skb->len, est_slot);
        } else {
            update_stats(&proto_stats->outgoing, skb->len, est_slot);
        }
    }

    return 0;
}
#endif // ENABLE_XDPI_FEATURE

static inline int process_packet(struct __sk_buff *skb, direction_t dir) {
    __u32 current_time = get_current_time();
    __u32 est_slot = current_time / RATE_ESTIMATOR;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    long err = 0;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return 0;

    {
        struct traffic_stats *s_stats = bpf_map_lookup_elem(&mac_map, eth->h_source);
        if (s_stats) {
            if (s_stats->outgoing_rate_limit.bps) {
                if (edt_sched_departure(skb, &s_stats->outgoing_rate_limit)) {
                    return 1;
                }
            }
            update_stats(&s_stats->outgoing, skb->wire_len, est_slot);
        }
    }
     
    {
        struct traffic_stats *d_stats = bpf_map_lookup_elem(&mac_map, eth->h_dest);
        if (d_stats) {
            if (d_stats->incoming_rate_limit.bps) {
                if (edt_sched_departure(skb, &d_stats->incoming_rate_limit)) {
                    return 1;
                }
            } 
            update_stats(&d_stats->incoming, skb->wire_len, est_slot);
        }
    }
    
    // Handle IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return 0;

#ifdef ENABLE_XDPI_FEATURE
        if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + sizeof(*ip));
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return 0;
            __u32 tcp_hdr_len = tcp->doff * 4;
            __u32 ip_hdr_len = ip->ihl * 4;
            
            // Check for TCP session termination first
            if (tcp->fin || tcp->rst) {
                struct bpf_sock_tuple bpf_tuple = {};
                if (dir == INGRESS) {
                    bpf_tuple.ipv4.saddr = ip->saddr;
                    bpf_tuple.ipv4.daddr = ip->daddr;
                } else {
                    bpf_tuple.ipv4.saddr = ip->daddr;
                    bpf_tuple.ipv4.daddr = ip->saddr;
                }
                bpf_tuple.ipv4.sport = dir == INGRESS ? tcp->source : tcp->dest;
                bpf_tuple.ipv4.dport = dir == INGRESS ? tcp->dest : tcp->source;
                
                // Remove the session from tcp_conn_map
                bpf_map_delete_elem(&tcp_conn_map, &bpf_tuple);
                BPF_DEBUG("tcp_fin_rst: %d %d", tcp->fin, tcp->rst);
                return 0;
            }

            __s32 tcp_data_len = skb->len - sizeof(*eth) - ip_hdr_len - tcp_hdr_len;
            if (tcp_data_len < MIN_TCP_DATA_SIZE)
                return 0;
            
            struct bpf_sock_tuple bpf_tuple = {};
            bpf_tuple.ipv4.saddr = dir == INGRESS? ip->saddr: ip->daddr;
            bpf_tuple.ipv4.daddr = dir == INGRESS? ip->daddr: ip->saddr;
            bpf_tuple.ipv4.sport = dir == INGRESS ? tcp->source : tcp->dest;
            bpf_tuple.ipv4.dport = dir == INGRESS ? tcp->dest : tcp->source;
            
            if (handle_tcp_packet(skb, dir, &bpf_tuple, tcp_data_len, current_time, est_slot, 4)) { // Pass 4 for IPv4
                return 1;
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip));
            if ((void *)udp + sizeof(*udp) > data_end)
                return 0;
            
            struct bpf_sock_tuple bpf_tuple = {};
            bpf_tuple.ipv4.saddr = dir == INGRESS ? ip->saddr : ip->daddr;
            bpf_tuple.ipv4.daddr = dir == INGRESS ? ip->daddr : ip->saddr;
            bpf_tuple.ipv4.sport = dir == INGRESS ? udp->source : udp->dest;
            bpf_tuple.ipv4.dport = dir == INGRESS ? udp->dest : udp->source;
            
            if (handle_udp_packet(skb, dir, &bpf_tuple, current_time, est_slot, 4)) { // Pass 4 for IPv4
                return 1;
            }
        }
#endif // ENABLE_XDPI_FEATURE

        // Process source IP (outgoing traffic)
        struct traffic_stats *s_stats = bpf_map_lookup_elem(&ipv4_map, &ip->saddr);
        if (s_stats) {
            if (s_stats->outgoing_rate_limit.bps) {
                if (edt_sched_departure(skb, &s_stats->outgoing_rate_limit)) {
                    return 1;
                }
            } 
            update_stats(&s_stats->outgoing, skb->len, est_slot);    
        }

        // Process destination IP (incoming traffic)
        struct traffic_stats *d_stats = bpf_map_lookup_elem(&ipv4_map, &ip->daddr);
        if (d_stats) {
            if (d_stats->incoming_rate_limit.bps) {
                if (edt_sched_departure(skb, &d_stats->incoming_rate_limit)) {
                    return 1;
                }
            } 
            update_stats(&d_stats->incoming, skb->len, est_slot);
        }
    }
    // Handle IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return 0;
#ifdef ENABLE_XDPI_FEATURE
        if (ip6->nexthdr == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(*eth) + sizeof(*ip6));
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return 0;
            __u32 tcp_hdr_len = tcp->doff * 4;
            
            // Check for TCP session termination first
            if (tcp->fin || tcp->rst) {
                struct bpf_sock_tuple bpf_tuple = {};
                if (dir == INGRESS) {
                    set_ip(bpf_tuple.ipv6.saddr, &ip6->saddr);
                    set_ip(bpf_tuple.ipv6.daddr, &ip6->daddr);
                } else {
                    set_ip(bpf_tuple.ipv6.saddr, &ip6->daddr);
                    set_ip(bpf_tuple.ipv6.daddr, &ip6->saddr);
                }
                bpf_tuple.ipv6.sport = dir == INGRESS ? tcp->source : tcp->dest;
                bpf_tuple.ipv6.dport = dir == INGRESS ? tcp->dest : tcp->source;
                
                // Remove the session from tcp_conn_map
                bpf_map_delete_elem(&tcp_conn_map, &bpf_tuple);
                BPF_DEBUG("tcp_fin_rst: %d %d", tcp->fin, tcp->rst);
                return 0;
            }

            __s32 tcp_data_len = skb->len - sizeof(*eth) - sizeof(*ip6) - tcp_hdr_len;
            if (tcp_data_len < MIN_TCP_DATA_SIZE)
                return 0;
            
            struct bpf_sock_tuple bpf_tuple = {};
            if (dir == INGRESS) {
                set_ip(bpf_tuple.ipv6.saddr, &ip6->saddr);
                set_ip(bpf_tuple.ipv6.daddr, &ip6->daddr);
            } else {
                set_ip(bpf_tuple.ipv6.saddr, &ip6->daddr);
                set_ip(bpf_tuple.ipv6.daddr, &ip6->saddr);
            }
            bpf_tuple.ipv6.sport = dir == INGRESS ? tcp->source : tcp->dest;
            bpf_tuple.ipv6.dport = dir == INGRESS ? tcp->dest : tcp->source;
            
            if (handle_tcp_packet(skb, dir, &bpf_tuple, tcp_data_len, current_time, est_slot, 6)) { // Pass 6 for IPv6
                return 1;
            }
        } else if (ip6->nexthdr == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)(data + sizeof(*eth) + sizeof(*ip6));
            if ((void *)udp + sizeof(*udp) > data_end)
                return 0;
            
            struct bpf_sock_tuple bpf_tuple = {};
            if (dir == INGRESS) {
                set_ip(bpf_tuple.ipv6.saddr, &ip6->saddr);
                set_ip(bpf_tuple.ipv6.daddr, &ip6->daddr);
            } else {
                set_ip(bpf_tuple.ipv6.saddr, &ip6->daddr);
                set_ip(bpf_tuple.ipv6.daddr, &ip6->saddr);
            }
            bpf_tuple.ipv6.sport = dir == INGRESS ? udp->source : udp->dest;
            bpf_tuple.ipv6.dport = dir == INGRESS ? udp->dest : udp->source;
            
            if (handle_udp_packet(skb, dir, &bpf_tuple, current_time, est_slot, 6)) { // Pass 6 for IPv6
                return 1;
            }
        }
#endif // ENABLE_XDPI_FEATURE

        // Process source IPv6 (outgoing traffic)
        struct traffic_stats *s_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->saddr);
        if (s_stats6) {
            if (s_stats6->outgoing_rate_limit.bps) {
                if (edt_sched_departure(skb, &s_stats6->outgoing_rate_limit)) {
                    return 1;
                }
            }
            update_stats(&s_stats6->outgoing, skb->len, est_slot);
        }

        // Process destination IPv6 (incoming traffic)
        struct traffic_stats *d_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->daddr);
        if (d_stats6) {
            if (d_stats6->incoming_rate_limit.bps) {
                if (edt_sched_departure(skb, &d_stats6->incoming_rate_limit)) {
                    return 1;
                }
            } 
            update_stats(&d_stats6->incoming, skb->len, est_slot);
        }
    }
    return 0;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    int result = process_packet(skb, INGRESS);
    if (result) {
        return TC_ACT_SHOT;
    }
    
    // No DNS processing needed for ingress (DNS responses come from egress)
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    int result = process_packet(skb, EGRESS);
    if (result) {
        return TC_ACT_SHOT;
    }
    
    // Tail call to dns-bpf program for DNS response processing
    // Index 0 is reserved for DNS egress handler (DNS responses)
    bpf_tail_call(skb, &prog_array_map, 0);
    
    // If tail call fails, continue with normal processing
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
