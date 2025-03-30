#define KBUILD_MODNAME "aw-bpf"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "aw-bpf.h"

extern int bpf_xdpi_skb_match(struct __sk_buff *skb, direction_t dir) __ksym;

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

// Map for TCP connections
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(pinning, 1);
    __type(key, struct bpf_sock_tuple);
    __type(value, struct xdpi_nf_conn);
    __uint(max_entries, 10240);
} tcp_conn_map SEC(".maps");

// Map for xdpi protocol descriptors
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(pinning, 1);
    __type(key, __u32);
    __type(value, struct xdpi_proto_desc);
    __uint(max_entries, XDPI_PROTO_TRAITS_MAX_SIZE);
} xdpi_proto_map SEC(".maps");

static __always_inline __u32 get_current_time(void)
{
    __u32 val = bpf_ktime_get_ns() / 1000000000;
    return val ? val : 1;
}

static inline void update_stats(struct counters *cnt, __u32 len, __u32 est_slot) {
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

static inline __u32 calc_rate_estimator(struct counters *cnt, __u32 now,  __u32 est_slot) {
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

static inline int process_packet(struct __sk_buff *skb, direction_t dir) {
    __u32 current_time = get_current_time();
    __u32 est_slot = current_time / RATE_ESTIMATOR;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return 0;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;
    
    // Check if protocol is TCP or UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return 0;
        
    
    if ((void *)(ip + 1) > data_end) // Ensure at least 1 byte of data
        return 0;

    {
        struct traffic_stats *s_stats = bpf_map_lookup_elem(&mac_map, eth->h_source);
        if (s_stats) {
            if (s_stats->outgoing_rate_limit && 
                s_stats->outgoing_rate_limit < calc_rate_estimator(&s_stats->outgoing, current_time, est_slot)) {
                return 1;
            }
            update_stats(&s_stats->outgoing, skb->len, est_slot);
        }
    }
     
    {
        struct traffic_stats *d_stats = bpf_map_lookup_elem(&mac_map, eth->h_dest);
        if (d_stats) {
            if (d_stats->incoming_rate_limit && 
                d_stats->incoming_rate_limit < calc_rate_estimator(&d_stats->incoming, current_time, est_slot)) {
                return 1;
            }
            update_stats(&d_stats->incoming, skb->len, est_slot);
        }
    }
    
    // Handle IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        
        bpf_xdpi_skb_match(skb, dir);

        // Process source IP (outgoing traffic)
        struct traffic_stats *s_stats = bpf_map_lookup_elem(&ipv4_map, &ip->saddr);
        if (s_stats) {
            if (s_stats->outgoing_rate_limit && 
                s_stats->outgoing_rate_limit < calc_rate_estimator(&s_stats->outgoing, current_time, est_slot)) {
                return 1;
            }
            update_stats(&s_stats->outgoing, skb->len, est_slot);
            
        }

        // Process destination IP (incoming traffic)
        struct traffic_stats *d_stats = bpf_map_lookup_elem(&ipv4_map, &ip->daddr);
        if (d_stats) {
            if (d_stats->incoming_rate_limit && 
                d_stats->incoming_rate_limit < calc_rate_estimator(&d_stats->incoming, current_time, est_slot)) {
                return 1;
            }
            update_stats(&d_stats->incoming, skb->len, est_slot);
        }
    }
    // Handle IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return 0;

        // Check if protocol is TCP or UDP
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return 0;
        // Calculate the IPv6 header length and check data length
        int ip6_hdr_len = sizeof(*ip6);
        if ((void *)ip6 + ip6_hdr_len + 1 > data_end) // Ensure at least 1 byte of data
            return 0;

        // Process source IPv6 (outgoing traffic)
        struct traffic_stats *s_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->saddr);
        if (s_stats6) {
            if (s_stats6->outgoing_rate_limit && 
                s_stats6->outgoing_rate_limit < calc_rate_estimator(&s_stats6->outgoing, current_time, est_slot)) {
                return 1;
            }
            update_stats(&s_stats6->outgoing, skb->len, est_slot);
        }

        // Process destination IPv6 (incoming traffic)
        struct traffic_stats *d_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->daddr);
        if (d_stats6) {
            if (d_stats6->incoming_rate_limit && 
                d_stats6->incoming_rate_limit < calc_rate_estimator(&d_stats6->incoming, current_time, est_slot)) {
                return 1;
            }
            update_stats(&d_stats6->incoming, skb->len, est_slot);
        }
    }

    return 0;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    return process_packet(skb, INGRESS) ? TC_ACT_SHOT : TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    return process_packet(skb, EGRESS) ? TC_ACT_SHOT : TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
