#define KBUILD_MODNAME "aw-bpf"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "aw-bpf.h"

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

static __always_inline __u32 get_current_time(void)
{
    __u32 val = bpf_ktime_get_ns() >> 24;
    return val ? val : 1;
}

static inline void update_stats(struct counters *cnt, __u32 len, __u32 est_slot) {
    __u32 old_slot = cnt->est_slot;
    
    if (old_slot == est_slot) {
        cnt->cur_s_bytes += len;
    } else {
        __u32 new_prev = (old_slot == est_slot - 1) ? cnt->cur_s_bytes : 0;
        cnt->prev_s_bytes = new_prev;
        cnt->cur_s_bytes = len;
        cnt->est_slot = est_slot;
    }

    cnt->total_bytes += len;
    cnt->total_packets += 1;
}

static inline void process_packet(struct __sk_buff *skb) {
    __u32 current_time = get_current_time();
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return;

    // Handle IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) > data_end)
            return;

        // Process source IP (outgoing traffic)
        struct traffic_stats *s_stats = bpf_map_lookup_elem(&ipv4_map, &ip->saddr);
        if (s_stats) {
            update_stats(&s_stats->outgoing, skb->len, current_time);
        }

        // Process destination IP (incoming traffic)
        struct traffic_stats *d_stats = bpf_map_lookup_elem(&ipv4_map, &ip->daddr);
        if (d_stats) {
            update_stats(&d_stats->incoming, skb->len, current_time);
        }
    }
    // Handle IPv6
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)ip6 + sizeof(*ip6) > data_end)
            return;

        // Process source IPv6 (outgoing traffic)
        struct traffic_stats *s_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->saddr);
        if (s_stats6) {
            update_stats(&s_stats6->outgoing, skb->len, current_time);
        }

        // Process destination IPv6 (incoming traffic)
        struct traffic_stats *d_stats6 = bpf_map_lookup_elem(&ipv6_map, &ip6->daddr);
        if (d_stats6) {
            update_stats(&d_stats6->incoming, skb->len, current_time);
        }
    }
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *skb) {
    process_packet(skb);
    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
    process_packet(skb);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
