// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

// 定义最大DNS负载长度，512字节足以覆盖大部分DNS响应
#define MAX_DNS_PAYLOAD_LEN 512

// 定义一个结构体用于发送原始DNS数据到用户空间
struct raw_dns_data {
    __u32 pkt_len;      // 整个UDP/DNS报文的长度，从UDP头开始
    __u8 ip_version;    // 4 for IPv4, 6 for IPv6
    __u16 src_port;     // UDP源端口
    __u16 dst_port;     // UDP目标端口
    __u32 timestamp;    // 时间戳
    union {
        __be32 saddr_v4;
        struct in6_addr saddr_v6;
    } src_ip;
    union {
        __be32 daddr_v4;
        struct in6_addr daddr_v6;
    } dst_ip;
    char dns_payload[MAX_DNS_PAYLOAD_LEN]; // 存储DNS报文的原始字节
};

// 定义DNS报文头结构体 (用于在eBPF中做初步判断)
struct dns_hdr {
    __be16 id;       // 查询标识
    __be16 flags;    // 标志位
    __be16 qdcount;  // 问题计数
    __be16 ancount;  // 回答计数
    __be16 nscount;  // 权威名称服务器计数
    __be16 arcount;  // 附加资源记录计数
};

// 定义ring buffer map用于向用户空间传输数据
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(pinning, 1);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} dns_ringbuf SEC(".maps");

// 统计map，记录DNS查询和响应的统计信息
struct dns_stats {
    __u64 dns_queries;
    __u64 dns_responses;
    __u64 dns_errors;
    __u64 ipv4_packets;
    __u64 ipv6_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(pinning, 1);
    __type(key, __u32);
    __type(value, struct dns_stats);
    __uint(max_entries, 1);
} dns_stats_map SEC(".maps");

// 内联函数：获取当前时间戳（秒）
static __always_inline __u32 get_current_time(void)
{
    __u64 ns = bpf_ktime_get_ns();
    return (__u32)(ns / 1000000000); // 转换为秒
}

// 内联函数：更新DNS统计信息
static __always_inline void update_dns_stats(__u8 is_response, __u8 ip_version, __u8 is_error)
{
    __u32 key = 0;
    struct dns_stats *stats = bpf_map_lookup_elem(&dns_stats_map, &key);
    if (!stats)
        return;
    
    if (is_response) {
        stats->dns_responses++;
    } else {
        stats->dns_queries++;
    }
    
    if (is_error) {
        stats->dns_errors++;
    }
    
    if (ip_version == 4) {
        stats->ipv4_packets++;
    } else if (ip_version == 6) {
        stats->ipv6_packets++;
    }
}

// 内联函数：检查DNS标志位是否表示错误
static __always_inline __u8 is_dns_error(__be16 flags)
{
    __u16 rcode = bpf_ntohs(flags) & 0x000F; // 取响应码（RCODE）
    return (rcode != 0); // 0表示无错误，其他值表示有错误
}

// 主要的DNS监控函数
static __always_inline int dns_monitor_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 h_proto = bpf_ntohs(eth->h_proto);
    __u8 ip_proto;
    __u16 ip_hdr_len;
    __u8 ip_version;
    __be32 src_ip_v4 = 0;
    __be32 dst_ip_v4 = 0;
    struct in6_addr src_ip_v6 = {};
    struct in6_addr dst_ip_v6 = {};

    // 处理IPv4数据包
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;
        
        ip_proto = ip->protocol;
        ip_hdr_len = ip->ihl * 4;
        ip_version = 4;
        src_ip_v4 = ip->saddr;
        dst_ip_v4 = ip->daddr;
    }
    // 处理IPv6数据包
    else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ipv6 = data + sizeof(*eth);
        if ((void *)(ipv6 + 1) > data_end)
            return TC_ACT_OK;
        
        ip_proto = ipv6->nexthdr;
        ip_hdr_len = sizeof(struct ipv6hdr);
        ip_version = 6;
        
        // 安全地复制IPv6地址
        __builtin_memcpy(&src_ip_v6, &ipv6->saddr, sizeof(struct in6_addr));
        __builtin_memcpy(&dst_ip_v6, &ipv6->daddr, sizeof(struct in6_addr));

        // 简化处理IPv6扩展头：只处理UDP紧跟在IPv6头之后的情况
        if (ip_proto != IPPROTO_UDP) {
            return TC_ACT_OK;
        }
    } else {
        return TC_ACT_OK; // 不是IPv4也不是IPv6
    }

    // 只处理UDP协议
    if (ip_proto != IPPROTO_UDP)
        return TC_ACT_OK;

    // 解析UDP头
    struct udphdr *udp = data + sizeof(*eth) + ip_hdr_len;
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    __u16 src_port = bpf_ntohs(udp->source);
    __u16 dst_port = bpf_ntohs(udp->dest);

    // 检查是否为DNS流量（端口53）
    if (src_port != 53 && dst_port != 53)
        return TC_ACT_OK;

    // DNS报文起始位置
    void *dns_payload_start = (void *)udp + sizeof(*udp);
    if ((void *)(dns_payload_start + sizeof(struct dns_hdr)) > data_end)
        return TC_ACT_OK;

    struct dns_hdr *dns_h = (struct dns_hdr *)dns_payload_start;

    // 检查DNS标志位：QR位确定是查询还是响应
    __u16 flags = bpf_ntohs(dns_h->flags);
    __u8 is_response = (flags >> 15) & 0x1; // QR位
    __u8 is_error = is_dns_error(dns_h->flags);

    // 更新统计信息
    update_dns_stats(is_response, ip_version, is_error);

    // 只监控DNS响应，过滤掉查询
    if (!is_response) return TC_ACT_OK;

    // 计算DNS负载的实际长度
    __u32 dns_payload_len = data_end - dns_payload_start;
    if (dns_payload_len > MAX_DNS_PAYLOAD_LEN) {
        dns_payload_len = MAX_DNS_PAYLOAD_LEN; // 截断到最大允许长度
    }

    // 分配ring buffer空间
    struct raw_dns_data *output_data = bpf_ringbuf_reserve(&dns_ringbuf, sizeof(*output_data), 0);
    if (!output_data) {
        return TC_ACT_OK; // 无法获取ring buffer空间
    }

    // 填充数据到ring buffer
    output_data->pkt_len = dns_payload_len;
    output_data->ip_version = ip_version;
    output_data->src_port = src_port;
    output_data->dst_port = dst_port;
    output_data->timestamp = get_current_time();

    // 根据IP版本设置地址信息
    if (ip_version == 4) {
        output_data->src_ip.saddr_v4 = src_ip_v4;
        output_data->dst_ip.daddr_v4 = dst_ip_v4;
    } else { // IPv6
        __builtin_memcpy(&output_data->src_ip.saddr_v6, &src_ip_v6, sizeof(struct in6_addr));
        __builtin_memcpy(&output_data->dst_ip.daddr_v6, &dst_ip_v6, sizeof(struct in6_addr));
    }
    
    // 将DNS负载的原始字节安全地拷贝到ring buffer
    if (dns_payload_len > 0 && dns_payload_len <= MAX_DNS_PAYLOAD_LEN) {
        // 计算DNS负载在skb中的偏移量
        __u32 dns_offset = sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct udphdr);
        
        // 额外的长度检查，确保长度至少为1且不超过最大值
        if (dns_payload_len >= 1 && dns_payload_len <= 512) {
            // 使用bpf_skb_load_bytes替代bpf_probe_read_kernel
            // 这对BPF验证器更友好，因为它专门用于从skb读取数据
            int ret = bpf_skb_load_bytes(skb, dns_offset, output_data->dns_payload, dns_payload_len);
            if (ret < 0) {
                // 如果读取失败，仍然提交数据但DNS负载为空
                output_data->pkt_len = 0;
            }
        }
    }

    // 提交数据到ring buffer
    bpf_ringbuf_submit(output_data, 0);

    return TC_ACT_OK; // 继续处理数据包
}

// TC ingress程序入口点 - 专门监控DNS响应
SEC("tc/dns/ingress")
int dns_monitor_ingress(struct __sk_buff *skb)
{
    return dns_monitor_main(skb);
}

char _license[] SEC("license") = "GPL";
