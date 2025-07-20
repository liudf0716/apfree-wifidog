// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#ifndef __DNS_BPF_H__
#define __DNS_BPF_H__

#include <linux/types.h>
#include <linux/in6.h>

// 定义最大DNS负载长度，与eBPF程序中的定义保持一致
#define MAX_DNS_PAYLOAD_LEN 512

// DNS统计信息结构体
struct dns_stats {
    __u64 dns_queries;      // DNS查询计数
    __u64 dns_responses;    // DNS响应计数
    __u64 dns_errors;       // DNS错误计数
    __u64 ipv4_packets;     // IPv4数据包计数
    __u64 ipv6_packets;     // IPv6数据包计数
};

// 原始DNS数据结构体，用于ring buffer传输
struct raw_dns_data {
    __u32 pkt_len;          // 整个DNS报文的长度
    __u8 ip_version;        // IP版本：4 for IPv4, 6 for IPv6
    __u16 src_port;         // UDP源端口
    __u16 dst_port;         // UDP目标端口
    __u32 timestamp;        // 时间戳（秒）
    union {
        __be32 saddr_v4;
        struct in6_addr saddr_v6;
    } src_ip;
    union {
        __be32 daddr_v4;
        struct in6_addr daddr_v6;
    } dst_ip;
    char dns_payload[MAX_DNS_PAYLOAD_LEN]; // DNS报文的原始字节
};

// DNS报文头结构体
struct dns_hdr {
    __be16 id;          // 查询标识
    __be16 flags;       // 标志位
    __be16 qdcount;     // 问题计数
    __be16 ancount;     // 回答计数
    __be16 nscount;     // 权威名称服务器计数
    __be16 arcount;     // 附加资源记录计数
};

// DNS标志位定义
#define DNS_QR_QUERY    0x0000  // 查询
#define DNS_QR_RESPONSE 0x8000  // 响应

// DNS响应码定义
#define DNS_RCODE_NOERROR   0   // 无错误
#define DNS_RCODE_FORMERR   1   // 格式错误
#define DNS_RCODE_SERVFAIL  2   // 服务器失败
#define DNS_RCODE_NXDOMAIN  3   // 名称不存在
#define DNS_RCODE_NOTIMP    4   // 未实现
#define DNS_RCODE_REFUSED   5   // 拒绝

// DNS资源记录类型定义
#define DNS_TYPE_A      1   // IPv4地址
#define DNS_TYPE_NS     2   // 名称服务器
#define DNS_TYPE_CNAME  5   // 规范名称
#define DNS_TYPE_SOA    6   // 权威开始
#define DNS_TYPE_PTR    12  // 指针记录
#define DNS_TYPE_MX     15  // 邮件交换
#define DNS_TYPE_TXT    16  // 文本记录
#define DNS_TYPE_AAAA   28  // IPv6地址

// DNS类定义
#define DNS_CLASS_IN    1   // Internet类

// eBPF map路径定义
#define DNS_RINGBUF_MAP_PATH    "/sys/fs/bpf/tc/globals/dns_ringbuf"
#define DNS_STATS_MAP_PATH      "/sys/fs/bpf/tc/globals/dns_stats_map"

// 工具函数宏
#define DNS_GET_QR(flags)       (((flags) >> 15) & 0x1)
#define DNS_GET_OPCODE(flags)   (((flags) >> 11) & 0xF)
#define DNS_GET_AA(flags)       (((flags) >> 10) & 0x1)
#define DNS_GET_TC(flags)       (((flags) >> 9) & 0x1)
#define DNS_GET_RD(flags)       (((flags) >> 8) & 0x1)
#define DNS_GET_RA(flags)       (((flags) >> 7) & 0x1)
#define DNS_GET_RCODE(flags)    ((flags) & 0xF)

// 检查是否为DNS响应的宏
#define IS_DNS_RESPONSE(flags)  (DNS_GET_QR(flags) == 1)
#define IS_DNS_QUERY(flags)     (DNS_GET_QR(flags) == 0)

#endif /* __DNS_BPF_H__ */
