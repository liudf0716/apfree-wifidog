// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "dns-bpf.h"

static volatile int stop = 0;

// 信号处理函数
static void signal_handler(int sig)
{
    stop = 1;
}

// 打印IPv4地址
static void print_ipv4_addr(__be32 addr, char *buf, size_t buf_size)
{
    struct in_addr in_addr = { .s_addr = addr };
    inet_ntop(AF_INET, &in_addr, buf, buf_size);
}

// 打印IPv6地址
static void print_ipv6_addr(const struct in6_addr *addr, char *buf, size_t buf_size)
{
    inet_ntop(AF_INET6, addr, buf, buf_size);
}

// 打印时间戳
static void print_timestamp(__u32 timestamp)
{
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    printf("%04d-%02d-%02d %02d:%02d:%02d",
           tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
           tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

// 解析并打印DNS头信息
static void print_dns_header(const struct dns_hdr *dns_hdr)
{
    __u16 flags = ntohs(dns_hdr->flags);
    
    printf("  DNS Header:\n");
    printf("    ID: 0x%04x\n", ntohs(dns_hdr->id));
    printf("    Flags: 0x%04x", flags);
    
    if (IS_DNS_RESPONSE(flags)) {
        printf(" (Response)");
    } else {
        printf(" (Query)");
    }
    
    __u8 rcode = DNS_GET_RCODE(flags);
    if (rcode != DNS_RCODE_NOERROR) {
        printf(" - Error: ");
        switch (rcode) {
            case DNS_RCODE_FORMERR:  printf("Format Error"); break;
            case DNS_RCODE_SERVFAIL: printf("Server Failure"); break;
            case DNS_RCODE_NXDOMAIN: printf("Name Error"); break;
            case DNS_RCODE_NOTIMP:   printf("Not Implemented"); break;
            case DNS_RCODE_REFUSED:  printf("Refused"); break;
            default: printf("Unknown (%d)", rcode); break;
        }
    }
    printf("\n");
    
    printf("    Questions: %d, Answers: %d, Authority: %d, Additional: %d\n",
           ntohs(dns_hdr->qdcount), ntohs(dns_hdr->ancount),
           ntohs(dns_hdr->nscount), ntohs(dns_hdr->arcount));
}

// 处理DNS数据事件
static int handle_dns_event(void *ctx, void *data, size_t data_sz)
{
    const struct raw_dns_data *dns_data = data;
    char src_ip_str[INET6_ADDRSTRLEN];
    char dst_ip_str[INET6_ADDRSTRLEN];
    
    if (data_sz < sizeof(*dns_data)) {
        fprintf(stderr, "Invalid data size: %zu\n", data_sz);
        return 0;
    }
    
    printf("=== DNS Packet Captured ===\n");
    
    // 打印时间戳
    printf("Time: ");
    print_timestamp(dns_data->timestamp);
    printf("\n");
    
    // 打印IP信息
    if (dns_data->ip_version == 4) {
        print_ipv4_addr(dns_data->src_ip.saddr_v4, src_ip_str, sizeof(src_ip_str));
        print_ipv4_addr(dns_data->dst_ip.daddr_v4, dst_ip_str, sizeof(dst_ip_str));
        printf("IPv4: %s:%u -> %s:%u\n", 
               src_ip_str, dns_data->src_port,
               dst_ip_str, dns_data->dst_port);
    } else if (dns_data->ip_version == 6) {
        print_ipv6_addr(&dns_data->src_ip.saddr_v6, src_ip_str, sizeof(src_ip_str));
        print_ipv6_addr(&dns_data->dst_ip.daddr_v6, dst_ip_str, sizeof(dst_ip_str));
        printf("IPv6: [%s]:%u -> [%s]:%u\n", 
               src_ip_str, dns_data->src_port,
               dst_ip_str, dns_data->dst_port);
    }
    
    printf("DNS Payload Length: %u bytes\n", dns_data->pkt_len);
    
    // 解析DNS头
    if (dns_data->pkt_len >= sizeof(struct dns_hdr)) {
        const struct dns_hdr *dns_hdr = (const struct dns_hdr *)dns_data->dns_payload;
        print_dns_header(dns_hdr);
    }
    
    // 打印原始DNS数据的前64字节（十六进制）
    printf("  Raw DNS Data (first 64 bytes):\n    ");
    int print_len = dns_data->pkt_len > 64 ? 64 : dns_data->pkt_len;
    for (int i = 0; i < print_len; i++) {
        printf("%02x ", (unsigned char)dns_data->dns_payload[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n    ");
        }
    }
    if (print_len % 16 != 0) {
        printf("\n");
    }
    
    printf("\n");
    return 0;
}

// 打印DNS统计信息
static void print_dns_stats(int stats_map_fd)
{
    __u32 key = 0;
    struct dns_stats stats;
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stats) == 0) {
        printf("\n=== DNS Statistics ===\n");
        printf("Queries: %llu\n", stats.dns_queries);
        printf("Responses: %llu\n", stats.dns_responses);
        printf("Errors: %llu\n", stats.dns_errors);
        printf("IPv4 Packets: %llu\n", stats.ipv4_packets);
        printf("IPv6 Packets: %llu\n", stats.ipv6_packets);
        printf("======================\n\n");
    }
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    int ringbuf_map_fd, stats_map_fd;
    int err;
    
    printf("DNS Monitor User Space Program\n");
    printf("Press Ctrl+C to stop...\n\n");
    
    // 设置信号处理
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // 打开ring buffer map
    ringbuf_map_fd = bpf_obj_get(DNS_RINGBUF_MAP_PATH);
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "Failed to open ring buffer map: %s\n", strerror(errno));
        fprintf(stderr, "Make sure the DNS eBPF program is loaded with 'make load-dns'\n");
        return 1;
    }
    
    // 打开统计map
    stats_map_fd = bpf_obj_get(DNS_STATS_MAP_PATH);
    if (stats_map_fd < 0) {
        fprintf(stderr, "Failed to open stats map: %s\n", strerror(errno));
        close(ringbuf_map_fd);
        return 1;
    }
    
    // 创建ring buffer
    rb = ring_buffer__new(ringbuf_map_fd, handle_dns_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        close(ringbuf_map_fd);
        close(stats_map_fd);
        return 1;
    }
    
    printf("DNS monitor started, waiting for DNS packets...\n\n");
    
    // 主循环
    time_t last_stats_time = time(NULL);
    while (!stop) {
        err = ring_buffer__poll(rb, 100); // 100ms timeout
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
        
        // 每10秒打印一次统计信息
        time_t current_time = time(NULL);
        if (current_time - last_stats_time >= 10) {
            print_dns_stats(stats_map_fd);
            last_stats_time = current_time;
        }
    }
    
    printf("\nShutting down DNS monitor...\n");
    
    // 最后打印一次统计信息
    print_dns_stats(stats_map_fd);
    
    // 清理资源
    ring_buffer__free(rb);
    close(ringbuf_map_fd);
    close(stats_map_fd);
    
    return 0;
}
