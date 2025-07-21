// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "debug.h"
#include "conf.h"
#include "dns_monitor.h"

// DNS监控状态
static volatile int dns_monitor_running = 0;
static pthread_t dns_monitor_tid = 0;

// eBPF map文件路径
#define DNS_RINGBUF_MAP_PATH    "/sys/fs/bpf/tc/globals/dns_ringbuf"
#define DNS_STATS_MAP_PATH      "/sys/fs/bpf/tc/globals/dns_stats_map"


// DNS相关常量
#define MAX_DNS_PAYLOAD_LEN 512
#define INET6_ADDRSTRLEN 46

// DNS统计信息结构
struct dns_stats {
    __u64 dns_queries;
    __u64 dns_responses;
    __u64 dns_errors;
    __u64 ipv4_packets;
    __u64 ipv6_packets;
};

// 原始DNS数据结构
struct raw_dns_data {
    __u32 pkt_len;
    __u8 ip_version;
    __u16 src_port;
    __u16 dst_port;
    __u32 timestamp;
    union {
        __be32 saddr_v4;
        struct in6_addr saddr_v6;
    } src_ip;
    union {
        __be32 daddr_v4;
        struct in6_addr daddr_v6;
    } dst_ip;
    char dns_payload[MAX_DNS_PAYLOAD_LEN];
};

// DNS头部结构
struct dns_hdr {
    __be16 id;
    __be16 flags;
    __be16 qdcount;
    __be16 ancount;
    __be16 nscount;
    __be16 arcount;
};

// DNS标志位和响应码定义
#define DNS_QR_RESPONSE 0x8000
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5

// 工具宏
#define DNS_GET_QR(flags)       (((flags) >> 15) & 0x1)
#define DNS_GET_RCODE(flags)    ((flags) & 0xF)
#define IS_DNS_RESPONSE(flags)  (DNS_GET_QR(flags) == 1)

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
    debug(LOG_DEBUG, "DNS Event Time: %04d-%02d-%02d %02d:%02d:%02d",
           tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
           tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

// 解析并处理DNS头信息
static void process_dns_header(const struct dns_hdr *dns_hdr)
{
    __u16 flags = ntohs(dns_hdr->flags);
    
    debug(LOG_DEBUG, "DNS Header - ID: 0x%04x, Flags: 0x%04x", 
          ntohs(dns_hdr->id), flags);
    
    if (IS_DNS_RESPONSE(flags)) {
        debug(LOG_DEBUG, "DNS Response detected");
    } else {
        debug(LOG_DEBUG, "DNS Query detected");
    }
    
    __u8 rcode = DNS_GET_RCODE(flags);
    if (rcode != DNS_RCODE_NOERROR) {
        const char *error_msg;
        switch (rcode) {
            case DNS_RCODE_FORMERR:  error_msg = "Format Error"; break;
            case DNS_RCODE_SERVFAIL: error_msg = "Server Failure"; break;
            case DNS_RCODE_NXDOMAIN: error_msg = "Name Error"; break;
            case DNS_RCODE_NOTIMP:   error_msg = "Not Implemented"; break;
            case DNS_RCODE_REFUSED:  error_msg = "Refused"; break;
            default: error_msg = "Unknown Error"; break;
        }
        debug(LOG_INFO, "DNS Error: %s (code: %d)", error_msg, rcode);
    }
    
    debug(LOG_DEBUG, "Questions: %d, Answers: %d, Authority: %d, Additional: %d",
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
        debug(LOG_ERR, "Invalid DNS data size: %zu", data_sz);
        return 0;
    }
    
    debug(LOG_INFO, "=== DNS Packet Captured ===");
    
    // 打印时间戳
    print_timestamp(dns_data->timestamp);
    
    // 打印IP信息
    if (dns_data->ip_version == 4) {
        print_ipv4_addr(dns_data->src_ip.saddr_v4, src_ip_str, sizeof(src_ip_str));
        print_ipv4_addr(dns_data->dst_ip.daddr_v4, dst_ip_str, sizeof(dst_ip_str));
        debug(LOG_INFO, "IPv4: %s:%u -> %s:%u", 
               src_ip_str, dns_data->src_port,
               dst_ip_str, dns_data->dst_port);
    } else if (dns_data->ip_version == 6) {
        print_ipv6_addr(&dns_data->src_ip.saddr_v6, src_ip_str, sizeof(src_ip_str));
        print_ipv6_addr(&dns_data->dst_ip.daddr_v6, dst_ip_str, sizeof(dst_ip_str));
        debug(LOG_INFO, "IPv6: [%s]:%u -> [%s]:%u", 
               src_ip_str, dns_data->src_port,
               dst_ip_str, dns_data->dst_port);
    }
    
    debug(LOG_DEBUG, "DNS Payload Length: %u bytes", dns_data->pkt_len);
    
    // 解析DNS头
    if (dns_data->pkt_len >= sizeof(struct dns_hdr)) {
        const struct dns_hdr *dns_hdr = (const struct dns_hdr *)dns_data->dns_payload;
        process_dns_header(dns_hdr);
    }
    
    // 在DEBUG级别下打印原始数据的前32字节
    if (debugconf.debuglevel >= LOG_DEBUG) {
        debug(LOG_DEBUG, "Raw DNS Data (first 32 bytes):");
        int print_len = dns_data->pkt_len > 32 ? 32 : dns_data->pkt_len;
        char hex_str[256] = {0};
        for (int i = 0; i < print_len; i++) {
            sprintf(hex_str + strlen(hex_str), "%02x ", 
                   (unsigned char)dns_data->dns_payload[i]);
        }
        debug(LOG_DEBUG, "%s", hex_str);
    }
    
    debug(LOG_INFO, "==============================");
    return 0;
}

// 打印DNS统计信息
static void print_dns_stats(int stats_map_fd)
{
    __u32 key = 0;
    struct dns_stats stats;
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stats) == 0) {
        debug(LOG_INFO, "=== DNS Statistics ===");
        debug(LOG_INFO, "Queries: %llu", (unsigned long long)stats.dns_queries);
        debug(LOG_INFO, "Responses: %llu", (unsigned long long)stats.dns_responses);
        debug(LOG_INFO, "Errors: %llu", (unsigned long long)stats.dns_errors);
        debug(LOG_INFO, "IPv4 Packets: %llu", (unsigned long long)stats.ipv4_packets);
        debug(LOG_INFO, "IPv6 Packets: %llu", (unsigned long long)stats.ipv6_packets);
        debug(LOG_INFO, "======================");
    } else {
        debug(LOG_DEBUG, "Failed to read DNS statistics");
    }
}

// DNS监控线程主函数
static void *dns_monitor_thread(void *arg)
{
    struct ring_buffer *rb = NULL;
    int ringbuf_map_fd = -1, stats_map_fd = -1;
    int err;
    time_t last_stats_time = time(NULL);
    
    debug(LOG_INFO, "DNS Monitor thread started");
    
    // 打开ring buffer map
    ringbuf_map_fd = bpf_obj_get(DNS_RINGBUF_MAP_PATH);
    if (ringbuf_map_fd < 0) {
        debug(LOG_ERR, "Failed to open DNS ring buffer map: %s", strerror(errno));
        debug(LOG_INFO, "Make sure DNS eBPF program is loaded");
        goto cleanup;
    }
    
    // 打开统计map
    stats_map_fd = bpf_obj_get(DNS_STATS_MAP_PATH);
    if (stats_map_fd < 0) {
        debug(LOG_ERR, "Failed to open DNS stats map: %s", strerror(errno));
        goto cleanup;
    }
    
    // 创建ring buffer
    rb = ring_buffer__new(ringbuf_map_fd, handle_dns_event, NULL, NULL);
    if (!rb) {
        debug(LOG_ERR, "Failed to create DNS ring buffer");
        goto cleanup;
    }
    
    debug(LOG_INFO, "DNS monitor initialized, waiting for DNS packets...");
    
    // 主循环
    while (dns_monitor_running) {
        err = ring_buffer__poll(rb, 1000); // 1秒超时
        if (err == -EINTR) {
            debug(LOG_DEBUG, "DNS monitor interrupted");
            break;
        }
        if (err < 0) {
            debug(LOG_ERR, "Error polling DNS ring buffer: %d", err);
            break;
        }
        
        // 每30秒打印一次统计信息
        time_t current_time = time(NULL);
        if (current_time - last_stats_time >= 30) {
            print_dns_stats(stats_map_fd);
            last_stats_time = current_time;
        }
    }
    
    debug(LOG_INFO, "DNS monitor thread shutting down...");
    
    // 最后打印一次统计信息
    if (stats_map_fd >= 0) {
        print_dns_stats(stats_map_fd);
    }

cleanup:
    if (rb) {
        ring_buffer__free(rb);
    }
    if (ringbuf_map_fd >= 0) {
        close(ringbuf_map_fd);
    }
    if (stats_map_fd >= 0) {
        close(stats_map_fd);
    }
    
    debug(LOG_INFO, "DNS Monitor thread terminated");
    return NULL;
}

// 线程包装函数，用于在gateway.c中启动
void *thread_dns_monitor(void *arg)
{
    // 启动DNS监控
    dns_monitor_start();
    return NULL;
}

// 启动DNS监控
int dns_monitor_start(void)
{
    if (dns_monitor_running) {
        debug(LOG_WARNING, "DNS monitor is already running");
        return 1;
    }
    
    dns_monitor_running = 1;
    
    int result = pthread_create(&dns_monitor_tid, NULL, dns_monitor_thread, NULL);
    if (result != 0) {
        debug(LOG_ERR, "Failed to create DNS monitor thread: %s", strerror(result));
        dns_monitor_running = 0;
        return 0;
    }
    
    // 分离线程，不需要join
    pthread_detach(dns_monitor_tid);
    
    debug(LOG_INFO, "DNS monitor thread created successfully");
    return 1;
}

// 停止DNS监控
void dns_monitor_stop(void)
{
    if (!dns_monitor_running) {
        return;
    }
    
    debug(LOG_INFO, "Stopping DNS monitor...");
    dns_monitor_running = 0;
    
    // 等待线程结束（最多等待2秒）
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += 2;
    
    // 注意：由于使用了pthread_detach，不能使用pthread_join
    // 这里只是标记停止，线程会自然退出
    
    debug(LOG_INFO, "DNS monitor stop requested");
}

// 检查DNS监控是否运行
int dns_monitor_is_running(void)
{
    return dns_monitor_running;
}
