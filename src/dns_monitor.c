// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <ctype.h>

#include "debug.h"
#include "conf.h"
#include "dns_monitor.h"
#include "wd_util.h"
#include "firewall.h"

// DNS监控状态
static volatile int dns_monitor_running = 0;
static pthread_t dns_monitor_tid = 0;

// eBPF map文件路径
#define DNS_RINGBUF_MAP_PATH    "/sys/fs/bpf/tc/globals/dns_ringbuf"
#define DNS_STATS_MAP_PATH      "/sys/fs/bpf/tc/globals/dns_stats_map"

// DNS相关常量
#define MAX_DNS_PAYLOAD_LEN 512
#define INET6_ADDRSTRLEN 46
#define MAX_DNS_NAME 256

// xDPI相关常量
#define XDPI_DOMAIN_MAX 256
#define MAX_DOMAIN_LEN 64
#define INITIAL_MAX_SID 0
#define XDPI_IOC_MAGIC 'X'

// DNS协议相关常量
#define DNS_RR_TYPE_A 1
#define DNS_RR_TYPE_AAAA 28
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 16
#define MAX_PARTS 5

// xDPI IOCTL定义
#define XDPI_IOC_ADD    _IOW(XDPI_IOC_MAGIC, 1, struct domain_entry)
#define XDPI_IOC_DEL    _IOW(XDPI_IOC_MAGIC, 2, int)
#define XDPI_IOC_UPDATE _IOW(XDPI_IOC_MAGIC, 3, struct domain_update)

// DNS统计信息结构
struct dns_stats {
    __u64 dns_queries;
    __u64 dns_responses;
    __u64 dns_errors;
    __u64 ipv4_packets;
    __u64 ipv6_packets;
};

// xDPI域名条目结构
struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    int domain_len;
    int sid;
    bool used;
    __u64 access_count;         // 访问计数
    time_t last_access_time;    // 最后访问时间
    time_t first_seen_time;     // 首次发现时间
};

// xDPI域名更新结构
struct domain_update {
    struct domain_entry entry;
    int index;
};

// DNS名称解析结构
struct dns_name_info {
    char query_name[MAX_DNS_NAME];
    __u16 qtype;
    __u16 qclass;
};

// DNS答案记录结构
struct dns_answer {
    __u16 type;
    __u16 class;
    __u32 ttl;
    __u16 rdlength;
    unsigned char *rdata;
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
    unsigned char dns_payload[MAX_DNS_PAYLOAD_LEN];
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

// xDPI域名缓存数组和互斥锁
static struct domain_entry domain_entries[XDPI_DOMAIN_MAX];
static pthread_mutex_t domain_entries_mutex = PTHREAD_MUTEX_INITIALIZER;

// LFU淘汰阈值和统计周期
#define LFU_MIN_ACCESS_THRESHOLD 5      // 最少访问次数才能保留
#define TOP_DOMAINS_REPORT_INTERVAL 600 // 10分钟报告一次热门域名
#define TOP_DOMAINS_COUNT 20            // 报告前20个热门域名
#define DOMAIN_STATS_FILE "/tmp/wifidog_domain_stats.dat"  // 持久化文件路径
#define DNS_STATS_EXPORT_FILE "/tmp/dns_stats.txt"         // 统计导出文件（供aw-bpfctl读取）

// 有效域名后缀列表
static const char *valid_domain_suffixes[] = {
    ".com", ".net", ".org", ".gov", ".edu", ".cn", ".com.cn", ".co.uk", 
    ".io", ".me", ".app", ".xyz", ".site", ".top", ".club", ".vip", 
    ".shop", ".store", ".tech", ".dev", ".cloud", ".fun", ".online", 
    ".pro", ".work", ".link", ".live", ".run", ".group", ".red", 
    ".blue", ".green", ".mobi", ".asia", ".name", ".today", ".news", 
    ".website", ".space", ".icu", NULL
};

// 函数声明
static int parse_dns_header(const struct dns_hdr *dns_hdr, __u16 *flags, __u16 *qdcount, __u16 *ancount);
static int parse_dns_question(const unsigned char *payload, int payload_len, struct dns_name_info *name_info);
static int parse_dns_name(const unsigned char *payload, int payload_len, int offset, char *name, int max_len);
static int is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain);
static int process_dns_answers(const unsigned char *payload, int payload_len, int offset, int ancount, t_domain_trusted *trusted_domain);
static int add_trusted_ip(t_domain_trusted *trusted_domain, __u16 type, const unsigned char *addr_ptr);
static void handle_xdpi_domain_processing(const char *query_name);
static int is_valid_domain_suffix(const char *domain);
static int xdpi_short_domain(const char *full_domain, char *short_domain, int *olen);
static int xdpi_add_domain(const char *input_domain);
static int get_xdpi_domain_count(void);
static void sync_xdpi_domains_2_kern(void);
static int is_safe_ip_str(const char *ip_str);
static int process_dns_response_extended(const struct raw_dns_data *dns_data);

// LFU算法相关函数
static int find_least_frequently_used_domain(void);
static int remove_domain_from_kernel(int index);
static void print_top_domains(int top_n);
static int compare_domain_by_access_count(const void *a, const void *b);

// 统计导出相关函数
static int export_dns_stats_to_file(void);

// 持久化相关函数
static int save_domain_stats_to_file(void);
static int load_domain_stats_from_file(void);

// 打印IPv4地址
static void __attribute__((unused)) print_ipv4_addr(__be32 addr, char *buf, size_t buf_size)
{
    struct in_addr in_addr = { .s_addr = addr };
    inet_ntop(AF_INET, &in_addr, buf, buf_size);
}

// 打印IPv6地址
static void __attribute__((unused)) print_ipv6_addr(const struct in6_addr *addr, char *buf, size_t buf_size)
{
    inet_ntop(AF_INET6, addr, buf, buf_size);
}

// 打印时间戳
static void __attribute__((unused)) print_timestamp(__u32 timestamp)
{
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    debug(LOG_DEBUG, "DNS Event: %04d-%02d-%02d %02d:%02d:%02d",
           tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday,
           tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
}

// 解析并处理DNS头信息
static void process_dns_header(const struct dns_hdr *dns_hdr)
{
    __u16 flags = ntohs(dns_hdr->flags);
    __u8 rcode = DNS_GET_RCODE(flags);
    
    // 只在有错误时记录日志
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
}

static int handle_dns_event(void *ctx, void *data, size_t data_sz)
{
    const struct raw_dns_data *dns_data = data;
    
    if (!data || data_sz < sizeof(*dns_data)) {
        debug(LOG_ERR, "Invalid DNS data: ptr=%p, size=%zu", data, data_sz);
        return 0;
    }
    
    if (dns_data->pkt_len == 0 || dns_data->pkt_len > MAX_DNS_PAYLOAD_LEN) {
        debug(LOG_WARNING, "Invalid DNS packet length: %u", dns_data->pkt_len);
        return 0;
    }
    
    size_t expected_size = offsetof(struct raw_dns_data, dns_payload) + dns_data->pkt_len;
    if (data_sz < expected_size) {
        debug(LOG_WARNING, "DNS data size mismatch: data_sz=%zu, expected=%zu", 
              data_sz, expected_size);
        return 0;
    }
    
    
    if (dns_data->pkt_len >= sizeof(struct dns_hdr)) {
        const struct dns_hdr *dns_hdr = (const struct dns_hdr *)dns_data->dns_payload;
        
        if ((uintptr_t)dns_hdr % __alignof__(struct dns_hdr) != 0) {
            debug(LOG_WARNING, "Unaligned DNS header pointer");
            return 0;
        }
        
        process_dns_header(dns_hdr);
        
        process_dns_response_extended(dns_data);
    } else {
        debug(LOG_WARNING, "DNS packet too small for header: %u bytes", dns_data->pkt_len);
    }
    
    return 0;
}


static void print_dns_stats(int stats_map_fd)
{
    __u32 key = 0;
    struct dns_stats stats;
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stats) == 0) {
        debug(LOG_DEBUG, "=== DNS Statistics ===");
        debug(LOG_DEBUG, "Queries: %llu", (unsigned long long)stats.dns_queries);
        debug(LOG_DEBUG, "Responses: %llu", (unsigned long long)stats.dns_responses);
        debug(LOG_DEBUG, "Errors: %llu", (unsigned long long)stats.dns_errors);
        debug(LOG_DEBUG, "IPv4 Packets: %llu", (unsigned long long)stats.ipv4_packets);
        debug(LOG_DEBUG, "IPv6 Packets: %llu", (unsigned long long)stats.ipv6_packets);
        debug(LOG_DEBUG, "======================");
    }
}

// DNS监控线程主函数
static void *dns_monitor_thread(void *arg)
{
    struct ring_buffer *rb = NULL;
    int ringbuf_map_fd = -1, stats_map_fd = -1;
    int err;
    time_t last_stats_time = time(NULL);
    time_t last_top_domains_report = time(NULL);
    time_t last_save_time = time(NULL);
    
    debug(LOG_INFO, "DNS Monitor thread started");
    
    // 从文件加载之前保存的域名统计
    load_domain_stats_from_file();
    
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
    
    debug(LOG_DEBUG, "DNS monitor initialized, waiting for DNS packets...");
    
    // 主循环
    while (dns_monitor_running) {
        err = ring_buffer__poll(rb, 1000); // 1秒超时
        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            debug(LOG_ERR, "Error polling DNS ring buffer: %d", err);
            break;
        }
        
        // 定期任务检查
        time_t current_time = time(NULL);
        
        // 每30秒打印一次eBPF统计信息
        if (current_time - last_stats_time >= 30) {
            print_dns_stats(stats_map_fd);
            last_stats_time = current_time;
        }
        
        // 每10分钟报告一次热门域名
        if (current_time - last_top_domains_report >= TOP_DOMAINS_REPORT_INTERVAL) {
            print_top_domains(TOP_DOMAINS_COUNT);
            last_top_domains_report = current_time;
        }
        
        // 每5分钟保存一次域名统计到文件
        if (current_time - last_save_time >= 300) {
            save_domain_stats_to_file();
            export_dns_stats_to_file();  // 同时导出供aw-bpfctl读取
            last_save_time = current_time;
        }
        if (current_time - last_save_time >= 300) {
            save_domain_stats_to_file();
            last_save_time = current_time;
        }
    }
    
    debug(LOG_DEBUG, "DNS monitor thread shutting down...");
    
    // 退出前保存域名统计和导出
    save_domain_stats_to_file();
    export_dns_stats_to_file();
    
    // 最后打印一次统计信息
    if (stats_map_fd >= 0) {
        print_dns_stats(stats_map_fd);
        print_top_domains(TOP_DOMAINS_COUNT);
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
    
    debug(LOG_DEBUG, "DNS monitor thread created successfully");
    return 1;
}

// 停止DNS监控
void dns_monitor_stop(void)
{
    if (!dns_monitor_running) {
        return;
    }
    
    debug(LOG_DEBUG, "Stopping DNS monitor...");
    dns_monitor_running = 0;
    
    // 等待线程结束（最多等待2秒）
    // 注意：由于使用了pthread_detach，不能使用pthread_join
    // 这里只是标记停止，线程会自然退出
    sleep(1); // 简单等待1秒让线程有时间退出
    
    debug(LOG_DEBUG, "DNS monitor stop requested");
}

// 检查DNS监控是否运行
int dns_monitor_is_running(void)
{
    return dns_monitor_running;
}

// ========== DNS协议解析功能 ==========

/**
 * @brief 解析DNS头部
 */
static int parse_dns_header(const struct dns_hdr *dns_hdr, __u16 *flags, __u16 *qdcount, __u16 *ancount)
{
    if (!dns_hdr || !flags || !qdcount || !ancount) {
        return -1;
    }
    
    *flags = ntohs(dns_hdr->flags);
    *qdcount = ntohs(dns_hdr->qdcount);
    *ancount = ntohs(dns_hdr->ancount);
    
    // 验证DNS头部 - 放宽验证条件，只检查必要的字段
    __u8 qr = (*flags >> 15) & 0x1;
    __u8 opcode = (*flags >> 11) & 0xF;
    __u8 rcode __attribute__((unused)) = *flags & 0xF;
    
    // 只要求是响应(QR=1)和标准查询(opcode=0)，允许各种响应码
    if (qr != 1 || opcode != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * @brief 解析DNS名称
 */
static int parse_dns_name(const unsigned char *payload, int payload_len, int offset, char *name, int max_len)
{
    int pos = offset;
    int name_pos = 0;
    int jumped = 0;
    int max_jumps = 5;
    int jumps = 0;
    
    if (!payload || offset < 0 || offset >= payload_len) {
        return -1;
    }
    
    // 如果name为NULL，说明调用者只想跳过域名，不需要解析内容
    int skip_only = (name == NULL || max_len <= 0);
    if (!skip_only) {
        name[0] = '\0';
    }
    
    while (pos < payload_len && jumps < max_jumps) {
        // 确保pos在有效范围内
        if (pos < 0 || pos >= payload_len) {
            return -1;
        }
        
        int len = payload[pos];
        
        if (len == 0) {
            pos++;
            break;
        }
        
        if ((len & 0xC0) == 0xC0) {
            // 压缩指针
            if (pos + 1 >= payload_len) {
                return -1;
            }
            
            if (!jumped) {
                jumped = pos + 2;
            }
            
            int new_pos = ((len & 0x3F) << 8) | payload[pos + 1];
            // 验证新位置的有效性，防止无限循环和越界
            if (new_pos < 0 || new_pos >= payload_len || new_pos >= pos) {
                return -1;
            }
            
            pos = new_pos;
            jumps++;
            continue;
        }
        
        // 验证长度字段的合法性
        if (len > 63 || pos + len + 1 > payload_len) {
            return -1;
        }
        
        // 只在需要解析域名时才进行字符串操作
        if (!skip_only) {
            // 检查缓冲区边界
            if (name_pos > 0 && name_pos < max_len - 1) {
                name[name_pos++] = '.';
            }
            
            // 严格检查缓冲区边界，防止溢出
            for (int i = 0; i < len && name_pos < max_len - 1; i++) {
                unsigned char c = payload[pos + 1 + i];
                // 只允许可见ASCII字符，过滤控制字符
                if (c >= 32 && c <= 126) {
                    name[name_pos++] = c;
                } else {
                    name[name_pos++] = '?'; // 替换非法字符
                }
            }
        }
        
        pos += len + 1;
    }
    
    if (!skip_only && max_len > 0) {
        name[name_pos] = '\0';
    }
    
    return jumped ? jumped : pos;
}

/**
 * @brief 解析DNS问题段
 */
static int parse_dns_question(const unsigned char *payload, int payload_len, struct dns_name_info *name_info)
{
    if (!payload || !name_info || payload_len < sizeof(struct dns_hdr)) {
        return -1;
    }
    
    // 清零结构体，防止垃圾数据
    memset(name_info, 0, sizeof(*name_info));
    
    int offset = sizeof(struct dns_hdr);
    int next_offset = parse_dns_name(payload, payload_len, offset, name_info->query_name, MAX_DNS_NAME);
    
    if (next_offset < 0 || next_offset + 4 > payload_len) {
        return -1;
    }
    
    // 添加额外的边界检查
    if (next_offset < sizeof(struct dns_hdr) || next_offset >= payload_len - 4) {
        return -1;
    }
    
    // 安全地读取qtype和qclass，避免未对齐访问
    // 使用memcpy避免对齐问题，让编译器和CPU处理未对齐访问
    __u16 qtype_raw, qclass_raw;
    memcpy(&qtype_raw, payload + next_offset, sizeof(__u16));
    memcpy(&qclass_raw, payload + next_offset + 2, sizeof(__u16));
    
    name_info->qtype = ntohs(qtype_raw);
    name_info->qclass = ntohs(qclass_raw);
    
    return next_offset + 4;
}

// ========== xDPI集成功能 ==========

/**
 * @brief 获取xDPI域名数量
 */
static int get_xdpi_domain_count(void)
{
    FILE *fp;
    char buf[16] = {0};
    int count = 0;
    
    fp = fopen("/proc/xdpi_domain_num", "r");
    if (!fp) {
        return 0;
    }
    
    if (fgets(buf, sizeof(buf), fp)) {
        count = atoi(buf);
    }
    
    fclose(fp);
    return count;
}

/**
 * @brief 同步域名到内核
 */
static void sync_xdpi_domains_2_kern(void)
{
    int fd;
    int result;
    struct domain_entry entry;
    
    pthread_mutex_lock(&domain_entries_mutex);
    
    fd = open("/dev/xdpi", O_RDWR);
    if (fd < 0) {
        debug(LOG_ERR, "Cannot open /dev/xdpi: %s", strerror(errno));
        pthread_mutex_unlock(&domain_entries_mutex);
        return;
    }
    
    debug(LOG_DEBUG, "Syncing domain entries to kernel");
    
    int success_count = 0;
    int fail_count = 0;
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            memcpy(&entry, &domain_entries[i], sizeof(entry));
            result = ioctl(fd, XDPI_IOC_ADD, &entry);
            if (result < 0) {
                debug(LOG_WARNING, "Failed to sync domain %s to kernel: %s (errno=%d)", 
                      entry.domain, strerror(errno), errno);
                fail_count++;
            } else {
                success_count++;
            }
        }
    }
    
    close(fd);
    pthread_mutex_unlock(&domain_entries_mutex);
    debug(LOG_DEBUG, "Domain sync to kernel completed: %d succeeded, %d failed", 
          success_count, fail_count);
}

/**
 * @brief 添加域名到xDPI (增强版 - 支持访问计数和LFU淘汰)
 */
static int xdpi_add_domain(const char *input_domain)
{
    int fd = -1, result = 0;
    struct domain_entry entry_for_ioctl;
    int local_free_idx = -1;
    int local_max_sid = INITIAL_MAX_SID;
    char domain_to_process[MAX_DOMAIN_LEN] = {0};
    time_t current_time = time(NULL);
    
    if (!input_domain || input_domain[0] == '\0' || strlen(input_domain) >= MAX_DOMAIN_LEN) {
        return -1;
    }
    
    // 域名缩短处理
    char short_domain_buf[MAX_DOMAIN_LEN] = {0};
    int short_domain_len = 0;
    if (xdpi_short_domain(input_domain, short_domain_buf, &short_domain_len) == 0 && short_domain_len > 0) {
        strncpy(domain_to_process, short_domain_buf, MAX_DOMAIN_LEN - 1);
    } else {
        strncpy(domain_to_process, input_domain, MAX_DOMAIN_LEN - 1);
    }
    domain_to_process[MAX_DOMAIN_LEN-1] = '\0';
    
    // 查找重复、空闲位置和最大SID
    pthread_mutex_lock(&domain_entries_mutex);
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            if (strcmp(domain_entries[i].domain, domain_to_process) == 0) {
                // 域名已存在，增加访问计数
                domain_entries[i].access_count++;
                domain_entries[i].last_access_time = current_time;
                pthread_mutex_unlock(&domain_entries_mutex);
                return 0;
            }
            if (domain_entries[i].sid > local_max_sid) {
                local_max_sid = domain_entries[i].sid;
            }
        } else if (local_free_idx == -1) {
            local_free_idx = i;
        }
    }
    
    // 如果没有空闲位置，使用LFU算法淘汰
    if (local_free_idx == -1) {
        int lfu_idx = find_least_frequently_used_domain();
        if (lfu_idx >= 0) {
            // 只有当访问次数低于阈值时才淘汰
            if (domain_entries[lfu_idx].access_count < LFU_MIN_ACCESS_THRESHOLD) {
                // 从内核删除旧域名
                remove_domain_from_kernel(lfu_idx);
                // 清空该位置，准备添加新域名
                memset(&domain_entries[lfu_idx], 0, sizeof(struct domain_entry));
                domain_entries[lfu_idx].used = false;
                local_free_idx = lfu_idx;
            } else {
                // 所有域名访问次数都很高，拒绝添加新域名
                pthread_mutex_unlock(&domain_entries_mutex);
                debug(LOG_DEBUG, "All domains have high access count, rejecting new domain: %s", 
                      domain_to_process);
                return -1;
            }
        } else {
            pthread_mutex_unlock(&domain_entries_mutex);
            debug(LOG_WARNING, "xDPI domain cache is full and cannot find LFU candidate");
            return -1;
        }
    }
    pthread_mutex_unlock(&domain_entries_mutex);
    
    // 添加到内核
    fd = open("/dev/xdpi", O_RDWR);
    if (fd < 0) {
        debug(LOG_ERR, "Cannot open /dev/xdpi: %s", strerror(errno));
        return -1;
    }
    
    memset(&entry_for_ioctl, 0, sizeof(entry_for_ioctl));
    size_t len_to_copy = strlen(domain_to_process);
    if (len_to_copy >= MAX_DOMAIN_LEN) len_to_copy = MAX_DOMAIN_LEN - 1;
    
    memcpy(entry_for_ioctl.domain, domain_to_process, len_to_copy);
    entry_for_ioctl.domain[len_to_copy] = '\0';
    entry_for_ioctl.domain_len = len_to_copy;
    entry_for_ioctl.sid = local_max_sid + 1;
    entry_for_ioctl.used = true;
    entry_for_ioctl.access_count = 1;  // 初始访问计数为1
    entry_for_ioctl.first_seen_time = current_time;
    entry_for_ioctl.last_access_time = current_time;
    
    result = ioctl(fd, XDPI_IOC_ADD, &entry_for_ioctl);
    close(fd);
    
    if (result < 0) {
        debug(LOG_ERR, "Failed to add domain %s to xDPI kernel module: %s (errno=%d)", 
              domain_to_process, strerror(errno), errno);
        return -1;
    }
    
    // 更新本地缓存
    pthread_mutex_lock(&domain_entries_mutex);
    if (local_free_idx >= 0 && local_free_idx < XDPI_DOMAIN_MAX) {
        memcpy(domain_entries[local_free_idx].domain, domain_to_process, len_to_copy);
        domain_entries[local_free_idx].domain[len_to_copy] = '\0';
        domain_entries[local_free_idx].domain_len = len_to_copy;
        domain_entries[local_free_idx].sid = entry_for_ioctl.sid;
        domain_entries[local_free_idx].used = true;
        domain_entries[local_free_idx].access_count = 1;
        domain_entries[local_free_idx].first_seen_time = current_time;
        domain_entries[local_free_idx].last_access_time = current_time;
    } else {
        debug(LOG_WARNING, "Invalid local_free_idx: %d", local_free_idx);
    }
    pthread_mutex_unlock(&domain_entries_mutex);
    
    debug(LOG_DEBUG, "Added domain %s to xDPI (SID: %d)", domain_to_process, entry_for_ioctl.sid);
    return result;
}

// ========== 可信域名管理功能 ==========

/**
 * @brief 检查是否为可信域名
 */
static int is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain)
{
    s_config *config = config_get_config();
    if (!config || !query_name) return 0;
    
    t_domain_trusted *p = config->wildcard_domains_trusted;
    while (p) {
        if (p->domain) {
            const char *domain_pattern = p->domain;
            int matched = 0;
            
            // 只支持两种格式：*.example.com 和 .example.com
            if (strncmp(domain_pattern, "*.", 2) == 0) {
                // 处理 *.example.com 格式
                const char *suffix = domain_pattern + 1; // 跳过 '*', 得到 ".example.com"
                size_t query_len = strlen(query_name);
                size_t suffix_len = strlen(suffix);
                // 防止无符号整数下溢
                if (query_len >= suffix_len && suffix_len > 0 &&
                    strcmp(query_name + query_len - suffix_len, suffix) == 0) {
                    matched = 1;
                }
            } else if (domain_pattern[0] == '.') {
                // 处理 .example.com 格式
                size_t query_len = strlen(query_name);
                size_t pattern_len = strlen(domain_pattern);
                // 防止无符号整数下溢和空字符串
                if (query_len >= pattern_len && pattern_len > 0 &&
                    strcmp(query_name + query_len - pattern_len, domain_pattern) == 0) {
                    matched = 1;
                }
            }
            // 注意：不支持完整域名格式（如 example.com）
            
            if (matched) {
                debug(LOG_DEBUG, "Query name '%s' matched trusted domain rule '%s'", query_name, domain_pattern);
                *trusted_domain = p;
                return 1;
            }
        }
        p = p->next;
    }
    return 0;
}

/**
 * @brief 验证IP地址字符串安全性
 */
static int is_safe_ip_str(const char *ip_str)
{
    if (!ip_str || ip_str[0] == '\0') {
        return 0;
    }
    for (const char *p = ip_str; *p; ++p) {
        if (!(isxdigit((unsigned char)*p) || *p == '.' || *p == ':')) {
            debug(LOG_WARNING, "IP string '%s' contains unsafe character '%c'", ip_str, *p);
            return 0;
        }
    }
    return 1;
}

/**
 * @brief 添加可信IP地址
 */
static int add_trusted_ip(t_domain_trusted *trusted_domain, __u16 type, const unsigned char *addr_ptr)
{
    if (!trusted_domain || !addr_ptr) {
        return -1;
    }
    
    t_ip_trusted *ip_trusted = trusted_domain->ips_trusted;
    int found = 0;
    
    // 检查重复
    while (ip_trusted) {
        if (ip_trusted->ip_type == (type == DNS_RR_TYPE_A ? IP_TYPE_IPV4 : IP_TYPE_IPV6)) {
            if ((type == DNS_RR_TYPE_A && ip_trusted->uip.ipv4.s_addr == *(uint32_t *)addr_ptr) ||
                (type == DNS_RR_TYPE_AAAA && memcmp(&ip_trusted->uip.ipv6, addr_ptr, IPV6_ADDR_LEN) == 0)) {
                found = 1;
                break;
            }
        }
        ip_trusted = ip_trusted->next;
    }
    
    if (!found) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        if (type == DNS_RR_TYPE_A) {
            inet_ntop(AF_INET, addr_ptr, ip_str, sizeof(ip_str));
        } else {
            inet_ntop(AF_INET6, addr_ptr, ip_str, sizeof(ip_str));
        }
        
        debug(LOG_DEBUG, "Adding trusted IP for domain '%s': %s", trusted_domain->domain, ip_str);
        
        t_ip_trusted *new_ip_trusted = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
        if (!new_ip_trusted) {
            debug(LOG_ERR, "Memory allocation failed for new_ip_trusted");
            return -1;
        }
        
        if (type == DNS_RR_TYPE_A) {
            new_ip_trusted->ip_type = IP_TYPE_IPV4;
            memcpy(&new_ip_trusted->uip.ipv4, addr_ptr, IPV4_ADDR_LEN);
        } else {
            new_ip_trusted->ip_type = IP_TYPE_IPV6;
            memcpy(&new_ip_trusted->uip.ipv6, addr_ptr, IPV6_ADDR_LEN);
        }
        
        new_ip_trusted->next = trusted_domain->ips_trusted;
        trusted_domain->ips_trusted = new_ip_trusted;
        
        // 添加到nftables
        if (is_safe_ip_str(ip_str)) {
            char cmd[256] = {0};
            if (type == DNS_RR_TYPE_A) {
                snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_wildcard_trust_domains { %s }", ip_str);
            } else {
                snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_wildcard_trust_domains_v6 { %s }", ip_str);
            }
            execute(cmd, 0);
        }
    }
    return 0;
}

/**
 * @brief 处理DNS答案段
 */
static int process_dns_answers(const unsigned char *payload, int payload_len, int offset, int ancount, t_domain_trusted *trusted_domain)
{
    int pos = offset;
    
    for (int i = 0; i < ancount && pos < payload_len; i++) {
        // 跳过域名 - 现在可以安全使用NULL参数
        int name_end = parse_dns_name(payload, payload_len, pos, NULL, 0);
        if (name_end < 0) {
            return -1;
        }
        pos = name_end;
        
        // 检查是否有足够的空间读取资源记录头部 (type + class + ttl + rdlength = 10 bytes)
        if (pos + 10 > payload_len) {
            return -1;
        }
        
        // 安全地读取资源记录头部，避免未对齐访问
        __u16 type_raw, class_raw, rdlength_raw;
        __u32 ttl_raw;
        memcpy(&type_raw, payload + pos, sizeof(__u16));
        memcpy(&class_raw, payload + pos + 2, sizeof(__u16));
        memcpy(&ttl_raw, payload + pos + 4, sizeof(__u32));
        memcpy(&rdlength_raw, payload + pos + 8, sizeof(__u16));
        
        __u16 type = ntohs(type_raw);
        __u16 class __attribute__((unused)) = ntohs(class_raw);
        __u32 ttl __attribute__((unused)) = ntohl(ttl_raw);
        __u16 rdlength = ntohs(rdlength_raw);
        
        pos += 10;
        
        // 检查是否有足够的空间读取资源数据
        if (pos + rdlength > payload_len) {
            return -1;
        }
        
        // 防止整数溢出 - 检查pos + rdlength是否会溢出
        if (pos > INT_MAX - rdlength) {
            debug(LOG_WARNING, "Integer overflow prevented in DNS parsing: pos=%d, rdlength=%u", pos, rdlength);
            return -1;
        }
        
        // 只处理A记录和AAAA记录，且长度必须正确
        if (type == DNS_RR_TYPE_A && rdlength == IPV4_ADDR_LEN) {
            if (add_trusted_ip(trusted_domain, type, payload + pos) != 0) {
                return -1;
            }
        } else if (type == DNS_RR_TYPE_AAAA && rdlength == IPV6_ADDR_LEN) {
            if (add_trusted_ip(trusted_domain, type, payload + pos) != 0) {
                return -1;
            }
        }
        
        pos += rdlength;
    }
    return 0;
}

// ========== 域名处理算法 ==========

/**
 * @brief 检查域名后缀有效性
 */
static int is_valid_domain_suffix(const char *domain)
{
    if (!domain) return 0;
    size_t len = strlen(domain);
    
    for (int i = 0; valid_domain_suffixes[i]; i++) {
        size_t suffix_len = strlen(valid_domain_suffixes[i]);
        if (len >= suffix_len && 
            strcasecmp(domain + len - suffix_len, valid_domain_suffixes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief 提取短域名
 */
static int xdpi_short_domain(const char *full_domain, char *short_domain, int *olen)
{
    if (!full_domain || !short_domain || !olen) {
        return -1;
    }
    
    size_t full_domain_len = strlen(full_domain);
    short_domain[0] = '\0';
    *olen = 0;
    
    if (full_domain_len == 0 || full_domain_len >= MAX_DOMAIN_LEN) {
        return -1;
    }
    
    const char *p = full_domain + full_domain_len - 1;
    int part_count = 0;
    const char *parts_ptr[MAX_PARTS] = {0};
    int parts_len[MAX_PARTS] = {0};
    
    // 从右到左解析域名段
    while (p >= full_domain && part_count < MAX_PARTS) {
        const char *part_end = p;
        
        // 查找点号分隔符，防止指针越界
        while (p >= full_domain && *p != '.') {
            p--;
        }
        
        // 验证段长度合法性，防止负数或过长
        int segment_len = part_end - p;
        if (segment_len <= 0 || segment_len > MAX_DOMAIN_LEN) {
            debug(LOG_WARNING, "Invalid domain segment length: %d", segment_len);
            return -1;
        }
        
        parts_ptr[part_count] = p + 1;
        parts_len[part_count] = segment_len;
        part_count++;
        
        // 安全地移动指针
        if (p >= full_domain && *p == '.') {
            p--;
        }
    }
    
    if (part_count < 2) {
        return -1;
    }
    
    // 域名构建逻辑
    #define PART_EQ(index, str_literal) \
        (parts_len[index] == strlen(str_literal) && \
         strncmp(parts_ptr[index], str_literal, strlen(str_literal)) == 0)
    
    if (PART_EQ(0, "cn")) {
        if (part_count >= 3 && PART_EQ(1, "com")) {
            // .com.cn域名保留三段
            if (part_count >= 3) {
                int total_len = parts_len[2] + 1 + parts_len[1] + 1 + parts_len[0];
                if (total_len < MAX_DOMAIN_LEN) {
                    snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.%.*s.%.*s",
                            parts_len[2], parts_ptr[2],
                            parts_len[1], parts_ptr[1],
                            parts_len[0], parts_ptr[0]);
                }
            }
        } else {
            // 其他.cn域名取两段
            if (part_count >= 2) {
                int total_len = parts_len[1] + 1 + parts_len[0];
                if (total_len < MAX_DOMAIN_LEN) {
                    snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.%.*s",
                            parts_len[1], parts_ptr[1],
                            parts_len[0], parts_ptr[0]);
                }
            }
        }
    } else {
        // 非.cn域名取两段
        if (part_count >= 2) {
            int total_len = parts_len[1] + 1 + parts_len[0];
            if (total_len < MAX_DOMAIN_LEN) {
                snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.%.*s",
                        parts_len[1], parts_ptr[1],
                        parts_len[0], parts_ptr[0]);
            }
        }
    }
    
    #undef PART_EQ
    
    *olen = strlen(short_domain);
    if (*olen == 0 && full_domain_len > 0) {
        return -1;
    }
    
    return 0;
}

/**
 * @brief 处理xDPI域名
 */
static void handle_xdpi_domain_processing(const char *query_name)
{
    if (!query_name || query_name[0] == '\0') {
        return;
    }
    
    if (is_valid_domain_suffix(query_name)) {
        int domain_count = get_xdpi_domain_count();
        if (domain_count == 0) {
            sync_xdpi_domains_2_kern();
        }
        
        xdpi_add_domain(query_name);
    }
}

/**
 * @brief 扩展的DNS响应处理
 */
static int process_dns_response_extended(const struct raw_dns_data *dns_data)
{
    if (!dns_data || dns_data->pkt_len < sizeof(struct dns_hdr)) {
        return -1;
    }
    
    const struct dns_hdr *dns_hdr = (const struct dns_hdr *)dns_data->dns_payload;
    __u16 flags, qdcount, ancount;
    
    if (parse_dns_header(dns_hdr, &flags, &qdcount, &ancount) != 0) {
        return -1;
    }
    
    if (qdcount != 1) {
        return 0;
    }
    
    // 解析问题段
    struct dns_name_info name_info;
    int answers_offset = parse_dns_question(dns_data->dns_payload, dns_data->pkt_len, &name_info);
    if (answers_offset < 0) {
        return -1;
    }
    
    // xDPI域名处理（排除反向DNS查询）
    if (!strstr(name_info.query_name, "in-addr.arpa") && !strstr(name_info.query_name, "ip6.arpa")) {
        handle_xdpi_domain_processing(name_info.query_name);
    }
    
    // 可信域名处理
    t_domain_trusted *trusted_domain = NULL;
    if (is_trusted_domain(name_info.query_name, &trusted_domain)) {
        if (ancount > 0) {
            if (process_dns_answers(dns_data->dns_payload, dns_data->pkt_len, answers_offset, ancount, trusted_domain) != 0) {
                debug(LOG_WARNING, "Failed to process DNS answers for domain: %s", name_info.query_name);
                return -1;
            }
        }
    }
    
    return 0;
}

// ========== LFU算法实现 ==========

/**
 * @brief 查找访问频率最低的域名索引
 */
static int find_least_frequently_used_domain(void)
{
    int min_idx = -1;
    __u64 min_count = UINT64_MAX;
    time_t oldest_time = time(NULL);
    
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            // 优先淘汰访问次数最少的
            if (domain_entries[i].access_count < min_count) {
                min_count = domain_entries[i].access_count;
                min_idx = i;
                oldest_time = domain_entries[i].last_access_time;
            } 
            // 如果访问次数相同，淘汰最久未访问的
            else if (domain_entries[i].access_count == min_count && 
                     domain_entries[i].last_access_time < oldest_time) {
                min_idx = i;
                oldest_time = domain_entries[i].last_access_time;
            }
        }
    }
    
    return min_idx;
}

/**
 * @brief 从内核中删除域名
 */
static int remove_domain_from_kernel(int index)
{
    if (index < 0 || index >= XDPI_DOMAIN_MAX || !domain_entries[index].used) {
        return -1;
    }
    
    int fd = open("/dev/xdpi", O_RDWR);
    if (fd < 0) {
        debug(LOG_WARNING, "Cannot open /dev/xdpi for deletion: %s", strerror(errno));
        return -1;
    }
    
    int sid = domain_entries[index].sid;
    int result = ioctl(fd, XDPI_IOC_DEL, &sid);
    close(fd);
    
    if (result < 0) {
        debug(LOG_WARNING, "Failed to delete domain %s (SID: %d) from kernel", 
              domain_entries[index].domain, sid);
        return -1;
    }
    
    debug(LOG_INFO, "Evicted domain '%s' (access_count: %llu, SID: %d) due to LFU", 
          domain_entries[index].domain, 
          (unsigned long long)domain_entries[index].access_count, 
          sid);
    
    return 0;
}

/**
 * @brief 比较函数 - 按访问次数降序排序
 */
static int compare_domain_by_access_count(const void *a, const void *b)
{
    const struct domain_entry *da = (const struct domain_entry *)a;
    const struct domain_entry *db = (const struct domain_entry *)b;
    
    // 未使用的条目排在最后
    if (!da->used && !db->used) return 0;
    if (!da->used) return 1;
    if (!db->used) return -1;
    
    // 按访问次数降序
    if (db->access_count > da->access_count) return 1;
    if (db->access_count < da->access_count) return -1;
    
    return 0;
}

/**
 * @brief 打印热门域名统计
 */
static void print_top_domains(int top_n)
{
    struct domain_entry sorted_entries[XDPI_DOMAIN_MAX];
    
    pthread_mutex_lock(&domain_entries_mutex);
    memcpy(sorted_entries, domain_entries, sizeof(sorted_entries));
    pthread_mutex_unlock(&domain_entries_mutex);
    
    // 排序
    qsort(sorted_entries, XDPI_DOMAIN_MAX, sizeof(struct domain_entry), 
          compare_domain_by_access_count);
    
    debug(LOG_INFO, "");
    debug(LOG_INFO, "========================================");
    debug(LOG_INFO, "  Top %d Most Accessed Domains", top_n);
    debug(LOG_INFO, "========================================");
    
    int count = 0;
    for (int i = 0; i < XDPI_DOMAIN_MAX && count < top_n; i++) {
        if (sorted_entries[i].used) {
            time_t last_access = sorted_entries[i].last_access_time;
            time_t first_seen = sorted_entries[i].first_seen_time;
            time_t now = time(NULL);
            
            int minutes_ago = (int)difftime(now, last_access) / 60;
            int hours_alive = (int)difftime(now, first_seen) / 3600;
            
            debug(LOG_INFO, "#%-2d %-40s | Count: %-8llu | Last: %dm ago | Age: %dh | SID: %d",
                  count + 1,
                  sorted_entries[i].domain,
                  (unsigned long long)sorted_entries[i].access_count,
                  minutes_ago,
                  hours_alive,
                  sorted_entries[i].sid);
            count++;
        }
    }
    
    debug(LOG_INFO, "========================================");
    debug(LOG_INFO, "");
}

// ========== 持久化功能实现 ==========

/**
 * @brief 保存域名统计到文件
 */
static int save_domain_stats_to_file(void)
{
    FILE *fp = fopen(DOMAIN_STATS_FILE, "wb");
    if (!fp) {
        debug(LOG_WARNING, "Failed to open domain stats file for writing: %s", strerror(errno));
        return -1;
    }
    
    pthread_mutex_lock(&domain_entries_mutex);
    
    // 写入魔数和版本号
    uint32_t magic = 0x44535441;  // "DSTA" = Domain STAts
    uint32_t version = 1;
    fwrite(&magic, sizeof(magic), 1, fp);
    fwrite(&version, sizeof(version), 1, fp);
    
    // 写入有效条目数量
    int valid_count = 0;
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            valid_count++;
        }
    }
    fwrite(&valid_count, sizeof(valid_count), 1, fp);
    
    // 写入每个有效条目
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            fwrite(&domain_entries[i], sizeof(struct domain_entry), 1, fp);
        }
    }
    
    pthread_mutex_unlock(&domain_entries_mutex);
    
    fclose(fp);
    debug(LOG_DEBUG, "Saved %d domain entries to %s", valid_count, DOMAIN_STATS_FILE);
    return 0;
}

/**
 * @brief 从文件加载域名统计
 */
static int load_domain_stats_from_file(void)
{
    FILE *fp = fopen(DOMAIN_STATS_FILE, "rb");
    if (!fp) {
        debug(LOG_INFO, "No domain stats file found at %s, starting fresh", DOMAIN_STATS_FILE);
        return 0;  // 不是错误，可能是首次启动
    }
    
    // 读取并验证魔数
    uint32_t magic = 0;
    uint32_t version = 0;
    if (fread(&magic, sizeof(magic), 1, fp) != 1 || magic != 0x44535441) {
        debug(LOG_WARNING, "Invalid magic number in domain stats file");
        fclose(fp);
        return -1;
    }
    
    if (fread(&version, sizeof(version), 1, fp) != 1 || version != 1) {
        debug(LOG_WARNING, "Unsupported domain stats file version: %u", version);
        fclose(fp);
        return -1;
    }
    
    // 读取条目数量
    int valid_count = 0;
    if (fread(&valid_count, sizeof(valid_count), 1, fp) != 1) {
        debug(LOG_WARNING, "Failed to read domain count from stats file");
        fclose(fp);
        return -1;
    }
    
    if (valid_count < 0 || valid_count > XDPI_DOMAIN_MAX) {
        debug(LOG_WARNING, "Invalid domain count in stats file: %d", valid_count);
        fclose(fp);
        return -1;
    }
    
    // 读取域名条目
    pthread_mutex_lock(&domain_entries_mutex);
    
    // 清空现有数据
    memset(domain_entries, 0, sizeof(domain_entries));
    
    int loaded_count = 0;
    for (int i = 0; i < valid_count && i < XDPI_DOMAIN_MAX; i++) {
        struct domain_entry temp_entry;
        if (fread(&temp_entry, sizeof(struct domain_entry), 1, fp) == 1) {
            memcpy(&domain_entries[i], &temp_entry, sizeof(struct domain_entry));
            loaded_count++;
        }
    }
    
    pthread_mutex_unlock(&domain_entries_mutex);
    
    fclose(fp);
    
    debug(LOG_INFO, "Loaded %d domain entries from %s", loaded_count, DOMAIN_STATS_FILE);
    
    // 加载后同步到内核
    sync_xdpi_domains_2_kern();
    
    return loaded_count;
}

// ========== 统计数据导出功能 ==========

/**
 * @brief 导出DNS域名统计到文件供aw-bpfctl读取
 */
static int export_dns_stats_to_file(void)
{
    FILE *fp = fopen(DNS_STATS_EXPORT_FILE, "w");
    if (!fp) {
        debug(LOG_WARNING, "Failed to open DNS stats export file: %s", strerror(errno));
        return -1;
    }
    
    // 创建排序后的副本
    struct domain_entry sorted_entries[XDPI_DOMAIN_MAX];
    
    pthread_mutex_lock(&domain_entries_mutex);
    memcpy(sorted_entries, domain_entries, sizeof(sorted_entries));
    pthread_mutex_unlock(&domain_entries_mutex);
    
    // 按访问次数降序排序
    qsort(sorted_entries, XDPI_DOMAIN_MAX, sizeof(struct domain_entry), 
          compare_domain_by_access_count);
    
    // 写入文件头
    fprintf(fp, "# DNS Domain Access Statistics\n");
    fprintf(fp, "# Format: Rank | Domain | Access Count | SID | First Seen | Last Access\n");
    fprintf(fp, "# Generated at: %ld\n", time(NULL));
    fprintf(fp, "#\n");
    
    // 写入每个有效域名的统计信息
    int rank = 1;
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (sorted_entries[i].used) {
            fprintf(fp, "%d|%s|%llu|%d|%ld|%ld\n",
                    rank++,
                    sorted_entries[i].domain,
                    (unsigned long long)sorted_entries[i].access_count,
                    sorted_entries[i].sid,
                    (long)sorted_entries[i].first_seen_time,
                    (long)sorted_entries[i].last_access_time);
        }
    }
    
    fclose(fp);
    
    // 设置文件权限，允许其他用户读取
    chmod(DNS_STATS_EXPORT_FILE, 0644);
    
    return 0;
}

