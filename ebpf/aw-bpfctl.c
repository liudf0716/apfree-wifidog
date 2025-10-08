// update_maps.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <json-c/json.h>
#include <ctype.h>
#include <unistd.h>
#include <uci.h>
#include <sys/ioctl.h>
#include <fcntl.h>

/* 检查是否安装了 libcurl */
#if defined(HAVE_LIBCURL) || defined(USE_LIBCURL)
#include <curl/curl.h>  /* 添加curl支持 */
#endif

#include "aw-bpf.h"
#include "xdpi-bpf.h"  // 包含统一的ioctl接口定义

#define DOMAIN_API_URL "http://seo.chawrt.com/open/api/domain/info/batch"  /* 添加API URL定义 */
#define DNS_STATS_FILE "/tmp/dns_stats.txt"  /* DNS统计文件 */
#define XDPI_DEVICE "/dev/xdpi"

struct xdpi_l7_proto {
    __u32 id;
    char proto_desc[XDPI_PROTO_FEATURE_MAX_SIZE];
    __u32 sid;
};

// 应用层域名信息结构体（包含扩展信息）
struct app_domain_entry {
    __u32 id;                                  // 域名ID
    char name[XDPI_PROTO_FEATURE_MAX_SIZE];    // 域名
    __u32 sid;                                 // SID
    char title[128];                           // 域名标题
    char desc[256];                            // 域名描述
    bool has_details;                          // 是否有详细信息
    // DNS统计信息
    unsigned long long access_count;           // 访问次数
    time_t first_seen;                         // 首次发现时间
    time_t last_access;                        // 最后访问时间
    bool has_stats;                            // 是否有统计信息
};

// 前向声明函数
static bool fetch_domain_info(void);
static void print_stats_l7(void);

// 合并后的域名信息列表
static struct app_domain_entry domains[XDPI_PROTO_TRAITS_MAX_SIZE];
static int domains_count = 0;

static struct xdpi_l7_proto xdpi_l7_protos[XDPI_PROTO_TRAITS_MAX_SIZE];
static int xdpi_l7_protos_count = 0;

static void load_domains(void)
{
    int fd;
    struct domain_list list;
    int result;
    
    // 打开xDPI设备
    fd = open(XDPI_DEVICE, O_RDWR);
    if (fd < 0) {
        perror("Failed to open " XDPI_DEVICE);
        domains_count = 0;
        return;
    }
    
    // 初始化domain_list结构
    memset(&list, 0, sizeof(list));
    list.max_count = XDPI_DOMAIN_MAX;
    
    // 通过ioctl获取域名列表
    result = ioctl(fd, XDPI_IOC_LIST, &list);
    if (result < 0) {
        perror("Failed to get domain list via ioctl");
        close(fd);
        domains_count = 0;
        return;
    }
    
    close(fd);
    
    // 转换内核域名数据到用户态格式
    domains_count = 0;
    printf("Debug: Loading %d domains from kernel via ioctl\n", list.count);
    
    for (int i = 0; i < list.count && domains_count < XDPI_PROTO_TRAITS_MAX_SIZE; i++) {
        struct domain_entry *kernel_entry = &list.domains[i];  // 这是内核的domain_entry结构
        if (!kernel_entry->used) continue;
        
        // 检查重复（额外的安全检查）
        bool duplicate = false;
        for (int j = 0; j < domains_count; j++) {
            if (strcmp(domains[j].name, kernel_entry->domain) == 0) {
                printf("Debug: Skipping duplicate domain: %s\n", kernel_entry->domain);
                duplicate = true;
                break;
            }
        }
        
        if (!duplicate) {
            struct app_domain_entry *entry = &domains[domains_count];
            memset(entry, 0, sizeof(*entry));
            
            // 设置基本信息
            entry->id = domains_count + 1;  // 分配唯一ID
            strncpy(entry->name, kernel_entry->domain, sizeof(entry->name) - 1);
            entry->sid = kernel_entry->sid;
            entry->has_details = false;
            
            // 设置统计信息
            if (kernel_entry->access_count > 0) {
                entry->access_count = kernel_entry->access_count;
                entry->first_seen = (time_t)kernel_entry->first_seen_time;
                entry->last_access = (time_t)kernel_entry->last_access_time;
                entry->has_stats = true;
                printf("Debug: Loaded domain[%d]: %s (sid=%u, count=%llu)\n", 
                       domains_count, entry->name, entry->sid, entry->access_count);
            } else {
                entry->access_count = 0;
                entry->first_seen = 0;
                entry->last_access = 0;
                entry->has_stats = false;
                printf("Debug: Loaded domain[%d]: %s (sid=%u, no stats)\n", 
                       domains_count, entry->name, entry->sid);
            }
            
            domains_count++;
        }
    }
    
    printf("Debug: Total domains loaded: %d\n", domains_count);
    
    // 注意：统计数据现在直接从内核获取，不再需要外部文件
}

// L7协议加载逻辑现在也使用ioctl接口（如果需要的话）
static void load_xdpi_l7_protos(void)
{
    // TODO: 如果需要L7协议信息，也应该通过ioctl从内核获取
    // 目前保持简单实现，使用硬编码或从其他来源获取
    
    // 清空计数器
    xdpi_l7_protos_count = 0;
    
    // 这里可以添加L7协议的获取逻辑
    // 暂时保持为空，因为主要focus是域名管理
}

static const char* get_domain_name_by_sid(__u32 sid) {
    for (int i = 0; i < domains_count; i++) {
        if (domains[i].sid == sid) {
            return domains[i].name;
        }
    }
    return "unknown";
}

static const char *get_l7_proto_desc_by_sid(__u32 sid) {
    for (int i = 0; i < xdpi_l7_protos_count; i++) {
        if (xdpi_l7_protos[i].sid == sid) {
            return xdpi_l7_protos[i].proto_desc;
        }
    }
    return "unknown";
}

static void 
print_stats_ipv4(__be32 ip, struct traffic_stats *stats)
{
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)) == NULL)
        strcpy(ip_str, "Invalid");
    printf("Key (IPv4): %s\n", ip_str);
    printf("  Incoming: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->incoming.total_bytes, stats->incoming.total_packets, calc_rate_estimator(stats, true));
    printf("  Outgoing: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->outgoing.total_bytes, stats->outgoing.total_packets, calc_rate_estimator(stats, false));
    printf("  Rate Limits: incoming=%llu bps, tokens=%llu, t_last=%llu, outgoing=%llu bps tokens=%llu, t_last=%llu\n",
           stats->incoming_rate_limit.bps, stats->incoming_rate_limit.tokens, stats->incoming_rate_limit.t_last, stats->outgoing_rate_limit.bps, stats->outgoing_rate_limit.tokens, stats->outgoing_rate_limit.t_last);
}

static void 
print_stats_ipv6(struct in6_addr ip, struct traffic_stats *stats)
{
    char ip_str[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str)) == NULL)
        strcpy(ip_str, "Invalid");
    printf("Key (IPv6): %s\n", ip_str);
    printf("  Incoming: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->incoming.total_bytes, stats->incoming.total_packets, calc_rate_estimator(stats, true));
    printf("  Outgoing: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->outgoing.total_bytes, stats->outgoing.total_packets, calc_rate_estimator(stats, false));
    printf("  Rate Limits: incoming=%llu bps, tokens=%llu, t_last=%llu, outgoing=%llu bps tokens=%llu, t_last=%llu\n",
           stats->incoming_rate_limit.bps, stats->incoming_rate_limit.tokens, stats->incoming_rate_limit.t_last, stats->outgoing_rate_limit.bps, stats->outgoing_rate_limit.tokens, stats->outgoing_rate_limit.t_last);
}

static void 
print_stats_mac(struct mac_addr mac, struct traffic_stats *stats)
{
    printf("Key (MAC): %02x:%02x:%02x:%02x:%02x:%02x\n", 
           mac.h_addr[0], mac.h_addr[1], mac.h_addr[2],
           mac.h_addr[3], mac.h_addr[4], mac.h_addr[5]);
    printf("  Incoming: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->incoming.total_bytes, stats->incoming.total_packets, calc_rate_estimator(stats, true));
    printf("  Outgoing: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->outgoing.total_bytes, stats->outgoing.total_packets, calc_rate_estimator(stats, false));
    printf("  Rate Limits: incoming=%llu bps, tokens=%llu, t_last=%llu, outgoing=%llu bps tokens=%llu, t_last=%llu\n",
           stats->incoming_rate_limit.bps, stats->incoming_rate_limit.tokens, stats->incoming_rate_limit.t_last, stats->outgoing_rate_limit.bps, stats->outgoing_rate_limit.tokens, stats->outgoing_rate_limit.t_last);
}

static void 
print_stats_sid(uint32_t sid, struct traffic_stats *stats)
{
    uint32_t incoming_rate = calc_rate_estimator(stats, true);
    uint32_t outgoing_rate = calc_rate_estimator(stats, false);
    
    if (sid < 1000) {
        const char *l7_proto_desc = get_l7_proto_desc_by_sid(sid);
        printf("Key (SID): %u (%s)\n", sid, l7_proto_desc);
    } else {
        const char *domain_name = get_domain_name_by_sid(sid);
        printf("Key (SID): %u (%s)\n", sid, domain_name);
    }
    
    printf("  Incoming: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->incoming.total_bytes, stats->incoming.total_packets, incoming_rate);
    printf("  Outgoing: total_bytes=%llu, total_packets=%llu, rate=%u\n",
           stats->outgoing.total_bytes, stats->outgoing.total_packets, outgoing_rate);
    printf("  Rate Limits: incoming=%llu bps, tokens=%llu, t_last=%llu, outgoing=%llu bps tokens=%llu, t_last=%llu\n",
           stats->incoming_rate_limit.bps, stats->incoming_rate_limit.tokens, stats->incoming_rate_limit.t_last, 
           stats->outgoing_rate_limit.bps, stats->outgoing_rate_limit.tokens, stats->outgoing_rate_limit.t_last);
}

static struct json_object*
parse_stats_ipv4_json(__be32 ip, struct traffic_stats *stats) 
{
    char ip_str[INET_ADDRSTRLEN];
    struct json_object *jobj = json_object_new_object();
    

    if (inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)) == NULL) {
        json_object_put(jobj);
        return NULL;
    }

    // Add IP address
    json_object_object_add(jobj, "ip", json_object_new_string(ip_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();
    
    // Add incoming stats
    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object*
parse_stats_ipv6_json(struct in6_addr ip, struct traffic_stats *stats)
{
    char ip_str[INET6_ADDRSTRLEN];
    struct json_object *jobj = json_object_new_object();

    if (inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str)) == NULL) {
        json_object_put(jobj);
        return NULL;
    }

    // Add IP address
    json_object_object_add(jobj, "ip", json_object_new_string(ip_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();
    
    // Add incoming stats
    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object*
parse_stats_mac_json(struct mac_addr mac, struct traffic_stats *stats)
{
    char mac_str[18];
    struct json_object *jobj = json_object_new_object();

    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac.h_addr[0], mac.h_addr[1], mac.h_addr[2],
             mac.h_addr[3], mac.h_addr[4], mac.h_addr[5]);

    // Add MAC address
    json_object_object_add(jobj, "mac", json_object_new_string(mac_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();
    
    // Add incoming stats
    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object*
parse_stats_sid_json(uint32_t sid, struct traffic_stats *stats)
{
    uint32_t incoming_rate = calc_rate_estimator(stats, true);
    uint32_t outgoing_rate = calc_rate_estimator(stats, false);
    
    struct json_object *jobj = json_object_new_object();

    // Add SID and domain name
    json_object_object_add(jobj, "sid", json_object_new_int(sid));
    if (sid < 1000) {
        const char *l7_proto_desc = get_l7_proto_desc_by_sid(sid);
        json_object_object_add(jobj, "sid_type", json_object_new_string("L7"));
        json_object_object_add(jobj, "l7_proto_desc", json_object_new_string(l7_proto_desc));
    } else {
        const char *domain_name = get_domain_name_by_sid(sid);
        json_object_object_add(jobj, "sid_type", json_object_new_string("Domain"));
        json_object_object_add(jobj, "domain", json_object_new_string(domain_name));

    }
    
    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();
    
    // Add incoming stats
    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(incoming_rate));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(outgoing_rate));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static bool
is_valid_mac_addr(const char *mac_addr)
{
    int i, colon_count = 0;
    size_t len = strlen(mac_addr);

    if (len != 17) // MAC address format should be XX:XX:XX:XX:XX:XX
        return false;

    for (i = 0; i < len; i++) {
        if (i % 3 == 2) {
            if (mac_addr[i] != ':')
                return false;
            colon_count++;
        } else {
            if (!isxdigit(mac_addr[i]))
                return false;
        }
    }

    return colon_count == 5;
}

static void
parse_mac_address(struct mac_addr *m_addr, const char *str_val)
{
    unsigned int val;
    const char *pos = str_val;

    // Parse each byte of the MAC address
    for (int i = 0; i < 6; i++) {
        val = 0;
        sscanf(pos, "%2x", &val);
        m_addr->h_addr[i] = (uint8_t)val;
        pos += 3;  // Move past the two hex digits and colon
    }
}

static void
aw_bpf_usage()
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> add <IP_ADDRESS|MAC_ADDRESS>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7|domain> list\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> del <IP_ADDRESS|MAC_ADDRESS>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> flush\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7|domain> json\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid> update <IP_ADDRESS|MAC_ADDRESS|SID> downrate <bps> uprate <bps>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid> update_all downrate <bps> uprate <bps>\n");
}

static bool
is_valid_command(const char *cmd)
{
    return !strcmp(cmd, "add") || !strcmp(cmd, "list") || !strcmp(cmd, "del") || !strcmp(cmd, "flush") || 
           !strcmp(cmd, "json") || !strcmp(cmd, "update") || !strcmp(cmd, "update_all") || 
           !strcmp(cmd, "domain");  /* 添加domain命令 */
}

static void get_aw_global_qos_config(uint32_t *downrate, uint32_t *uprate)
{
    {
        struct uci_context *ctx;
        struct uci_package *pkg = NULL;
        struct uci_element *e;
        bool found = false;

        *downrate = 0;
        *uprate = 0;

        ctx = uci_alloc_context();
        if (!ctx) {
            fprintf(stderr, "Failed to allocate UCI context\n");
            return;
        }

        if (uci_load(ctx, "wifidogx", &pkg) != UCI_OK) {
            fprintf(stderr, "Failed to load wifidogx config\n");
            uci_free_context(ctx);
            return;
        }

        uci_foreach_element(&pkg->sections, e) {
            struct uci_section *s = uci_to_section(e);
            if (strcmp(s->type, "wifidogx") == 0) {
                const char *enable_qos = uci_lookup_option_string(ctx, s, "enable_qos");
                
                if (enable_qos && strcmp(enable_qos, "1") == 0) {
                    const char *qos_down = uci_lookup_option_string(ctx, s, "qos_down");
                    const char *qos_up = uci_lookup_option_string(ctx, s, "qos_up");
                    
                    if (qos_down) {
                        long val = strtol(qos_down, NULL, 10);
                        if (val >= 0 && val <= (UINT32_MAX / (1024 * 1024)))
                            *downrate = (uint32_t)(val * 1024 * 1024); // Convert Mbps to bps
                    }
                    if (qos_up) {
                        long val = strtol(qos_up, NULL, 10);
                        if (val >= 0 && val <= (UINT32_MAX / (1024 * 1024)))
                            *uprate = (uint32_t)(val * 1024 * 1024);   // Convert Mbps to bps
                    }
                    found = true;
                    break;
                }
            }
        }

        if (pkg) {
            uci_unload(ctx, pkg);
        }
        uci_free_context(ctx);
    }
}

static bool handle_add_command(int map_fd, const char *map_type, const char *addr_str) {
    struct traffic_stats stats = {0};
    void *key = NULL;
    int key_size = 0;
    
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 ipv4_key = 0;
        if (inet_pton(AF_INET, addr_str, &ipv4_key) != 1) {
            perror("inet_pton (IPv4)");
            return false;
        }
        key = &ipv4_key;
        key_size = sizeof(ipv4_key);
    } else if (strcmp(map_type, "mac") == 0) {
        if (!is_valid_mac_addr(addr_str)) {
            fprintf(stderr, "Invalid MAC address format\n");
            return false;
        }
        struct mac_addr mac_key = {0};
        parse_mac_address(&mac_key, addr_str);
        key = &mac_key;
        key_size = sizeof(mac_key);
    } else if (strcmp(map_type, "ipv6") == 0) {
        struct in6_addr ipv6_key = {0};
        if (inet_pton(AF_INET6, addr_str, &ipv6_key) != 1) {
            perror("inet_pton (IPv6)");
            return false;
        }
        key = &ipv6_key;
        key_size = sizeof(ipv6_key);
    } else {
        fprintf(stderr, "Invalid address type\n");
        return false;
    }

    struct traffic_stats tmp;
    if (bpf_map_lookup_elem(map_fd, key, &tmp) == 0) {
        printf("%s key %s already exists in map.\n", map_type, addr_str);
        return true;
    }

    // Get global QoS configuration
    uint32_t downrate, uprate;
    get_aw_global_qos_config(&downrate, &uprate);
    stats.incoming_rate_limit.bps = downrate;
    stats.outgoing_rate_limit.bps = uprate;

    if (bpf_map_update_elem(map_fd, key, &stats, BPF_NOEXIST) < 0) {
        perror("bpf_map_update_elem");
        return false;
    }

    printf("Added %s key %s successfully with downrate %u uprate %u.\n", map_type, addr_str, downrate, uprate);
    return true;
}

static bool handle_list_command(int map_fd, const char *map_type) {
    int ret;
    
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 cur_key = 0, next_key = 0;
        struct traffic_stats stats = {0};
        
        while ((ret = bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) < 0) {
                perror("bpf_map_lookup_elem (IPv4)");
            } else {
                print_stats_ipv4(next_key, &stats);
            }
            cur_key = next_key;
        }
        
        if (ret != -ENOENT) {
            perror("bpf_map_get_next_key (IPv4)");
            return false;
        }
    } else if (strcmp(map_type, "mac") == 0) {
        struct mac_addr cur_key = {0}, next_key = {0};
        struct traffic_stats stats = {0};
        
        while ((ret = bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct mac_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) < 0) {
                perror("bpf_map_lookup_elem (MAC)");
            } else {
                print_stats_mac(next_key, &stats);
            }
            cur_key = next_key;
        }
        
        if (ret != -ENOENT) {
            perror("bpf_map_get_next_key (MAC)");
            return false;
        }
    } else if (strcmp(map_type, "ipv6") == 0){ // ipv6
        struct in6_addr cur_key = {0}, next_key = {0};
        struct traffic_stats stats = {0};
        
        while ((ret = bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct in6_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) < 0) {
                perror("bpf_map_lookup_elem (IPv6)");
            } else {
                print_stats_ipv6(next_key, &stats);
            }
            cur_key = next_key;
        }
        
        if (ret != -ENOENT) {
            perror("bpf_map_get_next_key (IPv6)");
            return false;
        }
    } else if (strcmp(map_type, "sid") == 0) {
        uint32_t cur_key = 0, next_key;
        struct traffic_stats stats = {0};
        
        while ((ret = bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key)) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) < 0) {
                perror("bpf_map_lookup_elem (SID)");
            } else {
                print_stats_sid(next_key, &stats);
            }
            cur_key = next_key;
        }
        
        if (ret != -ENOENT) {
            perror("bpf_map_get_next_key (SID)");
            return false;
        }
    } else {
        fprintf(stderr, "Invalid map type: %s\n", map_type);
        return false;
    }
    
    return true;
}

static bool handle_json_command(int map_fd, const char *map_type) {
    struct json_object *jroot = json_object_new_object();
    struct json_object *jdata = json_object_new_array();
    
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 cur_key = 0, next_key = 0;
        struct traffic_stats stats = {0};
        
        while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                struct json_object *jentry = parse_stats_ipv4_json(next_key, &stats);
                if (jentry) {
                    json_object_array_add(jdata, jentry);
                }
            }
            cur_key = next_key;
        }
    } else if (strcmp(map_type, "mac") == 0) {
        struct mac_addr cur_key = {0}, next_key = {0};
        struct traffic_stats stats = {0};

        while (bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct mac_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                struct json_object *jentry = parse_stats_mac_json(next_key, &stats);
                if (jentry) {
                    json_object_array_add(jdata, jentry);
                }
            } else {
                break;
            }
            cur_key = next_key;
        }
    } else if (strcmp(map_type, "sid") == 0) {
        __u32 cur_key = 0, next_key;
        struct traffic_stats stats = {0};

        while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                struct json_object *jentry = parse_stats_sid_json(next_key, &stats);
                if (jentry) {
                    json_object_array_add(jdata, jentry);
                }
            }
            cur_key = next_key;
        }
    } else { // ipv6
        struct in6_addr cur_key = {0}, next_key = {0};
        struct traffic_stats stats = {0};

        while (bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct in6_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &stats) == 0) {
                struct json_object *jentry = parse_stats_ipv6_json(next_key, &stats);
                if (jentry) {
                    json_object_array_add(jdata, jentry);
                }
            }
            cur_key = next_key;
        }
    }

    json_object_object_add(jroot, "status", json_object_new_string("success"));
    json_object_object_add(jroot, "type", json_object_new_string(map_type));
    json_object_object_add(jroot, "data", jdata);

    printf("%s\n", json_object_to_json_string(jroot));
    json_object_put(jroot);
    return true;
}

static bool handle_del_command(int map_fd, const char *map_type, const char *addr_str) {
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 key = 0;
        if (inet_pton(AF_INET, addr_str, &key) != 1) {
            perror("inet_pton (IPv4)");
            return false;
        }
        if (bpf_map_delete_elem(map_fd, &key) < 0) {
            perror("bpf_map_delete_elem (IPv4)");
            return false;
        }
        printf("Deleted IPv4 key %s successfully.\n", addr_str);
    } else if (strcmp(map_type, "mac") == 0) {
        if (!is_valid_mac_addr(addr_str)) {
            fprintf(stderr, "Invalid MAC address format\n");
            return false;
        }
        struct mac_addr key = {0};
        parse_mac_address(&key, addr_str);
        if (bpf_map_delete_elem(map_fd, &key) < 0) {
            perror("bpf_map_delete_elem (MAC)");
            return false;
        }
        printf("Deleted MAC key %s successfully.\n", addr_str);
    } else { // ipv6
        struct in6_addr key = {0};
        if (inet_pton(AF_INET6, addr_str, &key) != 1) {
            perror("inet_pton (IPv6)");
            return false;
        }
        if (bpf_map_delete_elem(map_fd, &key) < 0) {
            perror("bpf_map_delete_elem (IPv6)");
            return false;
        }
        printf("Deleted IPv6 key %s successfully.\n", addr_str);
    }
    return true;
}

static void* get_address_key(const char *map_type, const char *addr_str, void *key_storage) {
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 *ipv4_key = (__be32*)key_storage;
        if (inet_pton(AF_INET, addr_str, ipv4_key) != 1) {
            perror("inet_pton (IPv4)");
            return NULL;
        }
        return ipv4_key;
    } else if (strcmp(map_type, "mac") == 0) {
        if (!is_valid_mac_addr(addr_str)) {
            fprintf(stderr, "Invalid MAC address format\n");
            return NULL;
        }
        struct mac_addr *mac_key = (struct mac_addr*)key_storage;
        memset(mac_key, 0, sizeof(struct mac_addr));
        parse_mac_address(mac_key, addr_str);
        return mac_key;
    } else { // ipv6
        struct in6_addr *ipv6_key = (struct in6_addr*)key_storage;
        if (inet_pton(AF_INET6, addr_str, ipv6_key) != 1) {
            perror("inet_pton (IPv6)");
            return NULL;
        }
        return ipv6_key;
    }
}

static bool handle_update_command(int map_fd, const char *map_type, const char *addr_str, 
                                uint32_t downrate, uint32_t uprate) {
    union {
        __be32 ipv4_key;
        struct mac_addr mac_key;
        struct in6_addr ipv6_key;
    } key_storage;
    
    void *key = get_address_key(map_type, addr_str, &key_storage);
    if (!key) {
        return false;
    }

    // Look up existing stats
    struct traffic_stats stats = {0};
    bool exists = (bpf_map_lookup_elem(map_fd, key, &stats) == 0);
    
    // Update rate limits
    stats.incoming_rate_limit.bps = downrate;
    stats.outgoing_rate_limit.bps = uprate;
    
    // Update or add the entry
    int update_flag = exists ? BPF_EXIST : BPF_NOEXIST;
    if (bpf_map_update_elem(map_fd, key, &stats, update_flag) < 0) {
        perror("bpf_map_update_elem");
        return false;
    }

    printf("%s %s key %s successfully.\n", exists ? "Updated" : "Added", map_type, addr_str);
    return true;
}

static bool handle_update_all_command(int map_fd, const char *map_type, 
                                    uint32_t downrate, uint32_t uprate) {
    // Prepare stats structure with updated rate limits
    struct traffic_stats stats = {0};
    stats.incoming_rate_limit.bps = downrate;
    stats.outgoing_rate_limit.bps = uprate;
    
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 cur_key = 0, next_key = 0;
        struct traffic_stats existing;
        
        while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
            // Keep existing traffic stats, just update rate limits
            if (bpf_map_lookup_elem(map_fd, &next_key, &existing) == 0) {
                existing.incoming_rate_limit.bps = downrate;
                existing.outgoing_rate_limit.bps = uprate;
                if (bpf_map_update_elem(map_fd, &next_key, &existing, BPF_EXIST) < 0) {
                    perror("bpf_map_update_elem (IPv4)");
                    return false;
                }
            }
            cur_key = next_key;
        }
    } else if (strcmp(map_type, "mac") == 0) {
        struct mac_addr cur_key = {0}, next_key = {0};
        struct traffic_stats existing;
        
        while (bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct mac_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &existing) == 0) {
                existing.incoming_rate_limit.bps = downrate;
                existing.outgoing_rate_limit.bps = uprate;
                if (bpf_map_update_elem(map_fd, &next_key, &existing, BPF_EXIST) < 0) {
                    perror("bpf_map_update_elem (MAC)");
                    return false;
                }
            }
            cur_key = next_key;
        }
    } else { // ipv6
        struct in6_addr cur_key = {0}, next_key = {0};
        struct traffic_stats existing;
        
        while (bpf_map_get_next_key(map_fd, 
               (memcmp(&cur_key, &(struct in6_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &existing) == 0) {
                existing.incoming_rate_limit.bps = downrate;
                existing.outgoing_rate_limit.bps = uprate;
                if (bpf_map_update_elem(map_fd, &next_key, &existing, BPF_EXIST) < 0) {
                    perror("bpf_map_update_elem (IPv6)");
                    return false;
                }
            }
            cur_key = next_key;
        }
    }

    printf("Updated all %s keys successfully.\n", map_type);
    return true;
}

static void 
print_domain_list(void)
{
    printf("===== Domains =====\n");
    printf("%-5s | %-40s | %-5s | %-12s | %-20s | %-20s | %-30s\n",
           "Index", "Domain", "SID", "Access Count", "First Seen", "Last Access", "Title");
    printf("----------------------------------------------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < domains_count; i++) {
        // 基本信息
        printf("%5d | %-40s | %5u", 
               domains[i].id, 
               domains[i].name, 
               domains[i].sid);
        
        // DNS统计信息
        if (domains[i].has_stats) {
            printf(" | %12llu", (unsigned long long)domains[i].access_count);
            
            // 格式化时间
            char first_seen_str[20] = "-";
            char last_access_str[20] = "-";
            if (domains[i].first_seen > 0) {
                struct tm *tm_info = localtime(&domains[i].first_seen);
                strftime(first_seen_str, sizeof(first_seen_str), "%Y-%m-%d %H:%M:%S", tm_info);
            }
            if (domains[i].last_access > 0) {
                struct tm *tm_info = localtime(&domains[i].last_access);
                strftime(last_access_str, sizeof(last_access_str), "%Y-%m-%d %H:%M:%S", tm_info);
            }
            printf(" | %-20s | %-20s", first_seen_str, last_access_str);
        } else {
            printf(" | %12s | %-20s | %-20s", "-", "-", "-");
        }
        
        // 标题信息
        if (domains[i].has_details && strlen(domains[i].title) > 0) {
            printf(" | %s", domains[i].title);
        } else {
            printf(" | -");
        }
        
        printf("\n");
    }
}

// 将域名列表转换为json格式
static struct json_object*
parse_domain_json(void)
{
    struct json_object *jroot = json_object_new_object();
    
    // 创建域名信息数组
    struct json_object *jdomains = json_object_new_array();
    for (int i = 0; i < domains_count; i++) {
        struct json_object *jentry = json_object_new_object();
        json_object_object_add(jentry, "id", json_object_new_int(domains[i].id));
        json_object_object_add(jentry, "domain", json_object_new_string(domains[i].name));
        json_object_object_add(jentry, "sid", json_object_new_int(domains[i].sid));
        
        // 添加 DNS 统计信息（如果有）
        if (domains[i].has_stats) {
            json_object_object_add(jentry, "access_count", json_object_new_int64(domains[i].access_count));
            json_object_object_add(jentry, "first_seen", json_object_new_int64((int64_t)domains[i].first_seen));
            json_object_object_add(jentry, "last_access", json_object_new_int64((int64_t)domains[i].last_access));
            
            // 添加人类可读的时间格式
            if (domains[i].first_seen > 0) {
                char time_str[64];
                struct tm *tm_info = localtime(&domains[i].first_seen);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                json_object_object_add(jentry, "first_seen_str", json_object_new_string(time_str));
            }
            if (domains[i].last_access > 0) {
                char time_str[64];
                struct tm *tm_info = localtime(&domains[i].last_access);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                json_object_object_add(jentry, "last_access_str", json_object_new_string(time_str));
            }
        }
        
        // 添加域名详细信息（如果已获取）
        if (domains[i].has_details) {
            if (strlen(domains[i].title) > 0) {
                json_object_object_add(jentry, "title", json_object_new_string(domains[i].title));
            }
            if (strlen(domains[i].desc) > 0) {
                json_object_object_add(jentry, "desc", json_object_new_string(domains[i].desc));
            }
        }
        
        json_object_array_add(jdomains, jentry);
    }

    json_object_object_add(jroot, "success", json_object_new_boolean(1));
    json_object_object_add(jroot, "msg", json_object_new_string("域名查询成功"));
    json_object_object_add(jroot, "data", jdomains);

    return jroot;
}

// 处理domain命令
static bool 
handle_domain_command(const char *subcmd) 
{
    // 尝试获取域名详细信息
    if (domains_count > 0 && !domains[0].has_details) {
        fetch_domain_info();
    }
    
    if (strcmp(subcmd, "list") == 0) {
        print_domain_list();
        return true;
    } else if (strcmp(subcmd, "json") == 0) {
        struct json_object *jroot = parse_domain_json();
        printf("%s\n", json_object_to_json_string_ext(jroot, JSON_C_TO_STRING_PRETTY));
        json_object_put(jroot);
        return true;
    }
    
    fprintf(stderr, "Invalid domain subcommand. Use 'list' or 'json'.\n");
    return false;
}

static struct json_object*
parse_stats_l7_json(void)
{
    struct json_object *jroot = json_object_new_object();
    
    // 创建 L7 协议信息数组
    struct json_object *jprotocols = json_object_new_array();
    for (int i = 0; i < xdpi_l7_protos_count; i++) {
        struct json_object *jentry = json_object_new_object();
        json_object_object_add(jentry, "id", json_object_new_int(xdpi_l7_protos[i].id));
        json_object_object_add(jentry, "protocol", json_object_new_string(xdpi_l7_protos[i].proto_desc));
        json_object_object_add(jentry, "sid", json_object_new_int(xdpi_l7_protos[i].sid));
        json_object_array_add(jprotocols, jentry);
    }
    
    // 创建域名信息数组
    struct json_object *jdomains = json_object_new_array();
    for (int i = 0; i < domains_count; i++) {
        struct json_object *jentry = json_object_new_object();
        json_object_object_add(jentry, "id", json_object_new_int(domains[i].id));
        json_object_object_add(jentry, "domain", json_object_new_string(domains[i].name));
        json_object_object_add(jentry, "sid", json_object_new_int(domains[i].sid));
        
        // 添加详细信息（如果有）
        if (domains[i].has_details) {
            if (strlen(domains[i].title) > 0) {
                json_object_object_add(jentry, "title", json_object_new_string(domains[i].title));
            }
            if (strlen(domains[i].desc) > 0) {
                json_object_object_add(jentry, "desc", json_object_new_string(domains[i].desc));
            }
        }
        
        json_object_array_add(jdomains, jentry);
    }

    // 将两种数据放入主数据对象
    struct json_object *jdata = json_object_new_object();
    json_object_object_add(jdata, "protocols", jprotocols);
    json_object_object_add(jdata, "domains", jdomains);

    json_object_object_add(jroot, "status", json_object_new_string("success"));
    json_object_object_add(jroot, "type", json_object_new_string("l7"));
    json_object_object_add(jroot, "data", jdata);

    return jroot;
}

// 打印L7协议和域名信息
static void
print_stats_l7(void)
{
    // 先显示 L7 协议部分
    printf("===== L7 Protocols =====\n");
    printf("Index | Protocol | SID\n");
    printf("----------------------\n");
    for (int i = 0; i < xdpi_l7_protos_count; i++) {
        printf("%5d | %-8s | %u\n", 
               xdpi_l7_protos[i].id, 
               xdpi_l7_protos[i].proto_desc, 
               xdpi_l7_protos[i].sid);
    }
    
    // 再显示 Domain 部分
    printf("\n===== Domains =====\n");
    printf("Index | Domain | SID\n");
    printf("---------------------\n");
    for (int i = 0; i < domains_count; i++) {
        printf("%5d | %-63s | %u\n", 
               domains[i].id, 
               domains[i].name, 
               domains[i].sid);
    }
}

static bool handle_l7_command(const char *cmd) {
    if (strcmp(cmd, "list") == 0) {
        print_stats_l7();
        return true;
    } else if (strcmp(cmd, "json") == 0) {
        struct json_object *jroot = parse_stats_l7_json();
        printf("%s\n", json_object_to_json_string_ext(jroot, JSON_C_TO_STRING_PRETTY));
        json_object_put(jroot);
        return true;
    }
    return false;
}

// curl回调函数，用于接收HTTP响应数据
struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

// 使用系统命令调用curl获取域名信息
static bool 
fetch_domain_info_via_cmd(void)
{
    char command[4096] = {0};
    char domains_json[4096] = {0}; // 减小缓冲区大小以防止溢出
    FILE *fp;
    int i;
    int batch_size = 20; // 减少每批处理的域名数，从100降低到20
    
    // 构建域名JSON数组
    strcat(domains_json, "[");
    for (i = 0; i < domains_count; i++) {
        char domain_entry[128];
        snprintf(domain_entry, sizeof(domain_entry), 
                "%s\"%s\"", 
                i > 0 ? "," : "", 
                domains[i].name);
                
        // 检查添加此域名是否会导致缓冲区溢出
        if (strlen(domains_json) + strlen(domain_entry) + 2 >= sizeof(domains_json)) {
            // 如果会溢出，提前结束这一批次
            strcat(domains_json, "]");
            
            // 构建curl命令，确保不会溢出
            if (snprintf(command, sizeof(command), 
                    "curl -s -X POST %s -H \"Content-Type: application/json\" -d '{\"domains\":%s}'",
                    DOMAIN_API_URL, domains_json) >= (int)sizeof(command)) {
                fprintf(stderr, "Command buffer overflow\n");
                return false;
            }
            
            // 执行curl命令
            fp = popen(command, "r");
            if (!fp) {
                fprintf(stderr, "Failed to execute curl command\n");
                return false;
            }
            
            char response[16384] = {0};
            char buffer[1024];
            while (fgets(buffer, sizeof(buffer), fp) != NULL) {
                strcat(response, buffer);
            }
            pclose(fp);
            
            // 解析响应
            struct json_object *jobj = json_tokener_parse(response);
            if (!jobj) {
                fprintf(stderr, "Failed to parse JSON response\n");
                return false;
            }
            
            // 处理响应数据
            struct json_object *jsuccess;
            if (json_object_object_get_ex(jobj, "success", &jsuccess) && 
                json_object_get_boolean(jsuccess)) {
                
                struct json_object *jdata;
                if (json_object_object_get_ex(jobj, "data", &jdata)) {
                    int data_len = json_object_array_length(jdata);
                    for (int j = 0; j < data_len; j++) {
                        struct json_object *jitem = json_object_array_get_idx(jdata, j);
                        
                        struct json_object *jdomain, *jtitle, *jdesc;
                        if (json_object_object_get_ex(jitem, "domain", &jdomain)) {
                            const char *domain = json_object_get_string(jdomain);
                            
                            // 在现有域名数组中查找匹配的域名并更新信息
                            for (int k = 0; k < domains_count; k++) {
                                if (strcmp(domains[k].name, domain) == 0) {
                                    if (json_object_object_get_ex(jitem, "title", &jtitle)) {
                                        strncpy(domains[k].title, 
                                                json_object_get_string(jtitle), 127);
                                    }
                                    
                                    if (json_object_object_get_ex(jitem, "desc", &jdesc)) {
                                        strncpy(domains[k].desc, 
                                                json_object_get_string(jdesc), 255);
                                    }
                                    
                                    domains[k].has_details = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            json_object_put(jobj);
            
            // 重置JSON数组，准备下一批
            memset(domains_json, 0, sizeof(domains_json));
            strcat(domains_json, "[");
        }
    }
    
    return true;
}

#ifdef HAVE_LIBCURL
// 使用libcurl库获取域名信息
static bool 
fetch_domain_info_via_libcurl(void)
{
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    struct json_object *jobj;
    char domains_json[8192] = {0};
    int i;
    
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "curl_easy_init() failed\n");
        return false;
    }
    
    // 设置HTTP请求参数
    curl_easy_setopt(curl, CURLOPT_URL, DOMAIN_API_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    
    // 构建域名JSON数组
    strcat(domains_json, "[");
    for (i = 0; i < domains_count; i++) {
        char domain_entry[128];
        snprintf(domain_entry, sizeof(domain_entry), 
                "%s\"%s\"", 
                i > 0 ? "," : "", 
                domains[i].name);
        strcat(domains_json, domain_entry);
        
        // 避免请求数据过大，每100个域名分批处理
        if ((i + 1) % 100 == 0 || i == domains_count - 1) {
            strcat(domains_json, "]");
            
            // 构建JSON请求体
            char postdata[8500];
            snprintf(postdata, sizeof(postdata), "{\"domains\":%s}", domains_json);
            
            chunk.memory = malloc(1);
            chunk.size = 0;
            
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            
            // 发送HTTP请求
            res = curl_easy_perform(curl);
            if (res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                free(chunk.memory);
                continue;
            }
            
            // 解析响应
            jobj = json_tokener_parse(chunk.memory);
            if (!jobj) {
                fprintf(stderr, "Failed to parse JSON response\n");
                free(chunk.memory);
                continue;
            }
            
            // 处理响应数据
            struct json_object *jsuccess;
            if (json_object_object_get_ex(jobj, "success", &jsuccess) && 
                json_object_get_boolean(jsuccess)) {
                
                struct json_object *jdata;
                if (json_object_object_get_ex(jobj, "data", &jdata)) {
                    int data_len = json_object_array_length(jdata);
                    for (int j = 0; j < data_len; j++) {
                        struct json_object *jitem = json_object_array_get_idx(jdata, j);
                        
                        struct json_object *jdomain, *jtitle, *jdesc;
                        if (json_object_object_get_ex(jitem, "domain", &jdomain)) {
                            const char *domain = json_object_get_string(jdomain);
                            
                            // 在现有域名数组中查找匹配的域名并更新信息
                            for (int k = 0; k < domains_count; k++) {
                                if (strcmp(domains[k].name, domain) == 0) {
                                    if (json_object_object_get_ex(jitem, "title", &jtitle)) {
                                        strncpy(domains[k].title, 
                                                json_object_get_string(jtitle), 127);
                                    }
                                    
                                    if (json_object_object_get_ex(jitem, "desc", &jdesc)) {
                                        strncpy(domains[k].desc, 
                                                json_object_get_string(jdesc), 255);
                                    }
                                    
                                    domains[k].has_details = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            json_object_put(jobj);
            free(chunk.memory);
            
            // 重置JSON数组，准备下一批
            memset(domains_json, 0, sizeof(domains_json));
            strcat(domains_json, "[");
        }
    }
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    
    return true;
}
#endif

// 获取域名详细信息
static bool 
fetch_domain_info(void)
{
#ifdef HAVE_LIBCURL
    return fetch_domain_info_via_libcurl();
#else
    return fetch_domain_info_via_cmd();
#endif
}

int 
main(int argc, char **argv) 
{
    if (argc < 3) {
        aw_bpf_usage();
        return EXIT_FAILURE;
    }

    // Load domains and L7 protos at startup
    load_domains();
    load_xdpi_l7_protos();

    const char *map_type = argv[1];
    const char *cmd = argv[2];

    // Handle domain commands
    if (strcmp(map_type, "domain") == 0) {
        return handle_domain_command(cmd) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // Validate map type
    if (strcmp(map_type, "ipv4") != 0 && 
        strcmp(map_type, "ipv6") != 0 && 
        strcmp(map_type, "mac") != 0 && 
        strcmp(map_type, "sid") != 0 &&
        strcmp(map_type, "l7") != 0) {
        fprintf(stderr, "Invalid map type. Must be 'ipv4', 'ipv6', 'mac', 'sid', 'l7', or 'domain'.\n");
        aw_bpf_usage();
        return EXIT_FAILURE;
    }

    // Handle l7 commands separately since they don't need BPF map access
    if (strcmp(map_type, "l7") == 0) {
        if (!is_valid_command(cmd)) {
            fprintf(stderr, "Invalid command\n");
            aw_bpf_usage();
            return EXIT_FAILURE;
        }
        return handle_l7_command(cmd) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // Determine map path based on map type
    char map_path[100];
    if (strcmp(map_type, "sid") == 0) {
        snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/tc/globals/%s_map", "xdpi_l7");
    } else {
        snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/tc/globals/%s_map", map_type);
    }

    // Open the BPF map
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    // Validate command
    if (!is_valid_command(cmd)) {
        fprintf(stderr, "Invalid command\n");
        aw_bpf_usage();
        return EXIT_FAILURE;
    }

    bool success = false;

    // Handle commands
    if (strcmp(cmd, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s %s add <IP_ADDRESS|MAC_ADDRESS>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }
        success = handle_add_command(map_fd, map_type, argv[3]);
    } 
    else if (strcmp(cmd, "list") == 0) {
        success = handle_list_command(map_fd, map_type);
    } 
    else if (strcmp(cmd, "json") == 0) {
        if (argc != 3) {
            printf("{\"error\":\"Invalid arguments\"}\n");
            return EXIT_FAILURE;
        }
        success = handle_json_command(map_fd, map_type);
    } 
    else if (strcmp(cmd, "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s %s del <IP_ADDRESS|MAC_ADDRESS>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }
        success = handle_del_command(map_fd, map_type, argv[3]);
    } 
    else if (strcmp(cmd, "flush") == 0) {
        if (bpf_map_delete_elem(map_fd, NULL) < 0) {
            perror("bpf_map_delete_elem");
            return EXIT_FAILURE;
        }
        printf("Flushed all entries in the map.\n");
        success = true;
    } 
    else if (strcmp(cmd, "update") == 0) {
        if (argc != 8 || strcmp(argv[4], "downrate") != 0 || strcmp(argv[6], "uprate") != 0) {
            fprintf(stderr, "Usage: %s %s update <IP_ADDRESS|MAC_ADDRESS> downrate <bps> uprate <bps>\n", 
                    argv[0], map_type);
            return EXIT_FAILURE;
        }
        success = handle_update_command(map_fd, map_type, argv[3], atoi(argv[5]), atoi(argv[7]));
    } 
    else if (strcmp(cmd, "update_all") == 0) {
        if (argc != 6 || strcmp(argv[3], "downrate") != 0 || strcmp(argv[5], "uprate") != 0) {
            fprintf(stderr, "Usage: %s %s update_all downrate <bps> uprate <bps>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }
        success = handle_update_all_command(map_fd, map_type, atoi(argv[4]), atoi(argv[6]));
    }

    close(map_fd);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}