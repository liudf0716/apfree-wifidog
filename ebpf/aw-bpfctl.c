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

#define DNS_STATS_FILE "/tmp/dns_stats.txt"  /* DNS统计文件 */
#define XDPI_DEVICE "/dev/xdpi"

struct xdpi_l7_proto {
    __u32 id;
    char proto_desc[XDPI_PROTO_FEATURE_MAX_SIZE];
    __u32 sid;
};

// 前向声明函数
static void print_stats_l7(void);

static struct xdpi_l7_proto xdpi_l7_protos[XDPI_PROTO_TRAITS_MAX_SIZE];
static int xdpi_l7_protos_count = 0;

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

static const char *get_l7_proto_desc_by_sid(__u32 sid) {
    for (int i = 0; i < xdpi_l7_protos_count; i++) {
        if (xdpi_l7_protos[i].sid == sid) {
            return xdpi_l7_protos[i].proto_desc;
        }
    }
    return "unknown";
}

// 通过SID从内核获取域名信息
static const char* get_domain_name_by_sid(__u32 sid) {
    static char domain_name[XDPI_PROTO_FEATURE_MAX_SIZE] = "unknown";
    
    int fd = open(XDPI_DEVICE, O_RDWR);
    if (fd < 0) {
        return "unknown";
    }
    
    struct domain_list list;
    memset(&list, 0, sizeof(list));
    list.max_count = XDPI_DOMAIN_MAX;
    
    if (ioctl(fd, XDPI_IOC_LIST, &list) == 0) {
        for (int i = 0; i < list.count; i++) {
            struct domain_entry *entry = &list.domains[i];
            if (entry->used && entry->sid == sid) {
                strncpy(domain_name, entry->domain, sizeof(domain_name) - 1);
                domain_name[sizeof(domain_name) - 1] = '\0';
                close(fd);
                return domain_name;
            }
        }
    }
    
    close(fd);
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
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7> list\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> del <IP_ADDRESS|MAC_ADDRESS>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> flush\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid|l7> json\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid> update <IP_ADDRESS|MAC_ADDRESS|SID> downrate <bps> uprate <bps>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac|sid> update_all downrate <bps> uprate <bps>\n");
}

static bool
is_valid_command(const char *cmd)
{
    return !strcmp(cmd, "add") || !strcmp(cmd, "list") || !strcmp(cmd, "del") || !strcmp(cmd, "flush") || 
           !strcmp(cmd, "json") || !strcmp(cmd, "update") || !strcmp(cmd, "update_all");
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
    
    // 创建域名信息数组 - 直接从内核获取
    struct json_object *jdomains = json_object_new_array();
    
    // 获取域名列表
    int fd = open(XDPI_DEVICE, O_RDWR);
    if (fd >= 0) {
        struct domain_list list;
        memset(&list, 0, sizeof(list));
        list.max_count = XDPI_DOMAIN_MAX;
        
        if (ioctl(fd, XDPI_IOC_LIST, &list) == 0) {
            for (int i = 0; i < list.count; i++) {
                struct domain_entry *entry = &list.domains[i];
                if (!entry->used) continue;
                
                struct json_object *jentry = json_object_new_object();
                json_object_object_add(jentry, "id", json_object_new_int(i + 1));
                json_object_object_add(jentry, "domain", json_object_new_string(entry->domain));
                json_object_object_add(jentry, "sid", json_object_new_int(entry->sid));
                
                // 添加 DNS 统计信息（如果有）
                if (entry->access_count > 0) {
                    json_object_object_add(jentry, "access_count", json_object_new_int64(entry->access_count));
                    json_object_object_add(jentry, "first_seen", json_object_new_int64((int64_t)entry->first_seen_time));
                    json_object_object_add(jentry, "last_access", json_object_new_int64((int64_t)entry->last_access_time));
                    
                    // 添加人类可读的时间格式
                    if (entry->first_seen_time > 0) {
                        char time_str[64];
                        time_t first_seen = (time_t)entry->first_seen_time;
                        struct tm *tm_info = localtime(&first_seen);
                        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                        json_object_object_add(jentry, "first_seen_str", json_object_new_string(time_str));
                    }
                    if (entry->last_access_time > 0) {
                        char time_str[64];
                        time_t last_access = (time_t)entry->last_access_time;
                        struct tm *tm_info = localtime(&last_access);
                        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                        json_object_object_add(jentry, "last_access_str", json_object_new_string(time_str));
                    }
                }
                
                json_object_array_add(jdomains, jentry);
            }
        }
        close(fd);
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
    
    // 再显示 Domain 部分（包含详细统计信息）- 直接从内核获取
    printf("\n===== Domains =====\n");
    printf("%-5s | %-40s | %-5s | %-12s | %-20s | %-20s\n",
           "Index", "Domain", "SID", "Access Count", "First Seen", "Last Access");
    printf("------------------------------------------------------------------------------------------------------------------------\n");
    
    // 获取域名列表
    int fd = open(XDPI_DEVICE, O_RDWR);
    if (fd >= 0) {
        struct domain_list list;
        memset(&list, 0, sizeof(list));
        list.max_count = XDPI_DOMAIN_MAX;
        
        if (ioctl(fd, XDPI_IOC_LIST, &list) == 0) {
            for (int i = 0; i < list.count; i++) {
                struct domain_entry *entry = &list.domains[i];
                if (!entry->used) continue;
                
                // 基本信息
                printf("%5d | %-40s | %5u", 
                       i + 1, 
                       entry->domain, 
                       entry->sid);
                
                // DNS统计信息
                if (entry->access_count > 0) {
                    printf(" | %12llu", (unsigned long long)entry->access_count);
                    
                    // 格式化时间
                    char first_seen_str[20] = "-";
                    char last_access_str[20] = "-";
                    if (entry->first_seen_time > 0) {
                        time_t first_seen = (time_t)entry->first_seen_time;
                        struct tm *tm_info = localtime(&first_seen);
                        strftime(first_seen_str, sizeof(first_seen_str), "%m-%d %H:%M:%S", tm_info);
                    }
                    if (entry->last_access_time > 0) {
                        time_t last_access = (time_t)entry->last_access_time;
                        struct tm *tm_info = localtime(&last_access);
                        strftime(last_access_str, sizeof(last_access_str), "%m-%d %H:%M:%S", tm_info);
                    }
                    printf(" | %-20s | %-20s", first_seen_str, last_access_str);
                } else {
                    printf(" | %12s | %-20s | %-20s", "-", "-", "-");
                }
                
                printf("\n");
            }
        } else {
            printf("Failed to get domain list from kernel\n");
        }
        close(fd);
    } else {
        printf("Failed to open " XDPI_DEVICE "\n");
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

int 
main(int argc, char **argv) 
{
    if (argc < 3) {
        aw_bpf_usage();
        return EXIT_FAILURE;
    }

    // Load L7 protos at startup
    load_xdpi_l7_protos();

    const char *map_type = argv[1];
    const char *cmd = argv[2];

    // Validate map type
    if (strcmp(map_type, "ipv4") != 0 && 
        strcmp(map_type, "ipv6") != 0 && 
        strcmp(map_type, "mac") != 0 && 
        strcmp(map_type, "sid") != 0 &&
        strcmp(map_type, "l7") != 0) {
        fprintf(stderr, "Invalid map type. Must be 'ipv4', 'ipv6', 'mac', 'sid', or 'l7'.\n");
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