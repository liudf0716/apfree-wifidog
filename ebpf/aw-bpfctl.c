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

#include "aw-bpf.h"

static uint32_t 
aw_bpf_gettime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

static uint32_t
calc_rate_estimator(struct traffic_stats *val, bool is_incoming)
{
	uint32_t now = aw_bpf_gettime();
	uint32_t est_slot = now / RATE_ESTIMATOR;
	uint32_t rate = 0;
	uint32_t cur_bytes = 0;
	uint32_t delta = RATE_ESTIMATOR - (now % RATE_ESTIMATOR);
	uint32_t ratio = RATE_ESTIMATOR * SMOOTH_VALUE / delta;
#if 0
    printf("est_slot=%u, now=%u, delta=%u, ratio=%u\n", est_slot, now, delta, ratio);
    if (is_incoming) {
        printf("incoming: est_slot=%u, prev_s_bytes=%u, cur_s_bytes=%u\n", val->incoming.est_slot, val->incoming.prev_s_bytes, val->incoming.cur_s_bytes);
    } else {
        printf("outgoing: est_slot=%u, prev_s_bytes=%u, cur_s_bytes=%u\n", val->outgoing.est_slot, val->outgoing.prev_s_bytes, val->outgoing.cur_s_bytes);
    }
#endif
    if (is_incoming) {
        if (val->incoming.est_slot == est_slot) {
            rate = val->incoming.prev_s_bytes;
            cur_bytes = val->incoming.cur_s_bytes;
        } else if (val->incoming.est_slot == est_slot - 1) {
            rate = val->incoming.cur_s_bytes;
        } else {
            return 0;
        }
    } else {
        if (val->outgoing.est_slot == est_slot) {
            rate = val->outgoing.prev_s_bytes;
            cur_bytes = val->outgoing.cur_s_bytes;
        } else if (val->outgoing.est_slot == est_slot - 1) {
            rate = val->outgoing.cur_s_bytes;
        } else {
            return 0;
        }
    }

	rate = rate * SMOOTH_VALUE / ratio;
	rate += cur_bytes;

	return rate * 8 / RATE_ESTIMATOR;
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
    printf("  Rate Limits: incoming=%u bps, outgoing=%u bps\n",
           stats->incoming_rate_limit, stats->outgoing_rate_limit);
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
    printf("  Rate Limits: incoming=%u bps, outgoing=%u bps\n",
           stats->incoming_rate_limit, stats->outgoing_rate_limit);
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
    printf("  Rate Limits: incoming=%u bps, outgoing=%u bps\n",
           stats->incoming_rate_limit, stats->outgoing_rate_limit);
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
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_int(stats->incoming_rate_limit));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_int(stats->outgoing_rate_limit));
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
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_int(stats->incoming_rate_limit));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_int(stats->outgoing_rate_limit));
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
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_int(stats->incoming_rate_limit));
    json_object_object_add(jobj, "incoming", incoming);

    // Add outgoing stats
    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_int(stats->outgoing_rate_limit));
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
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> list\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> del <IP_ADDRESS|MAC_ADDRESS>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> flush\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> json\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> update <IP_ADDRESS|MAC_ADDRESS> downrate <bps> uprate <bps>\n");
    fprintf(stderr, "  aw-bpfctl <ipv4|ipv6|mac> update_all downrate <bps> uprate <bps>\n");
}

static bool
is_valid_command(const char *cmd)
{
    return !strcmp(cmd, "add") || !strcmp(cmd, "list") || !strcmp(cmd, "del") || !strcmp(cmd, "flush") || !strcmp(cmd, "json") || !strcmp(cmd, "update") || !strcmp(cmd, "update_all");
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

    if (bpf_map_update_elem(map_fd, key, &stats, BPF_NOEXIST) < 0) {
        perror("bpf_map_update_elem");
        return false;
    }

    printf("Added %s key %s successfully.\n", map_type, addr_str);
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
    } else { // ipv6
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
    stats.incoming_rate_limit = downrate;
    stats.outgoing_rate_limit = uprate;
    
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
    stats.incoming_rate_limit = downrate;
    stats.outgoing_rate_limit = uprate;
    
    if (strcmp(map_type, "ipv4") == 0) {
        __be32 cur_key = 0, next_key = 0;
        struct traffic_stats existing;
        
        while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
            // Keep existing traffic stats, just update rate limits
            if (bpf_map_lookup_elem(map_fd, &next_key, &existing) == 0) {
                existing.incoming_rate_limit = downrate;
                existing.outgoing_rate_limit = uprate;
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
                existing.incoming_rate_limit = downrate;
                existing.outgoing_rate_limit = uprate;
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
                existing.incoming_rate_limit = downrate;
                existing.outgoing_rate_limit = uprate;
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

int 
main(int argc, char **argv) 
{
    if (argc < 3) {
        aw_bpf_usage();
        return EXIT_FAILURE;
    }

    const char *map_type = argv[1];
    const char *cmd = argv[2];

    // Validate map type
    if (strcmp(map_type, "ipv4") != 0 && 
        strcmp(map_type, "ipv6") != 0 && 
        strcmp(map_type, "mac") != 0) {
        fprintf(stderr, "Invalid map type. Must be 'ipv4', 'ipv6', or 'mac'.\n");
        return EXIT_FAILURE;
    }

    // Determine map path based on map type
    char map_path[100];
    snprintf(map_path, sizeof(map_path), "/sys/fs/bpf/tc/globals/%s_map", map_type);

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