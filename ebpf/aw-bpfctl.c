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

int 
main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <ipv4|ipv6|mac> add <IP_ADDRESS|MAC_ADDRESS>\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6|mac> list\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6|mac> del <IP_ADDRESS|MAC_ADDRESS>\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6|mac> flush\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6|mac> json\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6|mac> update <IP_ADDRESS|MAC_ADDRESS> downrate <bps> uprate <bps>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *map_type = argv[1];
    const char *cmd = argv[2];
    const char *map_path = NULL;

    /* Set map path based on map type */
    if (!strcmp(map_type, "ipv4")) {
        map_path = "/sys/fs/bpf/tc/globals/ipv4_map";
    } else if (!strcmp(map_type, "ipv6")) {
        map_path = "/sys/fs/bpf/tc/globals/ipv6_map";
    } else if (!strcmp(map_type, "mac")) {
        map_path = "/sys/fs/bpf/tc/globals/mac_map";
    } else {
        fprintf(stderr, "Invalid map type. Must be 'ipv4', 'ipv6', or 'mac'.\n");
        return EXIT_FAILURE;
    }

    if (!map_path) {
        fprintf(stderr, "Failed to determine map path\n");
        return EXIT_FAILURE;
    }

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    if (strcmp(cmd, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s %s add <IP_ADDRESS|MAC_ADDRESS>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }

        const char *addr_str = argv[3];
        struct traffic_stats stats = {0};
        void *key = NULL;
        int key_size = 0;
        bool success = false;

        if (strcmp(map_type, "ipv4") == 0) {
            __be32 ipv4_key = 0;
            if (inet_pton(AF_INET, addr_str, &ipv4_key) != 1) {
                perror("inet_pton (IPv4)");
                return EXIT_FAILURE;
            }
            key = &ipv4_key;
            key_size = sizeof(ipv4_key);
            success = true;
        } else if (strcmp(map_type, "mac") == 0) {
            if (!is_valid_mac_addr(addr_str)) {
                fprintf(stderr, "Invalid MAC address format\n");
                return EXIT_FAILURE;
            }
            struct mac_addr mac_key = {0};
            parse_mac_address(&mac_key, addr_str);
            key = &mac_key;
            key_size = sizeof(mac_key);
            success = true;
        } else if (strcmp(map_type, "ipv6") == 0) {
            struct in6_addr ipv6_key = {0};
            if (inet_pton(AF_INET6, addr_str, &ipv6_key) != 1) {
                perror("inet_pton (IPv6)");
                return EXIT_FAILURE;
            }
            key = &ipv6_key;
            key_size = sizeof(ipv6_key);
            success = true;
        }

        if (!success || !key) {
            fprintf(stderr, "Invalid address type\n");
            return EXIT_FAILURE;
        }

        struct traffic_stats tmp;
        if (bpf_map_lookup_elem(map_fd, key, &tmp) == 0) {
            printf("%s key %s already exists in map.\n", map_type, addr_str);
            return EXIT_SUCCESS;
        }

        if (bpf_map_update_elem(map_fd, key, &stats, BPF_NOEXIST) < 0) {
            perror("bpf_map_update_elem");
            return EXIT_FAILURE;
        }

        printf("Added %s key %s successfully.\n", map_type, addr_str);
    } else if (strcmp(cmd, "list") == 0) {
        if (strcmp(map_type, "ipv4") == 0) {
            __be32 cur_key = 0, next_key = 0;
            int ret;
            struct traffic_stats stats = {0};
            /* Iteration: passing NULL as current key for the first call */
            while ((ret = bpf_map_get_next_key(map_fd,
                                                cur_key ? &cur_key : NULL,
                                                &next_key)) == 0) {
                if (bpf_map_lookup_elem(map_fd, &next_key, &stats) < 0) {
                    perror("bpf_map_lookup_elem (IPv4)");
                } else {
                    print_stats_ipv4(next_key, &stats);
                }
                cur_key = next_key;
            }
            if (ret != -ENOENT)
                perror("bpf_map_get_next_key (IPv4)");
        } else if (strcmp(map_type, "mac") == 0) {
            struct mac_addr cur_key = {0}, next_key = {0};
            int ret;
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
            if (ret != -ENOENT)
                perror("bpf_map_get_next_key (MAC)");
        } else { // ipv6
            struct in6_addr cur_key = {0}, next_key = {0};
            int ret;
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
            if (ret != -ENOENT)
                perror("bpf_map_get_next_key (IPv6)");
        }
    } else if (strcmp(cmd, "json") == 0) {
        if (argc != 3) {
            printf("{\"error\":\"Invalid arguments\"}\n");
            return EXIT_FAILURE;
        }

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
    } else if (strcmp(cmd, "del") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s %s del <IP_ADDRESS>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }
        const char *ip_str = argv[3];

        if (strcmp(map_type, "ipv4") == 0) {
            __be32 key = 0;
            if (inet_pton(AF_INET, ip_str, &key) != 1) {
                perror("inet_pton (IPv4)");
                return EXIT_FAILURE;
            }
            if (bpf_map_delete_elem(map_fd, &key) < 0) {
                perror("bpf_map_delete_elem (IPv4)");
                return EXIT_FAILURE;
            }
            printf("Deleted IPv4 key %s successfully.\n", ip_str);
        } else if (strcmp(map_type, "mac") == 0) {
            if (!is_valid_mac_addr(ip_str)) {
                fprintf(stderr, "Invalid MAC address format\n");
                return EXIT_FAILURE;
            }
            struct mac_addr key = {0};
            parse_mac_address(&key, ip_str);
            if (bpf_map_delete_elem(map_fd, &key) < 0) {
                perror("bpf_map_delete_elem (MAC)");
                return EXIT_FAILURE;
            }
            printf("Deleted MAC key %s successfully.\n", ip_str);
        } else { // ipv6
            struct in6_addr key = {0};
            if (inet_pton(AF_INET6, ip_str, &key) != 1) {
                perror("inet_pton (IPv6)");
                return EXIT_FAILURE;
            }
            if (bpf_map_delete_elem(map_fd, &key) < 0) {
                perror("bpf_map_delete_elem (IPv6)");
                return EXIT_FAILURE;
            }
            printf("Deleted IPv6 key %s successfully.\n", ip_str);
        }
    } else if (strcmp(cmd, "flush") == 0) {
        if (bpf_map_delete_elem(map_fd, NULL) < 0) {
            perror("bpf_map_delete_elem");
            return EXIT_FAILURE;
        }
        printf("Flushed all entries in the map.\n");
    } else if (strcmp(cmd, "update") == 0) {
        if (argc != 8 || strcmp(argv[4], "downrate") != 0 || strcmp(argv[6], "uprate") != 0) {
            fprintf(stderr, "Usage: %s %s update <IP_ADDRESS|MAC_ADDRESS> downrate <bps> uprate <bps>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }

        const char *addr_str = argv[3];
        uint32_t downrate = atoi(argv[5]);
        uint32_t uprate = atoi(argv[7]);

        // Structure to hold key information
        struct {
            void *ptr;
            size_t size;
        } key = {NULL, 0};

        // Handle different address types
        if (strcmp(map_type, "ipv4") == 0) {
            static __be32 ipv4_key;
            if (inet_pton(AF_INET, addr_str, &ipv4_key) != 1) {
                perror("inet_pton (IPv4)");
                return EXIT_FAILURE;
            }
            key.ptr = &ipv4_key;
            key.size = sizeof(ipv4_key);
        } else if (strcmp(map_type, "mac") == 0) {
            static struct mac_addr mac_key;
            if (!is_valid_mac_addr(addr_str)) {
                fprintf(stderr, "Invalid MAC address format\n");
                return EXIT_FAILURE;
            }
            parse_mac_address(&mac_key, addr_str);
            key.ptr = &mac_key;
            key.size = sizeof(mac_key);
        } else if (strcmp(map_type, "ipv6") == 0) {
            static struct in6_addr ipv6_key;
            if (inet_pton(AF_INET6, addr_str, &ipv6_key) != 1) {
                perror("inet_pton (IPv6)");
                return EXIT_FAILURE;
            }
            key.ptr = &ipv6_key;
            key.size = sizeof(ipv6_key);
        }

        if (!key.ptr) {
            fprintf(stderr, "Invalid address type\n");
            return EXIT_FAILURE;
        }

        // Prepare stats structure
        struct traffic_stats stats = {0};
        bool exists = (bpf_map_lookup_elem(map_fd, key.ptr, &stats) == 0);
        
        // Update or add entry
        int update_flag = exists ? BPF_EXIST : BPF_NOEXIST;
        stats.incoming_rate_limit = downrate;
        stats.outgoing_rate_limit = uprate;
        if (bpf_map_update_elem(map_fd, key.ptr, &stats, update_flag) < 0) {
            perror("bpf_map_update_elem");
            return EXIT_FAILURE;
        }

        printf("%s %s key %s successfully.\n", exists ? "Updated" : "Added", map_type, addr_str);
    } else {
        fprintf(stderr, "Invalid command. Use 'add <IP_ADDRESS>' or 'list'.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}