// update_maps.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
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
#define	SMOOTH_VALUE	10
#define	RATE_ESTIMATOR	4
	uint32_t now = aw_bpf_gettime();
	uint32_t est_slot = now / RATE_ESTIMATOR;
	uint32_t rate = 0;
	uint32_t cur_bytes = 0;
	uint32_t delta = RATE_ESTIMATOR - (now % RATE_ESTIMATOR);
	uint32_t ratio = RATE_ESTIMATOR * SMOOTH_VALUE / delta;

    printf("now: %u, est_slot: %u, delta: %u, ratio: %u\n", now, est_slot, delta, ratio);
    printf("val->incoming.est_slot: %u, val->incoming.prev_s_bytes: %u, val->incoming.cur_s_bytes: %u\n",
           val->incoming.est_slot, val->incoming.prev_s_bytes, val->incoming.cur_s_bytes);
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
}

int 
main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  %s <ipv4|ipv6> add <IP_ADDRESS>\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6> list\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6> del <IP_ADDRESS>\n", argv[0]);
        fprintf(stderr, "  %s <ipv4|ipv6> flush\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *map_type = argv[1];
    const char *cmd = argv[2];
    const char *map_path = NULL;

    /* Adjust the pinning path as appropriate for your setup. */
    if (strcmp(map_type, "ipv4") == 0)
        map_path = "/sys/fs/bpf/tc/globals/ipv4_map";
    else if (strcmp(map_type, "ipv6") == 0)
        map_path = "/sys/fs/bpf/tc/globals/ipv6_map";
    else {
        fprintf(stderr, "Invalid map type. Use 'ipv4' or 'ipv6'.\n");
        return EXIT_FAILURE;
    }

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    if (strcmp(cmd, "add") == 0) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s %s add <IP_ADDRESS>\n", argv[0], map_type);
            return EXIT_FAILURE;
        }
        const char *ip_str = argv[3];
        struct traffic_stats stats = {0};  // zero-initialized

        if (strcmp(map_type, "ipv4") == 0) {
            __be32 key = 0;
            if (inet_pton(AF_INET, ip_str, &key) != 1) {
                perror("inet_pton (IPv4)");
                return EXIT_FAILURE;
            }
            /* Check if exists */
            struct traffic_stats tmp;
            if (bpf_map_lookup_elem(map_fd, &key, &tmp) == 0) {
                printf("IPv4 key %s already exists in map.\n", ip_str);
                return EXIT_SUCCESS;
            }
            if (bpf_map_update_elem(map_fd, &key, &stats, BPF_NOEXIST) < 0) {
                perror("bpf_map_update_elem (IPv4)");
                return EXIT_FAILURE;
            }
            printf("Added IPv4 key %s successfully.\n", ip_str);
        } else { // ipv6
            struct in6_addr key = {0};
            if (inet_pton(AF_INET6, ip_str, &key) != 1) {
                perror("inet_pton (IPv6)");
                return EXIT_FAILURE;
            }
            struct traffic_stats tmp;
            if (bpf_map_lookup_elem(map_fd, &key, &tmp) == 0) {
                printf("IPv6 key %s already exists in map.\n", ip_str);
                return EXIT_SUCCESS;
            }
            if (bpf_map_update_elem(map_fd, &key, &stats, BPF_NOEXIST) < 0) {
                perror("bpf_map_update_elem (IPv6)");
                return EXIT_FAILURE;
            }
            printf("Added IPv6 key %s successfully.\n", ip_str);
        }
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
    } else {
        fprintf(stderr, "Invalid command. Use 'add <IP_ADDRESS>' or 'list'.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}