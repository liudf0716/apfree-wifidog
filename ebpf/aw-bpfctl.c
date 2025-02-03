// update_maps.c
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "aw-bpf.h"

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ipv4|ipv6> <IP_ADDRESS>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Open the map (assuming maps are pinned)
    const char *map_type = argv[1];
    const char *map_path = NULL;
    if (strcmp(map_type, "ipv4") == 0) {
        map_path = "/sys/fs/bpf/tc/globals/ipv4_map";
    } else if (strcmp(map_type, "ipv6") == 0) {
        map_path = "/sys/fs/bpf/tc/globals/ipv6_map";
    } else {
        fprintf(stderr, "Invalid map type. Use 'ipv4' or 'ipv6'.\n");
        return EXIT_FAILURE;
    }

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    // Initialize key
    union {
        __be32 ipv4_key;
        struct in6_addr ipv6_key;
    } key = {0};

    // Convert IP string to key
    if (strcmp(map_type, "ipv4") == 0) {
        if (inet_pton(AF_INET, argv[2], &key.ipv4_key) != 1) {
            perror("inet_pton (IPv4)");
            return EXIT_FAILURE;
        }
    } else {
        if (inet_pton(AF_INET6, argv[2], &key.ipv6_key) != 1) {
            perror("inet_pton (IPv6)");
            return EXIT_FAILURE;
        }
    }

    // Check if key exists
    void *temp_value;
    if (bpf_map_lookup_elem(map_fd, 
        (strcmp(map_type, "ipv4") == 0) ? (void *)&key.ipv4_key : (void *)&key.ipv6_key,
        &temp_value) == 0) {
        printf("Key %s already exists in %s map.\n", argv[2], map_type);
        return EXIT_SUCCESS;
    }

    // Add the key with zero-initialized value
    struct traffic_stats stats = {0};
    int ret = bpf_map_update_elem(
        map_fd,
        (strcmp(map_type, "ipv4") == 0) ? (void *)&key.ipv4_key : (void *)&key.ipv6_key,
        &stats,
        BPF_NOEXIST  // Only add if key doesn't exist
    );

    if (ret < 0) {
        perror("bpf_map_update_elem");
        return EXIT_FAILURE;
    }

    printf("Successfully added %s to %s map.\n", argv[2], map_type);
    return EXIT_SUCCESS;
}