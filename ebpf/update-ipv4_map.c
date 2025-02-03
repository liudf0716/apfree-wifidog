#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h> // or include <bpf/bpf.h> if libbpf not used

// Define the structure exactly as in the BPF program.
struct counters {
    __u32 cur_s_bytes;
    __u32 prev_s_bytes;
    __u64 total_bytes;
    __u64 total_packets;
    __u32 est_slot;
    __u32 reserved;
};

struct traffic_stats {
    struct counters incoming;
    struct counters outgoing;
};

int main(int argc, char **argv)
{
    const char *pin_path = "/sys/fs/bpf/aw_bpf/ipv4_map"; // adjust if your map is pinned here
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return EXIT_FAILURE;
    }

    // The key is an IPv4 address in network byte order.
    __u32 ip_key;
    // Convert string IP to network order.
    if (inet_pton(AF_INET, "192.168.1.100", &ip_key) != 1) {
        perror("inet_pton");
        return EXIT_FAILURE;
    }

    // Initialize value as needed.
    struct traffic_stats stats = {0};

    if (bpf_map_update_elem(map_fd, &ip_key, &stats, 0)) {
        perror("bpf_map_update_elem");
        return EXIT_FAILURE;
    }

    printf("IPv4 map updated successfully.\n");
    return EXIT_SUCCESS;
}