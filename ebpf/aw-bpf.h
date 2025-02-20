/*
 * aw-bpf.h - Header file for apfree wifidog eBPF traffic statistics
 * Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef AW_BPF_H
#define AW_BPF_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define ETH_ALEN        6
#define RATE_ESTIMATOR  4
#define SMOOTH_VALUE    10

struct mac_addr {
    char h_addr[ETH_ALEN];
} __attribute__((packed));

/**
 * @struct counters
 * @brief Structure to hold network traffic counters
 */
struct counters {
    __u32 cur_s_bytes;      /* Current session bytes */
    __u32 prev_s_bytes;     /* Previous session bytes */
    __u64 total_bytes;      /* Total bytes transferred */
    __u64 total_packets;    /* Total packets count */
    __u32 est_slot;         /* Estimation time slot */
    __u32 reserved;         /* Reserved for future use */
} __attribute__((packed));

/**
 * @struct traffic_stats
 * @brief Structure to maintain both incoming and outgoing traffic statistics
 */
struct traffic_stats {
    struct counters incoming;    /* Incoming traffic counters */
    struct counters outgoing;    /* Outgoing traffic counters */
    __u32  incoming_rate_limit;   /* Incoming rate limit */
    __u32  outgoing_rate_limit;   /* Outgoing rate limit */
} __attribute__((packed));

/* Function declarations if any would go here */

#endif /* AW_BPF_H */