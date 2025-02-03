/*
 * aw-bpf.h - Header file for WiFiDog eBPF traffic statistics
 * Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef AW_BPF_H
#define AW_BPF_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

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
} __attribute__((packed));

/* Function declarations if any would go here */

#endif /* AW_BPF_H */