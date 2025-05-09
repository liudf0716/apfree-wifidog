/*
 * aw-bpf.h - Header file for apfree wifidog eBPF traffic statistics
 * Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef AW_BPF_H
#define AW_BPF_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/compiler.h>
#include <bpf/bpf_helpers.h>
#else
#include <stdint.h>
#include <stdbool.h>  /* 添加 bool 类型定义 */
#include <time.h>     /* 添加 timespec 和 clock_gettime 定义 */

/* 添加在用户空间需要的定义 */
#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) (*(volatile typeof(x) *)&(x)) = (val)
#endif

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000UL
#endif
#endif

#define ETH_ALEN        6
#define RATE_ESTIMATOR  4
#define SMOOTH_VALUE    10
#define XDPI_PROTO_TRAITS_MAX_SIZE 128
#define XDPI_PROTO_FEATURE_MAX_SIZE 32

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFFU
#endif

#define DROP_HORIZON 2000000000UL  /* 2 seconds in nanoseconds */
#define TCP_CONN_TIMEOUT_NS 60000000000ULL /* 60 seconds in nanoseconds */
#define TCP_CONN_TIMEOUT_SEC 60 /* 60 seconds */
#define UDP_CONN_TIMEOUT_NS 30000000000ULL /* 30 seconds in nanoseconds */
#define UDP_CONN_TIMEOUT_SEC 30 /* 30 seconds */

typedef enum {
    INGRESS,
    EGRESS,
} direction_t;

struct mac_addr {
    __u8 h_addr[ETH_ALEN];
} __attribute__((packed));

/*
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

struct rate_limit {
    __u64 bps;             /* Rate limit */
    __u64 t_last;        /* Last time traffic was seen */
    __u64 tokens;         /* Tokens */
};

/**
 * @struct traffic_stats
 * @brief Structure to maintain both incoming and outgoing traffic statistics
 */
struct traffic_stats {
    struct counters incoming;    /* Incoming traffic counters */
    struct counters outgoing;    /* Outgoing traffic counters */
    struct rate_limit incoming_rate_limit;    /* Incoming rate limit */
    struct rate_limit outgoing_rate_limit;    /* Outgoing rate limit */
};

struct xdpi_nf_conn {
    __u32  sid;
    __u32  pkt_seen;
    __u32  last_time;
    struct bpf_timer timer;
};

#ifndef __KERNEL__
/**
 * @brief Get current monotonic time in seconds
 * @return Current time in seconds
 */
static inline uint32_t aw_bpf_gettime(void)
{
    struct timespec ts;
    
    clock_gettime(CLOCK_MONOTONIC, &ts);
    
    return ts.tv_sec;
}

/**
 * @brief Calculate the data rate based on traffic statistics
 * @param stats Pointer to traffic statistics structure
 * @param is_incoming Flag indicating if calculating for incoming (true) or outgoing (false) traffic
 * @return Data rate in bits per second
 */
static inline uint32_t calc_rate_estimator(struct traffic_stats *val, bool is_incoming)
{
    uint32_t now = aw_bpf_gettime();
    uint32_t est_slot = now / RATE_ESTIMATOR;
    uint32_t rate = 0;
    uint32_t cur_bytes = 0;
    uint32_t delta = RATE_ESTIMATOR - (now % RATE_ESTIMATOR);
    uint32_t ratio = RATE_ESTIMATOR * SMOOTH_VALUE / delta;
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
#endif

#endif /* AW_BPF_H */