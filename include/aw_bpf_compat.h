/*
 * aw_bpf_compat.h - Compatibility header for building apfree-wifidog without aw-bpf tree
 * Provides minimal user-space definitions required by apfree-wifidog so the project
 * can compile independently of the aw-bpf repository.
 */
#ifndef AW_BPF_COMPAT_H
#define AW_BPF_COMPAT_H

#include <stdint.h>
#include <stdbool.h>
#if defined(__has_include)
#  if __has_include(<linux/types.h>)
#    include <linux/types.h>
#  endif
#endif
#include <time.h>
#include <string.h>

/* XDPI constants and IOCTLs (user-space friendly) */
#define INGRESS 0
#define EGRESS 1

#define XDPI_IOC_MAGIC 'X'
#define XDPI_IOC_ADD    0x40584001
#define XDPI_IOC_DEL    0x40584002
#define XDPI_IOC_UPDATE 0x40584003
#define XDPI_IOC_LIST   0x40584004

#define MAX_DOMAIN_LEN 64
#define XDPI_DOMAIN_MAX 256

#define RATE_ESTIMATOR 4
#define SMOOTH_VALUE 10

struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    int domain_len;
    int sid;
    bool used;
    uint64_t access_count;
    uint64_t last_access_time;
    uint64_t first_seen_time;
};

struct domain_update {
    struct domain_entry entry;
    int index;
};

/* Traffic statistics structures (simplified user-space view) */
struct counters {
    uint32_t cur_s_bytes;
    uint32_t prev_s_bytes;
    uint64_t total_bytes;
    uint64_t total_packets;
    uint32_t est_slot;
    uint32_t reserved;
};

struct rate_limit {
    uint64_t bps;
    uint64_t t_last;
    uint64_t tokens;
};

struct traffic_stats {
    struct counters incoming;
    struct counters outgoing;
    struct rate_limit incoming_rate_limit;
    struct rate_limit outgoing_rate_limit;
};

/* Session data used by ring buffer events */
struct session_data_t {
    uint32_t sid;
    uint8_t ip_version;
    uint8_t proto;
    uint8_t reserved[2];
    union {
        struct {
            uint32_t saddr_v4;
            uint32_t daddr_v4;
        } v4;
        struct {
            uint8_t saddr_v6[16];
            uint8_t daddr_v6[16];
        } v6;
    } addrs;
    uint16_t sport;
    uint16_t dport;
} __attribute__((packed));

/**
 * @brief Get current monotonic time in seconds
 */
static inline uint32_t aw_bpf_gettime(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)ts.tv_sec;
}

static inline uint32_t calc_rate_estimator(struct traffic_stats *val, bool is_incoming)
{
    uint32_t now = aw_bpf_gettime();
    uint32_t est_slot = now / RATE_ESTIMATOR;
    uint64_t prev_bytes = 0;
    uint64_t cur_bytes = 0;
    uint32_t elapsed = now % RATE_ESTIMATOR;
    uint32_t remain = RATE_ESTIMATOR - elapsed;
    uint64_t weighted_bytes = 0;

    if (!val) return 0;

    if (is_incoming) {
        if (val->incoming.est_slot == est_slot) {
            prev_bytes = val->incoming.prev_s_bytes;
            cur_bytes = val->incoming.cur_s_bytes;
        } else if (val->incoming.est_slot == est_slot - 1) {
            prev_bytes = val->incoming.cur_s_bytes;
            cur_bytes = 0;
            elapsed = 0;
            remain = RATE_ESTIMATOR;
        } else {
            return 0;
        }
    } else {
        if (val->outgoing.est_slot == est_slot) {
            prev_bytes = val->outgoing.prev_s_bytes;
            cur_bytes = val->outgoing.cur_s_bytes;
        } else if (val->outgoing.est_slot == est_slot - 1) {
            prev_bytes = val->outgoing.cur_s_bytes;
            cur_bytes = 0;
            elapsed = 0;
            remain = RATE_ESTIMATOR;
        } else {
            return 0;
        }
    }

    weighted_bytes = prev_bytes * remain + cur_bytes * elapsed;
    return (uint32_t)((weighted_bytes * 8) / (RATE_ESTIMATOR * RATE_ESTIMATOR));
}

#endif /* AW_BPF_COMPAT_H */
