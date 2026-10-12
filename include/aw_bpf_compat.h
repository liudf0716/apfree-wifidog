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
#  if __has_include(<linux/bpf.h>)
#    include <linux/bpf.h>
#  endif
#endif
#ifndef __LINUX_BPF_H__
struct bpf_spin_lock {
    uint32_t val;
};
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

#define MAX_DNS_PAYLOAD_LEN 512
#define DNS_RINGBUF_PORTAL_MAP_PATH      "/sys/fs/bpf/tc/globals/dns_ringbuf_portal"
#define DNS_RINGBUF_PORTAL_MAP_PATH_ALT  "/sys/fs/bpf/aw/dns_ringbuf_portal"
#define DNS_RINGBUF_PORTAL_MAP_PATH_XDP  "/sys/fs/bpf/xdp/globals/dns_ringbuf_portal"
#define DNS_RINGBUF_PORTAL_MAP_PATH_ROOT "/sys/fs/bpf/dns_ringbuf_portal"
#define DNS_PORTAL_BUF_MAP_PATH          "/sys/fs/bpf/tc/globals/dns_portal_buf"
#define DNS_PORTAL_BUF_MAP_PATH_ALT      "/sys/fs/bpf/aw/dns_portal_buf"
#define DNS_PORTAL_BUF_MAP_PATH_XDP      "/sys/fs/bpf/xdp/globals/dns_portal_buf"
#define DNS_PORTAL_BUF_MAP_PATH_ROOT     "/sys/fs/bpf/dns_portal_buf"

#define MAX_DOMAIN_LEN 64
#define XDPI_DOMAIN_MAX 256

#define RATE_ESTIMATOR 4
#define SMOOTH_VALUE 10

struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    uint32_t domain_len;
    uint32_t sid;
    uint32_t used;
    uint32_t padding;
    uint64_t access_count;
    uint64_t last_access_time;
    uint64_t first_seen_time;
};
_Static_assert(sizeof(struct domain_entry) == 104, "struct domain_entry must match aw-bpf ABI size (104 bytes)");

struct domain_update {
    struct domain_entry entry;
    int index;
};

/* Time-based traffic control matching */
#define AW_TIME_FLAG_ENABLED        (1 << 0)  /* Whether time control is enabled */
#define AW_TIME_FLAG_LOCAL_TZ       (1 << 1)  /* Calculate using local timezone */
#define AW_TIME_FLAG_INVERT         (1 << 2)  /* Invert match condition */

struct aw_time_rule {
    uint8_t   flags;            /* AW_TIME_FLAG_* */
    uint8_t   weekdays_match;   /* Weekdays mask: bit0=Sun, bit1=Mon ... bit6=Sat (0x7F=all, 0=any) */
    uint16_t  reserved;         /* Alignment padding */
    uint32_t  daytime_start;    /* Day start seconds (0~86399, e.g. 09:30:00 = 34200) */
    uint32_t  daytime_stop;     /* Day stop seconds (0~86399, e.g. 18:30:00 = 66600) */
    uint32_t  date_start;       /* Epoch seconds start (0 = unlimited) */
    uint32_t  date_stop;        /* Epoch seconds stop (0 = unlimited) */
    int32_t   tz_offset_sec;    /* Local timezone offset in seconds (e.g. +28800 for UTC+8) */
    uint32_t  reserved2;        /* Reserved for future expansion */
};

/* Traffic statistics structures */
struct counters {
    uint32_t cur_s_bytes;
    uint32_t prev_s_bytes;
    uint64_t total_bytes;
    uint64_t total_packets;
    uint32_t est_slot;
    uint32_t reserved;
    uint64_t ppe_bytes;
    uint64_t ppe_packets;
} __attribute__((packed));

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
    struct aw_time_rule time_rule;
};

_Static_assert(sizeof(struct traffic_stats) == 176, "struct traffic_stats must match aw-bpf map value size (176 bytes)");

/* Non-percpu QoS rate limit structures */
struct qos_rate_limit {
    uint64_t bps;
    uint64_t t_last;
    uint64_t tokens;
};

struct qos_limit_cfg {
    struct bpf_spin_lock lock;
    uint32_t pad;
    struct qos_rate_limit incoming;
    struct qos_rate_limit outgoing;
    struct aw_time_rule time_rule;
};

_Static_assert(sizeof(struct qos_limit_cfg) == 88, "struct qos_limit_cfg size mismatch");

struct router_ip_cfg {
    uint32_t lan_ip;
    uint32_t wan_ip;
};

_Static_assert(sizeof(struct router_ip_cfg) == 8, "struct router_ip_cfg size mismatch");

#define AW_BPF_PIN_BASE "/sys/fs/bpf/tc/globals"
#define AW_BPF_IPV4_QOS_MAP_PATH AW_BPF_PIN_BASE "/ipv4_qos_map"
#define AW_BPF_IPV6_QOS_MAP_PATH AW_BPF_PIN_BASE "/ipv6_qos_map"
#define AW_BPF_MAC_QOS_MAP_PATH  AW_BPF_PIN_BASE "/mac_qos_map"
#define AW_BPF_SID_QOS_MAP_PATH  AW_BPF_PIN_BASE "/xdpi_l7_qos_map"
#define AW_BPF_ROUTER_IP_MAP_PATH AW_BPF_PIN_BASE "/router_ip_map"

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
