// SPDX-License-Identifier: GPL-3.0-only

#include "common.h"
#include "api_handlers.h"
#include "api_handlers_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <limits.h>

#ifdef HAVE_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#else
static inline int libbpf_num_possible_cpus(void)
{
    errno = ENOSYS;
    return -1;
}

static inline int bpf_obj_get(const char *path)
{
    (void)path;
    errno = ENOENT;
    return -1;
}

static inline int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    (void)fd;
    (void)key;
    (void)value;
    errno = ENOSYS;
    return -1;
}

static inline int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags)
{
    (void)fd;
    (void)key;
    (void)value;
    (void)flags;
    errno = ENOSYS;
    return -1;
}

static inline int bpf_map_delete_elem(int fd, const void *key)
{
    (void)fd;
    (void)key;
    errno = ENOSYS;
    return -1;
}

static inline int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    (void)fd;
    (void)key;
    (void)next_key;
    errno = ENOSYS;
    return -1;
}
#endif

#include <json-c/json.h>
#include <uci.h>

#include "aw_bpf_compat.h"

#ifndef AW_BPF_PROTO_TRAITS_MAX_SIZE
#define AW_BPF_PROTO_TRAITS_MAX_SIZE 128
#endif

#define AW_BPF_MAP_DIR "/sys/fs/bpf/tc/globals"
#define AW_BPF_IPV4_MAP_PATH AW_BPF_MAP_DIR "/ipv4_map"
#define AW_BPF_IPV6_MAP_PATH AW_BPF_MAP_DIR "/ipv6_map"
#define AW_BPF_MAC_MAP_PATH AW_BPF_MAP_DIR "/mac_map"
#define AW_BPF_SID_MAP_PATH AW_BPF_MAP_DIR "/xdpi_l7_map"
#define AW_BPF_XDPI_DEVICE "/dev/xdpi"
#define AW_BPF_XDPI_IOC_LIST XDPI_IOC_LIST
struct aw_bpf_l7_proto {
    __u32 id;
    __u32 sid;
    char proto_desc[32];
};

struct aw_bpf_domain_list {
    int32_t count;
    int32_t max_count;
    struct domain_entry domains[XDPI_DOMAIN_MAX];
};

struct aw_bpf_mac_addr {
    __u8 h_addr[6];
} __attribute__((packed));

static int aw_bpf_get_possible_cpus_cached(void)
{
    static int cached = -1;

    if (cached > 0)
        return cached;

    cached = libbpf_num_possible_cpus();
    if (cached <= 0)
        cached = 0;
    return cached;
}

static __u32 aw_bpf_sum_u32_sat(__u32 a, __u32 b)
{
    __u64 sum = (__u64)a + (__u64)b;
    return sum > UINT32_MAX ? UINT32_MAX : (__u32)sum;
}

static int aw_bpf_open_map(const char *table)
{
    const char *path = NULL;
    char map_path[128];

    if (!table) {
        errno = EINVAL;
        return -1;
    }

    if (strcmp(table, "ipv4") == 0) {
        path = AW_BPF_IPV4_MAP_PATH;
    } else if (strcmp(table, "ipv6") == 0) {
        path = AW_BPF_IPV6_MAP_PATH;
    } else if (strcmp(table, "mac") == 0) {
        path = AW_BPF_MAC_MAP_PATH;
    } else if (strcmp(table, "sid") == 0) {
        path = AW_BPF_SID_MAP_PATH;
    } else {
        errno = EINVAL;
        return -1;
    }

    if (snprintf(map_path, sizeof(map_path), "%s", path) <= 0)
        return -1;
    return bpf_obj_get(map_path);
}

static bool aw_bpf_is_valid_mac_address(const char *mac)
{
    if (!mac)
        return false;

    size_t len = strlen(mac);
    if (len == 17) {
        for (size_t i = 0; i < len; i++) {
            if (i % 3 == 2) {
                if (mac[i] != ':')
                    return false;
            } else if (!isxdigit((unsigned char)mac[i])) {
                return false;
            }
        }
        return true;
    }

    if (len == 12) {
        for (size_t i = 0; i < len; i++) {
            if (!isxdigit((unsigned char)mac[i]))
                return false;
        }
        return true;
    }

    return false;
}

static void aw_bpf_parse_mac_address(struct aw_bpf_mac_addr *mac_addr, const char *value)
{
    unsigned int byte_value;
    const char *cursor = value;

    for (int i = 0; i < 6; i++) {
        byte_value = 0;
        sscanf(cursor, "%2x", &byte_value);
        mac_addr->h_addr[i] = (__u8)byte_value;
        cursor += (strlen(value) == 17) ? 3 : 2;
    }
}

static void aw_bpf_format_mac_address(const struct aw_bpf_mac_addr *mac, char *buf, size_t buf_len)
{
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac->h_addr[0], mac->h_addr[1], mac->h_addr[2],
             mac->h_addr[3], mac->h_addr[4], mac->h_addr[5]);
}

static size_t aw_bpf_collect_l7_protocols_from_payload(json_object *payload, struct aw_bpf_l7_proto *protocols, size_t max_protocols)
{
    json_object *j_protocols = NULL;

    if (!payload || !json_object_object_get_ex(payload, "protocols", &j_protocols) ||
        !json_object_is_type(j_protocols, json_type_array)) {
        return 0;
    }

    size_t protocol_count = (size_t)json_object_array_length(j_protocols);
    size_t stored_count = 0;
    for (size_t i = 0; i < protocol_count && stored_count < max_protocols; i++) {
        json_object *j_entry = json_object_array_get_idx(j_protocols, (int)i);
        json_object *j_id = NULL;
        json_object *j_sid = NULL;
        json_object *j_protocol = NULL;

        if (!j_entry ||
            !json_object_object_get_ex(j_entry, "id", &j_id) ||
            !json_object_object_get_ex(j_entry, "sid", &j_sid) ||
            !json_object_object_get_ex(j_entry, "protocol", &j_protocol)) {
            continue;
        }

        const char *proto_desc = json_object_get_string(j_protocol);
        if (!proto_desc)
            continue;

        protocols[stored_count].id = (__u32)json_object_get_int64(j_id);
        protocols[stored_count].sid = (__u32)json_object_get_int64(j_sid);
        strncpy(protocols[stored_count].proto_desc, proto_desc,
                sizeof(protocols[stored_count].proto_desc) - 1);
        protocols[stored_count].proto_desc[sizeof(protocols[stored_count].proto_desc) - 1] = '\0';
        stored_count++;
    }

    return stored_count;
}

static size_t aw_bpf_fetch_l7_protocols(struct aw_bpf_l7_proto *protocols, size_t max_protocols)
{
    char *out = NULL;
    int exit_code = 0;

    if (run_command_capture("aw-bpfctl l7 json 2>&1", &out, &exit_code) != 0) {
        free(out);
        return 0;
    }

    if (exit_code != 0 || !out || !*out) {
        free(out);
        return 0;
    }

    json_object *payload = json_tokener_parse(out);
    free(out);
    if (!payload) {
        return 0;
    }

    size_t count = aw_bpf_collect_l7_protocols_from_payload(payload, protocols, max_protocols);
    json_object_put(payload);
    return count;
}

static json_object *aw_bpf_fetch_l7_json_payload(void)
{
    char *out = NULL;
    int exit_code = 0;
    json_object *payload = NULL;

    if (run_command_capture("aw-bpfctl l7 json 2>&1", &out, &exit_code) != 0) {
        free(out);
        return NULL;
    }

    if (exit_code != 0 || !out || !*out) {
        free(out);
        return NULL;
    }

    payload = json_tokener_parse(out);
    free(out);
    return payload;
}

static const struct aw_bpf_l7_proto *aw_bpf_find_l7_proto_by_sid(const struct aw_bpf_l7_proto *protocols, size_t protocol_count, __u32 sid)
{
    if (!protocols) {
        return NULL;
    }

    for (size_t i = 0; i < protocol_count; i++) {
        if (protocols[i].sid == sid)
            return &protocols[i];
    }

    return NULL;
}

static bool aw_bpf_fetch_domains(struct aw_bpf_domain_list *domain_list)
{
    if (!domain_list) {
        return false;
    }

    memset(domain_list, 0, sizeof(*domain_list));

    int fd = open(AW_BPF_XDPI_DEVICE, O_RDWR);
    if (fd < 0) {
        return false;
    }

    domain_list->max_count = XDPI_DOMAIN_MAX;
    if (ioctl(fd, AW_BPF_XDPI_IOC_LIST, domain_list) != 0) {
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

static const struct domain_entry *aw_bpf_find_domain_by_sid(const struct aw_bpf_domain_list *domain_list, __u32 sid)
{
    if (!domain_list) {
        return NULL;
    }

    for (int i = 0; i < domain_list->count; i++) {
        const struct domain_entry *entry = &domain_list->domains[i];
        if (entry->used && entry->sid == sid) {
            return entry;
        }
    }

    return NULL;
}

static int aw_bpf_lookup_stats_agg_percpu(int map_fd, const void *key, struct traffic_stats *agg)
{
    int ncpus = aw_bpf_get_possible_cpus_cached();

    if (ncpus <= 0 || !agg)
        return -1;

    struct traffic_stats *percpu_vals = calloc(ncpus, sizeof(*percpu_vals));
    if (!percpu_vals)
        return -1;

    if (bpf_map_lookup_elem(map_fd, key, percpu_vals) < 0) {
        free(percpu_vals);
        return -1;
    }

    memset(agg, 0, sizeof(*agg));
    for (int i = 0; i < ncpus; i++) {
        agg->incoming.cur_s_bytes = aw_bpf_sum_u32_sat(agg->incoming.cur_s_bytes, percpu_vals[i].incoming.cur_s_bytes);
        agg->incoming.prev_s_bytes = aw_bpf_sum_u32_sat(agg->incoming.prev_s_bytes, percpu_vals[i].incoming.prev_s_bytes);
        agg->incoming.total_bytes += percpu_vals[i].incoming.total_bytes;
        agg->incoming.total_packets += percpu_vals[i].incoming.total_packets;
        if (percpu_vals[i].incoming.est_slot > agg->incoming.est_slot)
            agg->incoming.est_slot = percpu_vals[i].incoming.est_slot;

        agg->outgoing.cur_s_bytes = aw_bpf_sum_u32_sat(agg->outgoing.cur_s_bytes, percpu_vals[i].outgoing.cur_s_bytes);
        agg->outgoing.prev_s_bytes = aw_bpf_sum_u32_sat(agg->outgoing.prev_s_bytes, percpu_vals[i].outgoing.prev_s_bytes);
        agg->outgoing.total_bytes += percpu_vals[i].outgoing.total_bytes;
        agg->outgoing.total_packets += percpu_vals[i].outgoing.total_packets;
        if (percpu_vals[i].outgoing.est_slot > agg->outgoing.est_slot)
            agg->outgoing.est_slot = percpu_vals[i].outgoing.est_slot;

        if (percpu_vals[i].incoming_rate_limit.bps > agg->incoming_rate_limit.bps)
            agg->incoming_rate_limit.bps = percpu_vals[i].incoming_rate_limit.bps;
        if (percpu_vals[i].outgoing_rate_limit.bps > agg->outgoing_rate_limit.bps)
            agg->outgoing_rate_limit.bps = percpu_vals[i].outgoing_rate_limit.bps;
        if (percpu_vals[i].incoming_rate_limit.t_last > agg->incoming_rate_limit.t_last)
            agg->incoming_rate_limit.t_last = percpu_vals[i].incoming_rate_limit.t_last;
        if (percpu_vals[i].outgoing_rate_limit.t_last > agg->outgoing_rate_limit.t_last)
            agg->outgoing_rate_limit.t_last = percpu_vals[i].outgoing_rate_limit.t_last;
        if (percpu_vals[i].incoming_rate_limit.tokens > agg->incoming_rate_limit.tokens)
            agg->incoming_rate_limit.tokens = percpu_vals[i].incoming_rate_limit.tokens;
        if (percpu_vals[i].outgoing_rate_limit.tokens > agg->outgoing_rate_limit.tokens)
            agg->outgoing_rate_limit.tokens = percpu_vals[i].outgoing_rate_limit.tokens;
    }

    free(percpu_vals);
    return 0;
}

static int aw_bpf_update_rate_limits_percpu(int map_fd, const void *key, uint32_t downrate, uint32_t uprate, bool create_if_missing)
{
    int ncpus = aw_bpf_get_possible_cpus_cached();

    if (ncpus <= 0)
        return -1;

    struct traffic_stats *percpu_vals = calloc(ncpus, sizeof(*percpu_vals));
    if (!percpu_vals)
        return -1;

    if (!create_if_missing) {
        if (bpf_map_lookup_elem(map_fd, key, percpu_vals) < 0) {
            free(percpu_vals);
            return -1;
        }
    }

    for (int i = 0; i < ncpus; i++) {
        percpu_vals[i].incoming_rate_limit.bps = downrate;
        percpu_vals[i].outgoing_rate_limit.bps = uprate;
    }

    int ret = bpf_map_update_elem(map_fd, key, percpu_vals, create_if_missing ? BPF_NOEXIST : BPF_EXIST);
    free(percpu_vals);
    return ret;
}

static bool aw_bpf_get_global_qos_config(uint32_t *downrate, uint32_t *uprate)
{
    struct uci_context *ctx;
    struct uci_package *pkg = NULL;
    struct uci_element *e;

    if (!downrate || !uprate)
        return false;

    *downrate = 0;
    *uprate = 0;

    ctx = uci_alloc_context();
    if (!ctx)
        return false;

    if (uci_load(ctx, "wifidogx", &pkg) != UCI_OK) {
        uci_free_context(ctx);
        return false;
    }

    bool found = false;
    uci_foreach_element(&pkg->sections, e) {
        struct uci_section *s = uci_to_section(e);

        if (strcmp(s->type, "wifidogx") != 0)
            continue;

        const char *enable_qos = uci_lookup_option_string(ctx, s, "enable_qos");
        if (!enable_qos || strcmp(enable_qos, "1") != 0)
            continue;

        const char *qos_down = uci_lookup_option_string(ctx, s, "qos_down");
        const char *qos_up = uci_lookup_option_string(ctx, s, "qos_up");

        if (qos_down) {
            long val = strtol(qos_down, NULL, 10);
            if (val >= 0 && val <= (UINT32_MAX / (1024 * 1024)))
                *downrate = (uint32_t)(val * 1024 * 1024);
        }
        if (qos_up) {
            long val = strtol(qos_up, NULL, 10);
            if (val >= 0 && val <= (UINT32_MAX / (1024 * 1024)))
                *uprate = (uint32_t)(val * 1024 * 1024);
        }

        found = true;
        break;
    }

    if (pkg)
        uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return found;
}

static bool aw_bpf_parse_key(const char *table, const char *value, void *key_storage)
{
    if (strcmp(table, "ipv4") == 0) {
        return inet_pton(AF_INET, value, key_storage) == 1;
    }

    if (strcmp(table, "ipv6") == 0) {
        return inet_pton(AF_INET6, value, key_storage) == 1;
    }

    if (strcmp(table, "mac") == 0) {
        if (!aw_bpf_is_valid_mac_address(value))
            return false;
        aw_bpf_parse_mac_address((struct aw_bpf_mac_addr *)key_storage, value);
        return true;
    }

    if (strcmp(table, "sid") == 0) {
        char *end = NULL;
        unsigned long sid = strtoul(value, &end, 10);
        if (!value[0] || (end && *end != '\0'))
            return false;
        *((__u32 *)key_storage) = (__u32)sid;
        return true;
    }

    return false;
}

static bool aw_bpf_delete_all_entries(int map_fd)
{
    if (map_fd < 0)
        return false;

    bool success = true;
    bool has_key = false;
    __u8 key_buf[sizeof(struct in6_addr)] = {0};
    __u8 next_key_buf[sizeof(struct in6_addr)] = {0};

    while (bpf_map_get_next_key(map_fd, has_key ? key_buf : NULL, next_key_buf) == 0) {
        if (bpf_map_delete_elem(map_fd, next_key_buf) < 0)
            success = false;
        memcpy(key_buf, next_key_buf, sizeof(key_buf));
        has_key = true;
    }

    return success;
}

static struct json_object *aw_bpf_parse_stats_ipv4_json(__be32 ip, struct traffic_stats *stats)
{
    char ip_str[INET_ADDRSTRLEN];
    struct json_object *jobj = json_object_new_object();

    if (inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str)) == NULL) {
        json_object_put(jobj);
        return NULL;
    }

    json_object_object_add(jobj, "ip", json_object_new_string(ip_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();

    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object *aw_bpf_parse_stats_ipv6_json(struct in6_addr ip, struct traffic_stats *stats)
{
    char ip_str[INET6_ADDRSTRLEN];
    struct json_object *jobj = json_object_new_object();

    if (inet_ntop(AF_INET6, &ip, ip_str, sizeof(ip_str)) == NULL) {
        json_object_put(jobj);
        return NULL;
    }

    json_object_object_add(jobj, "ip", json_object_new_string(ip_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();

    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object *aw_bpf_parse_stats_mac_json(struct aw_bpf_mac_addr mac, struct traffic_stats *stats)
{
    char mac_str[18];
    struct json_object *jobj = json_object_new_object();

    aw_bpf_format_mac_address(&mac, mac_str, sizeof(mac_str));
    json_object_object_add(jobj, "mac", json_object_new_string(mac_str));

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();

    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object *aw_bpf_parse_stats_sid_json(__u32 sid, struct traffic_stats *stats,
                                                       const struct aw_bpf_l7_proto *protocols, size_t protocol_count,
                                                       const struct aw_bpf_domain_list *domain_list)
{
    const struct aw_bpf_l7_proto *l7_proto = aw_bpf_find_l7_proto_by_sid(protocols, protocol_count, sid);
    const struct domain_entry *domain = aw_bpf_find_domain_by_sid(domain_list, sid);
    struct json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "sid", json_object_new_int(sid));

    if (l7_proto) {
        json_object_object_add(jobj, "sid_type", json_object_new_string("L7"));
        json_object_object_add(jobj, "l7_proto_desc", json_object_new_string(l7_proto->proto_desc));
    } else if (domain) {
        json_object_object_add(jobj, "sid_type", json_object_new_string("Domain"));
        json_object_object_add(jobj, "domain", json_object_new_string(domain->domain));
    } else {
        json_object_object_add(jobj, "sid_type", json_object_new_string("Unknown"));
        json_object_object_add(jobj, "domain", json_object_new_string("unknown"));
    }

    struct json_object *incoming = json_object_new_object();
    struct json_object *outgoing = json_object_new_object();

    json_object_object_add(incoming, "total_bytes", json_object_new_int64(stats->incoming.total_bytes));
    json_object_object_add(incoming, "total_packets", json_object_new_int64(stats->incoming.total_packets));
    json_object_object_add(incoming, "rate", json_object_new_int(calc_rate_estimator(stats, true)));
    json_object_object_add(incoming, "incoming_rate_limit", json_object_new_uint64(stats->incoming_rate_limit.bps));
    json_object_object_add(jobj, "incoming", incoming);

    json_object_object_add(outgoing, "total_bytes", json_object_new_int64(stats->outgoing.total_bytes));
    json_object_object_add(outgoing, "total_packets", json_object_new_int64(stats->outgoing.total_packets));
    json_object_object_add(outgoing, "rate", json_object_new_int(calc_rate_estimator(stats, false)));
    json_object_object_add(outgoing, "outgoing_rate_limit", json_object_new_uint64(stats->outgoing_rate_limit.bps));
    json_object_object_add(jobj, "outgoing", outgoing);

    return jobj;
}

static struct json_object *aw_bpf_parse_stats_l7_json(void)
{
    return aw_bpf_fetch_l7_json_payload();
}

/* Validate requested BPF table name */
static int is_valid_bpf_table(const char *table)
{
    if (!table) return 0;
    if (strcmp(table, "ipv4") == 0) return 1;
    if (strcmp(table, "ipv6") == 0) return 1;
    if (strcmp(table, "mac") == 0) return 1;
    return 0;
}

/* Validate bpf_json table names. Query view additionally supports sid and l7. */
static int is_valid_bpf_json_table(const char *table)
{
    if (is_valid_bpf_table(table)) return 1;
    if (strcmp(table, "sid") == 0) return 1;
    if (strcmp(table, "l7") == 0) return 1;
    return 0;
}

/* Validate IPv4 address using inet_pton */
static int is_valid_ipv4_address(const char *addr)
{
    if (!addr) return 0;
    struct in_addr in;
    return inet_pton(AF_INET, addr, &in) == 1;
}

/* Validate IPv6 address using inet_pton */
static int is_valid_ipv6_address(const char *addr)
{
    if (!addr) return 0;
    struct in6_addr in6;
    return inet_pton(AF_INET6, addr, &in6) == 1;
}

/* Validate MAC address formats: aa:bb:cc:dd:ee:ff or aabbccddeeff */
static int is_valid_mac_address(const char *mac)
{
    if (!mac) return 0;
    size_t len = strlen(mac);
    if (len == 17) {
        int vals[6];
        if (sscanf(mac, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        if (sscanf(mac, "%x-%x-%x-%x-%x-%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
            return 1;
        }
        return 0;
    } else if (len == 12) {
        for (size_t i = 0; i < 12; i++) {
            if (!isxdigit((unsigned char)mac[i])) return 0;
        }
        return 1;
    }
    return 0;
}

/* Validate bitrates (bps). Accept 1 .. 10_000_000_000 (10 Gbps) */
static int is_valid_bitrate_long(long long v)
{
    if (v <= 0) return 0;
    if (v > 10000000000LL) return 0;
    return 1;
}

void handle_bpf_add_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");

    json_object *j_response = api_response_new("bpf_add_response");

    if (!j_table || !j_addr) {
        api_response_set_error(j_response, 1000, "Missing 'table' or 'address' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
       
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid MAC address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    int map_fd = aw_bpf_open_map(table);
    if (map_fd < 0) {
        api_response_set_error(j_response, 3001, "Failed to open BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    union {
        __be32 ipv4_key;
        struct aw_bpf_mac_addr mac_key;
        struct in6_addr ipv6_key;
    } key_storage = {0};

    if (!aw_bpf_parse_key(table, addr, &key_storage)) {
        close(map_fd);
        api_response_set_error(j_response, 1002, "Invalid address parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    struct traffic_stats existing_stats = {0};
    if (aw_bpf_lookup_stats_agg_percpu(map_fd, &key_storage, &existing_stats) == 0) {
        json_object *j_data = api_response_get_data(j_response);
        api_response_set_success(j_response, "Entry already exists");
        if (j_data) {
            json_object_object_add(j_data, "exit_code", json_object_new_int(0));
            json_object_object_add(j_data, "output", json_object_new_string("Entry already exists"));
        }
        send_json_response(transport, j_response);
        json_object_put(j_response);
        close(map_fd);
        return;
    }

    uint32_t downrate = 0;
    uint32_t uprate = 0;
    aw_bpf_get_global_qos_config(&downrate, &uprate);

    if (aw_bpf_update_rate_limits_percpu(map_fd, &key_storage, downrate, uprate, true) < 0) {
        close(map_fd);
        api_response_set_error(j_response, 3001, "Failed to update BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    json_object *j_data = api_response_get_data(j_response);
    api_response_set_success(j_response, "Entry added successfully");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        json_object_object_add(j_data, "output", json_object_new_string("Entry added successfully"));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
    close(map_fd);
}

void handle_bpf_del_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_addr = json_object_object_get(j_req, "address");
    json_object *j_response = api_response_new("bpf_del_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_addr) {
        api_response_set_error(j_response, 1000, "Missing 'table' or 'address' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
    const char *addr = json_object_get_string(j_addr);
    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(addr)) {
            api_response_set_error(j_response, 1002, "Invalid MAC address");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    int map_fd = aw_bpf_open_map(table);
    if (map_fd < 0) {
        api_response_set_error(j_response, 3001, "Failed to open BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    union {
        __be32 ipv4_key;
        struct aw_bpf_mac_addr mac_key;
        struct in6_addr ipv6_key;
    } key_storage = {0};

    if (!aw_bpf_parse_key(table, addr, &key_storage)) {
        close(map_fd);
        api_response_set_error(j_response, 1002, "Invalid address parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    if (bpf_map_delete_elem(map_fd, &key_storage) < 0) {
        close(map_fd);
        api_response_set_error(j_response, 3001, "Failed to delete BPF entry");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        json_object_object_add(j_data, "output", json_object_new_string("Deleted entry successfully"));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
    close(map_fd);
}

void handle_bpf_flush_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = api_response_new("bpf_flush_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table) {
        api_response_set_error(j_response, 1000, "Missing 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    int map_fd = aw_bpf_open_map(table);
    if (map_fd < 0) {
        api_response_set_error(j_response, 3001, "Failed to open BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    bool success = aw_bpf_delete_all_entries(map_fd);
    close(map_fd);
    if (!success) {
        api_response_set_error(j_response, 3001, "Failed to flush BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        json_object_object_add(j_data, "output", json_object_new_string("Flushed all entries in the map"));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
}

void handle_bpf_json_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_response = api_response_new("bpf_json_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table) {
        api_response_set_error(j_response, 1000, "Missing 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_json_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    json_object *payload = NULL;
    if (strcmp(table, "l7") == 0) {
        payload = aw_bpf_parse_stats_l7_json();
        if (!payload) {
            api_response_set_error(j_response, 3001, "Failed to query aw-bpfctl l7 json");
            if (j_data) {
                json_object_object_add(j_data, "exit_code", json_object_new_int(-1));
                json_object_object_add(j_data, "output", json_object_new_string(""));
            }
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else {
        int map_fd = aw_bpf_open_map(table);
        if (map_fd < 0) {
            api_response_set_error(j_response, 3001, "Failed to open BPF map");
            if (j_data) {
                json_object_object_add(j_data, "exit_code", json_object_new_int(-1));
                json_object_object_add(j_data, "output", json_object_new_string(""));
            }
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }

        payload = json_object_new_object();
        struct json_object *jentries = json_object_new_array();

        if (strcmp(table, "ipv4") == 0) {
            __be32 cur_key = 0, next_key = 0;
            struct traffic_stats stats = {0};

            while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
                if (aw_bpf_lookup_stats_agg_percpu(map_fd, &next_key, &stats) == 0) {
                    struct json_object *jentry = aw_bpf_parse_stats_ipv4_json(next_key, &stats);
                    if (jentry)
                        json_object_array_add(jentries, jentry);
                }
                cur_key = next_key;
            }
        } else if (strcmp(table, "mac") == 0) {
            struct aw_bpf_mac_addr cur_key;
            struct aw_bpf_mac_addr next_key;
            struct aw_bpf_mac_addr zero_key;
            struct traffic_stats stats = {0};

            memset(&cur_key, 0, sizeof(cur_key));
            memset(&next_key, 0, sizeof(next_key));
            memset(&zero_key, 0, sizeof(zero_key));

            while (bpf_map_get_next_key(map_fd,
                   (memcmp(&cur_key, &zero_key, sizeof(cur_key)) ? &cur_key : NULL),
                   &next_key) == 0) {
                if (aw_bpf_lookup_stats_agg_percpu(map_fd, &next_key, &stats) == 0) {
                    struct json_object *jentry = aw_bpf_parse_stats_mac_json(next_key, &stats);
                    if (jentry)
                        json_object_array_add(jentries, jentry);
                }
                cur_key = next_key;
            }
        } else if (strcmp(table, "sid") == 0) {
            struct aw_bpf_l7_proto l7_protocols[AW_BPF_PROTO_TRAITS_MAX_SIZE];
            size_t l7_protocol_count = aw_bpf_fetch_l7_protocols(l7_protocols, AW_BPF_PROTO_TRAITS_MAX_SIZE);
            struct aw_bpf_domain_list domain_list;
            bool have_domains = aw_bpf_fetch_domains(&domain_list);
            __u32 cur_key = 0, next_key = 0;
            struct traffic_stats stats = {0};

            while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
                if (aw_bpf_lookup_stats_agg_percpu(map_fd, &next_key, &stats) == 0) {
                    struct json_object *jentry = aw_bpf_parse_stats_sid_json(next_key, &stats,
                                                                             l7_protocols, l7_protocol_count,
                                                                             have_domains ? &domain_list : NULL);
                    if (jentry)
                        json_object_array_add(jentries, jentry);
                }
                cur_key = next_key;
            }
        } else if (strcmp(table, "ipv6") == 0) {
            struct in6_addr cur_key = {0}, next_key = {0};
            struct traffic_stats stats = {0};

            while (bpf_map_get_next_key(map_fd,
                   (memcmp(&cur_key, &(struct in6_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
                   &next_key) == 0) {
                if (aw_bpf_lookup_stats_agg_percpu(map_fd, &next_key, &stats) == 0) {
                    struct json_object *jentry = aw_bpf_parse_stats_ipv6_json(next_key, &stats);
                    if (jentry)
                        json_object_array_add(jentries, jentry);
                }
                cur_key = next_key;
            }
        }

        json_object_object_add(payload, "status", json_object_new_string("success"));
        json_object_object_add(payload, "type", json_object_new_string(table));
        json_object_object_add(payload, "data", jentries);
        close(map_fd);
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        if (payload) {
            json_object_object_add(j_data, "payload", payload);
        } else {
            json_object_object_add(j_data, "output", json_object_new_string(""));
        }
    } else if (payload) {
        json_object_put(payload);
    }

    send_json_response(transport, j_response);
    json_object_put(j_response);
}

void handle_bpf_update_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_target = json_object_object_get(j_req, "target");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = api_response_new("bpf_update_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_target || !j_down || !j_up) {
        api_response_set_error(j_response, 1000, "Missing required parameters: 'table','target','downrate','uprate'");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }
    const char *target = json_object_get_string(j_target);

    if (strcmp(table, "ipv4") == 0) {
        if (!is_valid_ipv4_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid IPv4 target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "ipv6") == 0) {
        if (!is_valid_ipv6_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid IPv6 target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    } else if (strcmp(table, "mac") == 0) {
        if (!is_valid_mac_address(target)) {
            api_response_set_error(j_response, 1002, "Invalid MAC target");
            send_json_response(transport, j_response);
            json_object_put(j_response);
            return;
        }
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        api_response_set_error(j_response, 1002, "Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    int map_fd = aw_bpf_open_map(table);
    if (map_fd < 0) {
        api_response_set_error(j_response, 3001, "Failed to open BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    union {
        __be32 ipv4_key;
        struct aw_bpf_mac_addr mac_key;
        struct in6_addr ipv6_key;
        __u32 sid_key;
    } key_storage = {0};

    if (!aw_bpf_parse_key(table, target, &key_storage)) {
        close(map_fd);
        api_response_set_error(j_response, 1002, "Invalid target parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    if (aw_bpf_update_rate_limits_percpu(map_fd, &key_storage, (uint32_t)down, (uint32_t)up, true) < 0) {
        close(map_fd);
        api_response_set_error(j_response, 3001, "Failed to update BPF entry");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        json_object_object_add(j_data, "output", json_object_new_string("Entry updated successfully"));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
    close(map_fd);
}

void handle_bpf_update_all_request(json_object *j_req, api_transport_context_t *transport)
{
    json_object *j_table = json_object_object_get(j_req, "table");
    json_object *j_down = json_object_object_get(j_req, "downrate");
    json_object *j_up = json_object_object_get(j_req, "uprate");
    json_object *j_response = api_response_new("bpf_update_all_response");
    json_object *j_data = api_response_get_data(j_response);

    if (!j_table || !j_down || !j_up) {
        api_response_set_error(j_response, 1000, "Missing required parameters: 'table','downrate','uprate'");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    const char *table = json_object_get_string(j_table);
    if (!is_valid_bpf_table(table)) {
        api_response_set_error(j_response, 1002, "Invalid 'table' parameter");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    long long down = json_object_get_int64(j_down);
    long long up = json_object_get_int64(j_up);
    if (!is_valid_bitrate_long(down) || !is_valid_bitrate_long(up)) {
        api_response_set_error(j_response, 1002, "Invalid 'downrate' or 'uprate' (must be 1..10_000_000_000)");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    int map_fd = aw_bpf_open_map(table);
    if (map_fd < 0) {
        api_response_set_error(j_response, 3001, "Failed to open BPF map");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    bool success = true;
    if (strcmp(table, "ipv4") == 0) {
        __be32 cur_key = 0, next_key = 0;

        while (bpf_map_get_next_key(map_fd, cur_key ? &cur_key : NULL, &next_key) == 0) {
            if (aw_bpf_update_rate_limits_percpu(map_fd, &next_key, (uint32_t)down, (uint32_t)up, false) < 0) {
                success = false;
                break;
            }
            cur_key = next_key;
        }
    } else if (strcmp(table, "mac") == 0) {
        struct aw_bpf_mac_addr cur_key;
        struct aw_bpf_mac_addr next_key;
        struct aw_bpf_mac_addr zero_key;

        memset(&cur_key, 0, sizeof(cur_key));
        memset(&next_key, 0, sizeof(next_key));
        memset(&zero_key, 0, sizeof(zero_key));

        while (bpf_map_get_next_key(map_fd,
               (memcmp(&cur_key, &zero_key, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (aw_bpf_update_rate_limits_percpu(map_fd, &next_key, (uint32_t)down, (uint32_t)up, false) < 0) {
                success = false;
                break;
            }
            cur_key = next_key;
        }
    } else {
        struct in6_addr cur_key = {0}, next_key = {0};

        while (bpf_map_get_next_key(map_fd,
               (memcmp(&cur_key, &(struct in6_addr){0}, sizeof(cur_key)) ? &cur_key : NULL),
               &next_key) == 0) {
            if (aw_bpf_update_rate_limits_percpu(map_fd, &next_key, (uint32_t)down, (uint32_t)up, false) < 0) {
                success = false;
                break;
            }
            cur_key = next_key;
        }
    }

    close(map_fd);
    if (!success) {
        api_response_set_error(j_response, 3001, "Failed to update BPF entries");
        send_json_response(transport, j_response);
        json_object_put(j_response);
        return;
    }

    api_response_set_success(j_response, "OK");
    if (j_data) {
        json_object_object_add(j_data, "exit_code", json_object_new_int(0));
        json_object_object_add(j_data, "output", json_object_new_string("Updated all entries successfully"));
    }
    send_json_response(transport, j_response);
    json_object_put(j_response);
}
