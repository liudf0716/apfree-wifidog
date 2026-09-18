// SPDX-License-Identifier: GPL-3.0-only
/*
 * bpf_qos.c - Apply/remove per-IP QoS entries for authenticated clients
 */

#include "common.h"
#include "debug.h"
#include "bpf_qos.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBBPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "aw_bpf_compat.h"

#define AW_BPF_MAP_DIR "/sys/fs/bpf/tc/globals"
#define AW_BPF_MAP_DIR_ALT "/sys/fs/bpf/aw"

#define AW_BPF_IPV4_MAP_PATH AW_BPF_MAP_DIR "/ipv4_map"
#define AW_BPF_IPV4_MAP_PATH_ALT AW_BPF_MAP_DIR_ALT "/ipv4_map"
#define AW_BPF_IPV6_MAP_PATH AW_BPF_MAP_DIR "/ipv6_map"
#define AW_BPF_IPV6_MAP_PATH_ALT AW_BPF_MAP_DIR_ALT "/ipv6_map"

#define AW_BPF_IPV4_QOS_PATH AW_BPF_MAP_DIR "/ipv4_qos_map"
#define AW_BPF_IPV4_QOS_PATH_ALT AW_BPF_MAP_DIR_ALT "/ipv4_qos_map"
#define AW_BPF_IPV6_QOS_PATH AW_BPF_MAP_DIR "/ipv6_qos_map"
#define AW_BPF_IPV6_QOS_PATH_ALT AW_BPF_MAP_DIR_ALT "/ipv6_qos_map"

#define AW_BPF_ROUTER_IP_PATH AW_BPF_MAP_DIR "/router_ip_map"
#define AW_BPF_ROUTER_IP_PATH_ALT AW_BPF_MAP_DIR_ALT "/router_ip_map"

static int aw_bpf_open_map(const char *path1, const char *path2)
{
	int fd = bpf_obj_get(path1);
	if (fd < 0 && path2)
		fd = bpf_obj_get(path2);
	return fd;
}

static int aw_bpf_qos_ncpus(void)
{
	static int cached = -1;

	if (cached > 0)
		return cached;

	cached = libbpf_num_possible_cpus();
	if (cached <= 0)
		cached = 0;
	return cached;
}

static int is_usable_ip(const char *ip)
{
	if (!ip || !ip[0])
		return 0;
	if (strcmp(ip, "N/A") == 0 || strcmp(ip, "n/a") == 0)
		return 0;
	if (strcmp(ip, "null") == 0 || strcmp(ip, "(null)") == 0)
		return 0;
	return 1;
}

/**
 * Upsert rate limits on a per-CPU traffic_stats map entry.
 * If entry exists: update only bps fields (preserve counters/tokens).
 * If missing: create zeroed stats with given bps.
 */
static int aw_bpf_qos_upsert_percpu(int map_fd, const void *key,
				   uint32_t downrate_bps, uint32_t uprate_bps)
{
	int ncpus = aw_bpf_qos_ncpus();
	struct traffic_stats *percpu_vals;
	int exists;
	int i;
	int ret;

	if (ncpus <= 0) {
		errno = ENOSYS;
		return -1;
	}

	percpu_vals = calloc((size_t)ncpus, sizeof(*percpu_vals));
	if (!percpu_vals) {
		errno = ENOMEM;
		return -1;
	}

	exists = (bpf_map_lookup_elem(map_fd, key, percpu_vals) == 0);
	if (!exists) {
		memset(percpu_vals, 0, (size_t)ncpus * sizeof(*percpu_vals));
	}

	for (i = 0; i < ncpus; i++) {
		/* keep counters/tokens when updating existing entry */
		percpu_vals[i].incoming_rate_limit.bps = downrate_bps;
		percpu_vals[i].outgoing_rate_limit.bps = uprate_bps;
	}

	ret = bpf_map_update_elem(map_fd, key, percpu_vals, BPF_ANY);
	free(percpu_vals);
	return ret;
}

static int aw_bpf_qos_apply_one(int family, const char *ip,
			       uint32_t downrate_bps, uint32_t uprate_bps)
{
	int ret = 0;
	union {
		__be32 v4;
		struct in6_addr v6;
	} key;

	memset(&key, 0, sizeof(key));

	if (family == AF_INET) {
		if (inet_pton(AF_INET, ip, &key.v4) != 1) {
			debug(LOG_WARNING, "bpf_qos: invalid IPv4 %s", ip);
			errno = EINVAL;
			return -1;
		}
	} else {
		if (inet_pton(AF_INET6, ip, &key.v6) != 1) {
			debug(LOG_WARNING, "bpf_qos: invalid IPv6 %s", ip);
			errno = EINVAL;
			return -1;
		}
	}

	const char *qos_path = (family == AF_INET) ? AW_BPF_IPV4_QOS_PATH : AW_BPF_IPV6_QOS_PATH;
	const char *qos_alt  = (family == AF_INET) ? AW_BPF_IPV4_QOS_PATH_ALT : AW_BPF_IPV6_QOS_PATH_ALT;
	const char *stats_path = (family == AF_INET) ? AW_BPF_IPV4_MAP_PATH : AW_BPF_IPV6_MAP_PATH;
	const char *stats_alt  = (family == AF_INET) ? AW_BPF_IPV4_MAP_PATH_ALT : AW_BPF_IPV6_MAP_PATH_ALT;

	int qos_fd = aw_bpf_open_map(qos_path, qos_alt);
	bool used_qos_map = false;

	if (qos_fd >= 0) {
		if (downrate_bps > 0 || uprate_bps > 0) {
			struct qos_limit_cfg qcfg;
			memset(&qcfg, 0, sizeof(qcfg));
			bpf_map_lookup_elem(qos_fd, &key, &qcfg);
			qcfg.incoming.bps = downrate_bps;
			qcfg.outgoing.bps = uprate_bps;
			if (bpf_map_update_elem(qos_fd, &key, &qcfg, BPF_ANY) < 0) {
				debug(LOG_WARNING, "bpf_qos: update non-percpu qos map failed: %s", strerror(errno));
			} else {
				used_qos_map = true;
			}
		} else {
			bpf_map_delete_elem(qos_fd, &key);
			used_qos_map = true;
		}
		close(qos_fd);
	}

	/* Also ensure client is in percpu traffic_stats map for packet accounting */
	int stats_fd = aw_bpf_open_map(stats_path, stats_alt);
	if (stats_fd >= 0) {
		uint32_t percpu_down = used_qos_map ? 0 : downrate_bps;
		uint32_t percpu_up   = used_qos_map ? 0 : uprate_bps;
		ret = aw_bpf_qos_upsert_percpu(stats_fd, &key, percpu_down, percpu_up);
		close(stats_fd);
	} else if (!used_qos_map) {
		debug(LOG_WARNING, "bpf_qos: open stats map failed: %s", strerror(errno));
		ret = -1;
	}

	if (ret < 0) {
		debug(LOG_WARNING,
		      "bpf_qos: upsert %s %s down=%u up=%u failed: %s",
		      family == AF_INET ? "ipv4" : "ipv6", ip, downrate_bps,
		      uprate_bps, strerror(errno));
	} else {
		debug(LOG_INFO,
		      "bpf_qos: apply %s %s downrate_bps=%u uprate_bps=%u (mode: %s)",
		      family == AF_INET ? "ipv4" : "ipv6", ip, downrate_bps,
		      uprate_bps, used_qos_map ? "non-percpu-global" : "percpu-fallback");
	}

	return ret;
}

static int aw_bpf_qos_remove_one(int family, const char *ip)
{
	int ret = 0;
	union {
		__be32 v4;
		struct in6_addr v6;
	} key;

	memset(&key, 0, sizeof(key));

	if (family == AF_INET) {
		if (inet_pton(AF_INET, ip, &key.v4) != 1) {
			errno = EINVAL;
			return -1;
		}
	} else {
		if (inet_pton(AF_INET6, ip, &key.v6) != 1) {
			errno = EINVAL;
			return -1;
		}
	}

	const char *qos_path = (family == AF_INET) ? AW_BPF_IPV4_QOS_PATH : AW_BPF_IPV6_QOS_PATH;
	const char *qos_alt  = (family == AF_INET) ? AW_BPF_IPV4_QOS_PATH_ALT : AW_BPF_IPV6_QOS_PATH_ALT;
	const char *stats_path = (family == AF_INET) ? AW_BPF_IPV4_MAP_PATH : AW_BPF_IPV6_MAP_PATH;
	const char *stats_alt  = (family == AF_INET) ? AW_BPF_IPV4_MAP_PATH_ALT : AW_BPF_IPV6_MAP_PATH_ALT;

	int qos_fd = aw_bpf_open_map(qos_path, qos_alt);
	if (qos_fd >= 0) {
		bpf_map_delete_elem(qos_fd, &key);
		close(qos_fd);
	}

	int stats_fd = aw_bpf_open_map(stats_path, stats_alt);
	if (stats_fd >= 0) {
		ret = bpf_map_delete_elem(stats_fd, &key);
		if (ret < 0 && errno == ENOENT)
			ret = 0;
		close(stats_fd);
	}

	debug(LOG_INFO, "bpf_qos: removed %s %s",
	      family == AF_INET ? "ipv4" : "ipv6", ip);
	return ret;
}

int aw_bpf_qos_apply_client(const char *ipv4, const char *ipv6,
			    uint32_t downrate_bps, uint32_t uprate_bps)
{
	int rc = 0;
	int r;

	if (is_usable_ip(ipv4)) {
		r = aw_bpf_qos_apply_one(AF_INET, ipv4, downrate_bps, uprate_bps);
		if (r < 0)
			rc = -1;
	}
	if (is_usable_ip(ipv6)) {
		r = aw_bpf_qos_apply_one(AF_INET6, ipv6, downrate_bps, uprate_bps);
		if (r < 0)
			rc = -1;
	}
	return rc;
}

int aw_bpf_qos_remove_client(const char *ipv4, const char *ipv6)
{
	int rc = 0;
	int r;

	if (is_usable_ip(ipv4)) {
		r = aw_bpf_qos_remove_one(AF_INET, ipv4);
		if (r < 0)
			rc = -1;
	}
	if (is_usable_ip(ipv6)) {
		r = aw_bpf_qos_remove_one(AF_INET6, ipv6);
		if (r < 0)
			rc = -1;
	}
	return rc;
}

int aw_bpf_router_ip_sync(const char *lan_ip, const char *wan_ip)
{
	if (!lan_ip && !wan_ip)
		return 0;

	int map_fd = aw_bpf_open_map(AW_BPF_ROUTER_IP_PATH, AW_BPF_ROUTER_IP_PATH_ALT);
	if (map_fd < 0)
		return -1;

	uint32_t key = 0;
	struct router_ip_cfg cfg;
	memset(&cfg, 0, sizeof(cfg));
	bpf_map_lookup_elem(map_fd, &key, &cfg);

	if (lan_ip && inet_pton(AF_INET, lan_ip, &cfg.lan_ip) != 1)
		debug(LOG_WARNING, "bpf_qos: invalid router LAN IP %s", lan_ip);
	if (wan_ip && inet_pton(AF_INET, wan_ip, &cfg.wan_ip) != 1)
		debug(LOG_WARNING, "bpf_qos: invalid router WAN IP %s", wan_ip);

	int ret = bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY);
	close(map_fd);
	return ret;
}

#else /* !HAVE_LIBBPF */

int aw_bpf_qos_apply_client(const char *ipv4, const char *ipv6,
			    uint32_t downrate_bps, uint32_t uprate_bps)
{
	(void)ipv4;
	(void)ipv6;
	(void)downrate_bps;
	(void)uprate_bps;
	errno = ENOSYS;
	debug(LOG_DEBUG, "bpf_qos: libbpf unavailable, apply stub");
	return -1;
}

int aw_bpf_qos_remove_client(const char *ipv4, const char *ipv6)
{
	(void)ipv4;
	(void)ipv6;
	errno = ENOSYS;
	debug(LOG_DEBUG, "bpf_qos: libbpf unavailable, remove stub");
	return -1;
}

int aw_bpf_router_ip_sync(const char *lan_ip, const char *wan_ip)
{
	(void)lan_ip;
	(void)wan_ip;
	return 0;
}

#endif /* HAVE_LIBBPF */
