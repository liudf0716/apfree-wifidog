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
#define AW_BPF_IPV4_MAP_PATH AW_BPF_MAP_DIR "/ipv4_map"
#define AW_BPF_IPV6_MAP_PATH AW_BPF_MAP_DIR "/ipv6_map"

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

static int aw_bpf_qos_apply_one(const char *map_path, int family, const char *ip,
			       uint32_t downrate_bps, uint32_t uprate_bps)
{
	int map_fd;
	int ret;
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

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		debug(LOG_WARNING, "bpf_qos: open %s failed: %s", map_path,
		      strerror(errno));
		return -1;
	}

	ret = aw_bpf_qos_upsert_percpu(map_fd, &key, downrate_bps, uprate_bps);
	if (ret < 0) {
		debug(LOG_WARNING,
		      "bpf_qos: upsert %s %s down=%u up=%u failed: %s",
		      family == AF_INET ? "ipv4" : "ipv6", ip, downrate_bps,
		      uprate_bps, strerror(errno));
	} else {
		debug(LOG_INFO,
		      "bpf_qos: apply %s %s downrate_bps=%u uprate_bps=%u",
		      family == AF_INET ? "ipv4" : "ipv6", ip, downrate_bps,
		      uprate_bps);
	}

	close(map_fd);
	return ret;
}

static int aw_bpf_qos_remove_one(const char *map_path, int family, const char *ip)
{
	int map_fd;
	int ret;
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

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		/* Map not pinned: treat as already cleaned */
		if (errno == ENOENT)
			return 0;
		debug(LOG_WARNING, "bpf_qos: open %s for delete failed: %s",
		      map_path, strerror(errno));
		return -1;
	}

	ret = bpf_map_delete_elem(map_fd, &key);
	if (ret < 0) {
		if (errno == ENOENT) {
			ret = 0; /* already gone */
		} else {
			debug(LOG_WARNING, "bpf_qos: delete %s %s failed: %s",
			      family == AF_INET ? "ipv4" : "ipv6", ip,
			      strerror(errno));
		}
	} else {
		debug(LOG_INFO, "bpf_qos: removed %s %s",
		      family == AF_INET ? "ipv4" : "ipv6", ip);
	}

	close(map_fd);
	return ret;
}

int aw_bpf_qos_apply_client(const char *ipv4, const char *ipv6,
			    uint32_t downrate_bps, uint32_t uprate_bps)
{
	int rc = 0;
	int r;

	if (is_usable_ip(ipv4)) {
		r = aw_bpf_qos_apply_one(AW_BPF_IPV4_MAP_PATH, AF_INET, ipv4,
					 downrate_bps, uprate_bps);
		if (r < 0)
			rc = -1;
	}
	if (is_usable_ip(ipv6)) {
		r = aw_bpf_qos_apply_one(AW_BPF_IPV6_MAP_PATH, AF_INET6, ipv6,
					 downrate_bps, uprate_bps);
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
		r = aw_bpf_qos_remove_one(AW_BPF_IPV4_MAP_PATH, AF_INET, ipv4);
		if (r < 0)
			rc = -1;
	}
	if (is_usable_ip(ipv6)) {
		r = aw_bpf_qos_remove_one(AW_BPF_IPV6_MAP_PATH, AF_INET6, ipv6);
		if (r < 0)
			rc = -1;
	}
	return rc;
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

#endif /* HAVE_LIBBPF */
