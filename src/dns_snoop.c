// SPDX-License-Identifier: GPL-3.0-only
/*
 * Portal DNS consumer: reads dns_ringbuf_portal produced by aw-bpf XDP.
 * Only fills inet wifidogx wildcard trust sets. Does not use inet awbpf.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#ifdef HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#else
typedef struct ring_buffer ring_buffer;
static inline int bpf_obj_get(const char *path) { (void)path; errno = ENOENT; return -1; }
static inline struct ring_buffer *ring_buffer__new(int map_fd, void *cb, void *ctx, void *opts)
{ (void)map_fd; (void)cb; (void)ctx; (void)opts; return NULL; }
static inline int ring_buffer__poll(struct ring_buffer *rb, int timeout_ms)
{ (void)rb; (void)timeout_ms; return -ENOSYS; }
static inline void ring_buffer__free(struct ring_buffer *rb) { (void)rb; }
#endif

#include "common.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "dns_snoop.h"
#include "wd_util.h"
#include "aw_bpf_compat.h"

#include <netdb.h>
#include <pthread.h>

#define CAPTIVE_FAKE_IP "1.1.1.1"

/* Domains answered by aw-bpf captive_domain_map with a synthetic IP until
 * dns_snoop learns the real address from an upstream response. */
static const char *captive_seed_domains[] = {
	"captive.apple.com",
	"www.apple.com",
	"connect.rom.miui.com",
	"www.msftconnecttest.com",
	"www.gstatic.com",
	"www.gstatic.cn",
	"www.google.cn",
	"www.qualcomm.cn",
	"conn1.oppomobile.com",
	"conn2.oppomobile.com",
	"connectivitycheck.platform.hicloud.com",
	"connectivitycheck.cbg-app.huawei.com",
	"connectivitycheck.gstatic.com",
	"cp.cloudflare.com",
	"wifi.vivo.com.cn",
	"connectivitycheck.platform.hihonorcloud.com",
	"detectportal.firefox.com",
	"services.googleapis.cn",
	"g.cn",
	"developer.android.google.cn",
	"source.android.google.cn",
	"www.google-analytics.com",
	"clients1.google.com",
	"clients2.google.com",
	"clients3.google.com",
	"clients4.google.com",
	"clients5.google.com",
	"goo.gl",
	"google.cn",
	"google.com.hk",
	"google.com.tw",
	"google.com",
	"googleapis.com",
	"play.googleapis.com",
	"www.g.cn",
	"www.google.com.hk",
	"www.google.com.tw",
	"www.google.com",
	"www.googleapis.com",
	"www.youtube.com",
	"yt.be",
};

static void *
thread_preload_captive_domains(void *arg)
{
	(void)arg;
	/* Allow network and dns_portal_buf to settle before preloading */
	sleep(2);
	for (size_t i = 0; i < sizeof(captive_seed_domains) / sizeof(captive_seed_domains[0]); i++) {
		struct addrinfo hints, *res = NULL;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		getaddrinfo(captive_seed_domains[i], NULL, &hints, &res);
		if (res) {
			freeaddrinfo(res);
		}
	}
	return NULL;
}

static void
seed_captive_domain_map(void)
{
	if (!is_openwrt_platform() || is_portal_auth_disabled()) {
		return;
	}

	int seeded = 0;
	for (size_t i = 0; i < sizeof(captive_seed_domains) / sizeof(captive_seed_domains[0]); i++) {
		if (captive_domain_map_set(captive_seed_domains[i], CAPTIVE_FAKE_IP) == 0)
			seeded++;
	}

	if (seeded > 0) {
		debug(LOG_INFO, "Seeded %d captive domains into aw-bpf captive_domain_map", seeded);
		pthread_t tid;
		if (pthread_create(&tid, NULL, thread_preload_captive_domains, NULL) == 0) {
			pthread_detach(tid);
		}
	} else {
		debug(LOG_DEBUG, "captive_domain_map not ready yet; will learn if aw-bpf loads later");
	}
}

#ifndef MAX_DNS_PAYLOAD_LEN
#define MAX_DNS_PAYLOAD_LEN 512
#endif

#define MAX_DNS_NAME 256
#define DNS_PORTAL_MAP_PATH         "/sys/fs/bpf/tc/globals/dns_ringbuf_portal"
#define DNS_PORTAL_MAP_PATH_ALT     "/sys/fs/bpf/aw/dns_ringbuf_portal"
#define DNS_PORTAL_MAP_PATH_XDP     "/sys/fs/bpf/xdp/globals/dns_ringbuf_portal"
#define DNS_PORTAL_BUF_MAP_PATH     "/sys/fs/bpf/tc/globals/dns_portal_buf"
#define DNS_PORTAL_BUF_MAP_PATH_ALT "/sys/fs/bpf/aw/dns_portal_buf"
#define DNS_PORTAL_BUF_MAP_PATH_XDP "/sys/fs/bpf/xdp/globals/dns_portal_buf"

/* captive_domain_map: pinned by aw-bpf tc/ingress, must mirror the
 * definition in aw_bpf.c */
#define CAPTIVE_DOMAIN_KEY_LEN  64

#define CAPTIVE_DOMAIN_MAP_PATH     "/sys/fs/bpf/tc/globals/captive_domain_map"
#define CAPTIVE_DOMAIN_MAP_PATH_ALT "/sys/fs/bpf/aw/captive_domain_map"
#define CAPTIVE_DOMAIN_MAP_PATH_XDP "/sys/fs/bpf/xdp/globals/captive_domain_map"

struct captive_domain_value {
	uint32_t ip;      /* network order */
	uint8_t learned;  /* 1 = real IP learned from upstream response */
	uint8_t pad[3];
};

#ifdef HAVE_LIBBPF
static int open_captive_map(void)
{
	int fd = bpf_obj_get(CAPTIVE_DOMAIN_MAP_PATH);
	if (fd >= 0)
		return fd;
	fd = bpf_obj_get(CAPTIVE_DOMAIN_MAP_PATH_ALT);
	if (fd >= 0)
		return fd;
	return bpf_obj_get(CAPTIVE_DOMAIN_MAP_PATH_XDP);
}

/* Map keys hold the qname in DNS wire format (label-encoded, lowercase,
 * zero padded) — must match what the BPF program builds from queries. */
static int domain_to_wire_key(const char *domain, char *key, size_t keylen)
{
	memset(key, 0, keylen);
	size_t pos = 0;
	const char *p = domain;

	while (*p) {
		const char *dot = strchr(p, '.');
		size_t len = dot ? (size_t)(dot - p) : strlen(p);
		if (len == 0 || len > 63 || pos + 1 + len >= keylen)
			return -1;
		key[pos++] = (char)len;
		for (size_t i = 0; i < len; i++) {
			char c = p[i];
			key[pos++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
		}
		p = dot ? dot + 1 : p + len;
	}
	return pos ? 0 : -1;
}

static int captive_map_fd = -1;

static int get_captive_map_fd(void)
{
	if (captive_map_fd < 0)
		captive_map_fd = open_captive_map();
	return captive_map_fd;
}

/* flags: BPF_ANY to seed an entry, BPF_EXIST to learn real IPs only for
 * domains already in the map */
static int captive_domain_map_update(const char *domain, const char *ip,
				     uint8_t learned, uint64_t flags)
{
	int fd = get_captive_map_fd();

	if (fd < 0)
		return -1;

	struct in_addr addr;

	if (inet_pton(AF_INET, ip, &addr) != 1)
		return -1;

	char key[CAPTIVE_DOMAIN_KEY_LEN];
	if (domain_to_wire_key(domain, key, sizeof(key)))
		return -1;

	struct captive_domain_value val;
	memset(&val, 0, sizeof(val));
	val.ip = addr.s_addr;
	val.learned = learned;

	int ret = bpf_map_update_elem(fd, key, &val, flags);
	if (ret < 0 && errno == EBADF) {
		/* stale fd after aw-bpf reload recreated the map */
		close(fd);
		captive_map_fd = -1;
		fd = get_captive_map_fd();
		if (fd < 0)
			return -1;
		ret = bpf_map_update_elem(fd, key, &val, flags);
	}
	return ret;
}
#endif

int captive_domain_map_set(const char *domain, const char *ip)
{
#ifdef HAVE_LIBBPF
	return captive_domain_map_update(domain, ip, 0, BPF_ANY);
#else
	(void)domain; (void)ip;
	return -1;
#endif
}

int captive_domain_map_learn(const char *domain, const char *ip)
{
#ifdef HAVE_LIBBPF
	return captive_domain_map_update(domain, ip, 1, BPF_EXIST);
#else
	(void)domain; (void)ip;
	return -1;
#endif
}

struct raw_dns_data {
	uint32_t pkt_len;
	uint8_t ip_version;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t timestamp;
	union {
		uint32_t saddr_v4;
		uint8_t saddr_v6[16];
	} src_ip;
	union {
		uint32_t daddr_v4;
		uint8_t daddr_v6[16];
	} dst_ip;
	unsigned char dns_payload[MAX_DNS_PAYLOAD_LEN];
} __attribute__((packed));

static int parse_dns_name(const unsigned char *payload, int payload_len, int offset,
			  char *name, int max_len)
{
	int pos = offset, name_pos = 0, jumped = 0, jumps = 0;
	int skip_only = (name == NULL || max_len <= 0);
	int completed = 0;

	if (!payload || offset < 0 || offset >= payload_len)
		return -1;
	if (!skip_only)
		name[0] = '\0';

	while (pos < payload_len && jumps < 5) {
		int len = payload[pos];
		if (len == 0) {
			pos++;
			completed = 1;
			break;
		}
		if ((len & 0xC0) == 0xC0) {
			if (pos + 1 >= payload_len)
				return -1;
			if (!jumped)
				jumped = pos + 2;
			int new_pos = ((len & 0x3F) << 8) | payload[pos + 1];
			if (new_pos < 0 || new_pos >= payload_len || new_pos >= pos)
				return -1;
			pos = new_pos;
			jumps++;
			continue;
		}
		if (len > 63 || pos + len + 1 > payload_len)
			return -1;
		if (!skip_only) {
			if (name_pos > 0 && name_pos < max_len - 1)
				name[name_pos++] = '.';
			for (int i = 0; i < len && name_pos < max_len - 1; i++) {
				unsigned char c = payload[pos + 1 + i];
				name[name_pos++] = (c >= 32 && c <= 126) ? (char)tolower(c) : '?';
			}
		}
		pos += len + 1;
	}

	if (!completed)
		return -1;

	if (!skip_only && max_len > 0)
		name[name_pos] = '\0';
	return jumped ? jumped : pos;
}

static void handle_dns_payload(const unsigned char *payload, int payload_len)
{
	unsigned qdcount, ancount;
	int offset, i;
	char qname[MAX_DNS_NAME];

	if (payload_len < 12)
		return;
	{
		uint16_t flags, qd, an;
		memcpy(&flags, payload + 2, 2);
		memcpy(&qd, payload + 4, 2);
		memcpy(&an, payload + 6, 2);
		if ((ntohs(flags) & 0x8000) == 0)
			return;
		qdcount = ntohs(qd);
		ancount = ntohs(an);
	}
	if (qdcount != 1 || ancount == 0)
		return;

	offset = parse_dns_name(payload, payload_len, 12, qname, sizeof(qname));
	if (offset < 0 || offset + 4 > payload_len)
		return;
	offset += 4;

	for (i = 0; i < (int)ancount && offset + 10 <= payload_len; i++) {
		uint16_t type, rdlength;
		int name_end = parse_dns_name(payload, payload_len, offset, NULL, 0);
		if (name_end < 0)
			return;
		offset = name_end;
		if (offset + 10 > payload_len)
			return;
		memcpy(&type, payload + offset, 2);
		memcpy(&rdlength, payload + offset + 8, 2);
		type = ntohs(type);
		rdlength = ntohs(rdlength);
		offset += 10;
		if (offset + rdlength > payload_len)
			return;
		if (type == 1 && rdlength == 4) {
			char ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, payload + offset, ip, sizeof(ip));
			if (add_wildcard_resolved_ip(qname, ip))
				fw_add_wildcard_resolved_ip(ip);
			/* refresh the captive fast-answer map with the real IP */
			captive_domain_map_learn(qname, ip);
		} else if (type == 28 && rdlength == 16) {
			char ip[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, payload + offset, ip, sizeof(ip));
			if (add_wildcard_resolved_ip(qname, ip))
				fw_add_wildcard_resolved_ip(ip);
		}
		offset += rdlength;
	}
}

static int handle_portal_dns_event(void *ctx, void *data, size_t data_sz)
{
	const struct raw_dns_data *dns_data = data;
	(void)ctx;

	if (!data || data_sz < sizeof(*dns_data))
		return 0;
	if (dns_data->pkt_len == 0 || dns_data->pkt_len > MAX_DNS_PAYLOAD_LEN)
		return 0;
	if (data_sz < offsetof(struct raw_dns_data, dns_payload) + dns_data->pkt_len)
		return 0;
	handle_dns_payload(dns_data->dns_payload, (int)dns_data->pkt_len);
	return 0;
}

#include <time.h>

static uint32_t get_portal_map_id(int fd)
{
#ifdef HAVE_LIBBPF
	struct bpf_map_info info;
	uint32_t len = sizeof(info);
	memset(&info, 0, sizeof(info));
	if (fd >= 0 && bpf_obj_get_info_by_fd(fd, &info, &len) == 0) {
		return info.id;
	}
#else
	(void)fd;
#endif
	return 0;
}

static int open_portal_map(void)
{
	static const char *paths[] = {
		DNS_PORTAL_BUF_MAP_PATH,
		DNS_RINGBUF_PORTAL_MAP_PATH,
		DNS_PORTAL_BUF_MAP_PATH_ALT,
		DNS_RINGBUF_PORTAL_MAP_PATH_ALT,
		DNS_PORTAL_BUF_MAP_PATH_XDP,
		DNS_RINGBUF_PORTAL_MAP_PATH_XDP,
		DNS_PORTAL_BUF_MAP_PATH_ROOT,
		DNS_RINGBUF_PORTAL_MAP_PATH_ROOT,
		NULL
	};

	for (int i = 0; paths[i]; i++) {
		int fd = bpf_obj_get(paths[i]);
		if (fd >= 0)
			return fd;
	}
	return -1;
}

void *
thread_dns_snoop(void *arg)
{
	struct ring_buffer *rb = NULL;
	int map_fd = -1;
	uint32_t attached_map_id = 0;
	time_t last_check = 0;

	(void)arg;
	debug(LOG_INFO, "Portal DNS consumer started (dns_ringbuf_portal)");

	for (;;) {
		if (!rb) {
			map_fd = open_portal_map();
			if (map_fd < 0) {
				debug(LOG_DEBUG, "dns_ringbuf_portal not ready, retry in 5s: %s",
				      strerror(errno));
				sleep(5);
				continue;
			}
			attached_map_id = get_portal_map_id(map_fd);
			rb = ring_buffer__new(map_fd, handle_portal_dns_event, NULL, NULL);
			if (!rb) {
				debug(LOG_ERR, "Failed to attach dns_ringbuf_portal, retry in 5s");
				close(map_fd);
				map_fd = -1;
				attached_map_id = 0;
				sleep(5);
				continue;
			}
			last_check = time(NULL);
			debug(LOG_INFO, "Attached dns_ringbuf_portal for wildcard trust (map_id=%u)", attached_map_id);
			seed_captive_domain_map();
		}

		int err = ring_buffer__poll(rb, 200);
		if (err == -EINTR)
			continue;
		if (err < 0) {
			debug(LOG_ERR, "portal DNS ringbuf poll failed: %d", err);
			ring_buffer__free(rb);
			rb = NULL;
			if (map_fd >= 0) {
				close(map_fd);
				map_fd = -1;
			}
			attached_map_id = 0;
			sleep(5);
			continue;
		}

		/* Periodic self-healing: detect if aw-bpf reloaded and recreated the map */
		time_t now = time(NULL);
		if (now - last_check >= 2) {
			last_check = now;
			int cur_fd = open_portal_map();
			if (cur_fd >= 0) {
				uint32_t cur_id = get_portal_map_id(cur_fd);
				close(cur_fd);
				if (cur_id != 0 && attached_map_id != 0 && cur_id != attached_map_id) {
					debug(LOG_INFO, "dns_ringbuf_portal map ID changed (%u -> %u), aw-bpf reloaded, reconnecting...",
					      attached_map_id, cur_id);
					ring_buffer__free(rb);
					rb = NULL;
					if (map_fd >= 0) {
						close(map_fd);
						map_fd = -1;
					}
					attached_map_id = 0;
					continue;
				}
			} else {
				/* Map file disappeared during aw-bpf restart/reload */
				debug(LOG_DEBUG, "dns_ringbuf_portal map pin disappeared, aw-bpf restarting, reconnecting...");
				ring_buffer__free(rb);
				rb = NULL;
				if (map_fd >= 0) {
					close(map_fd);
					map_fd = -1;
				}
				attached_map_id = 0;
				sleep(1);
				continue;
			}
		}
	}
}
