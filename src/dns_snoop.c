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
#include "aw_bpf_compat.h"

#ifndef MAX_DNS_PAYLOAD_LEN
#define MAX_DNS_PAYLOAD_LEN 512
#endif

#define MAX_DNS_NAME 256
#define DNS_PORTAL_MAP_PATH     "/sys/fs/bpf/tc/globals/dns_ringbuf_portal"
#define DNS_PORTAL_MAP_PATH_ALT "/sys/fs/bpf/aw/dns_ringbuf_portal"

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
};

static int parse_dns_name(const unsigned char *payload, int payload_len, int offset,
			  char *name, int max_len)
{
	int pos = offset, name_pos = 0, jumped = 0, jumps = 0;
	int skip_only = (name == NULL || max_len <= 0);

	if (!payload || offset < 0 || offset >= payload_len)
		return -1;
	if (!skip_only)
		name[0] = '\0';

	while (pos < payload_len && jumps < 5) {
		int len = payload[pos];
		if (len == 0) {
			pos++;
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

static int open_portal_map(void)
{
	int fd = bpf_obj_get(DNS_PORTAL_MAP_PATH);
	if (fd >= 0)
		return fd;
	return bpf_obj_get(DNS_PORTAL_MAP_PATH_ALT);
}

void *
thread_dns_snoop(void *arg)
{
	struct ring_buffer *rb = NULL;
	int map_fd = -1;

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
			rb = ring_buffer__new(map_fd, handle_portal_dns_event, NULL, NULL);
			if (!rb) {
				debug(LOG_ERR, "Failed to attach dns_ringbuf_portal, retry in 5s");
				close(map_fd);
				map_fd = -1;
				sleep(5);
				continue;
			}
			debug(LOG_INFO, "Attached dns_ringbuf_portal for wildcard trust");
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
			sleep(5);
		}
	}
}
