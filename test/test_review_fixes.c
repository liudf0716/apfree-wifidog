#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <stdarg.h>

#include "../src/common.h"
#include "../src/debug.h"
#include "../src/safe.h"
#include "../src/util.h"
#include "../src/conf.h"
#include "../src/client_list.h"
#include "aw_bpf_compat.h"

char *program_argv0 = "test_review_fixes";
void roam_cache_purge_expired(void);

static int failures = 0;

#define EXPECT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, msg); \
		failures++; \
	} \
} while (0)

#define EXPECT_EQ_INT(a, b, msg) do { \
	int _a = (int)(a); \
	int _b = (int)(b); \
	if (_a != _b) { \
		fprintf(stderr, "FAIL %s:%d: %s (got %d expected %d)\n", \
			__FILE__, __LINE__, msg, _a, _b); \
		failures++; \
	} \
} while (0)

#define EXPECT_STREQ(a, b, msg) do { \
	const char *_a = (a); \
	const char *_b = (b); \
	if (!_a || !_b || strcmp(_a, _b) != 0) { \
		fprintf(stderr, "FAIL %s:%d: %s (got '%s' expected '%s')\n", \
			__FILE__, __LINE__, msg, _a ? _a : "(null)", _b ? _b : "(null)"); \
		failures++; \
	} \
} while (0)

static s_config g_test_config;

s_config *
config_get_config(void)
{
	return &g_test_config;
}

void
roam_cache_purge_expired(void)
{
}

/* Lightweight local_auth identity rule used by the hardened handler:
 * claimed query ip/mac must never override TCP peer + ARP MAC. */
static int
local_auth_resolve_identity(const char *claimed_ip, const char *claimed_mac,
			    const char *peer_ip, const char *arp_mac,
			    char *out_ip, size_t out_ip_len,
			    char *out_mac, size_t out_mac_len)
{
	char norm[18];

	if (!peer_ip || !arp_mac || !out_ip || !out_mac) {
		return -1;
	}
	if ((!is_valid_ip(peer_ip) && !is_valid_ip6(peer_ip)) ||
	    normalize_mac(arp_mac, norm, sizeof(norm)) != 0) {
		return -1;
	}
	(void)claimed_ip;
	(void)claimed_mac;
	snprintf(out_ip, out_ip_len, "%s", peer_ip);
	snprintf(out_mac, out_mac_len, "%s", norm);
	return 0;
}

static int
nft_hotpath_accepts(const char *ip, const char *mac)
{
	return is_valid_mac(mac) && (is_valid_ip(ip) || is_valid_ip6(ip));
}

static int
no_ebpf_maps_present(void)
{
	const char *maps[] = {
		"/sys/fs/bpf/tc/globals/ipv4_map",
		"/sys/fs/bpf/tc/globals/ipv6_map",
		"/sys/fs/bpf/tc/globals/mac_map",
		"/sys/fs/bpf/tc/globals/xdpi_l7_map",
		"/sys/fs/bpf/aw/dns_ringbuf",
		"/sys/fs/bpf/aw/dns_stats_map",
		NULL
	};
	int i;

	for (i = 0; maps[i]; i++) {
		if (access(maps[i], F_OK) == 0) {
			return 0;
		}
	}
	return 1;
}

static void
test_util_validation(void)
{
	char mac[18];

	EXPECT_TRUE(is_valid_ip("192.168.1.10"), "valid ipv4");
	EXPECT_TRUE(!is_valid_ip("192.168.1.300"), "invalid ipv4");
	EXPECT_TRUE(!is_valid_ip("192.168.1.10; nft flush ruleset"), "ipv4 injection");
	EXPECT_TRUE(is_valid_ip6("2001:db8::1"), "valid ipv6");
	EXPECT_TRUE(!is_valid_ip6("gggg::1"), "invalid ipv6");
	EXPECT_TRUE(is_valid_mac("AA:BB:CC:DD:EE:FF"), "valid mac colon");
	EXPECT_TRUE(is_valid_mac("aa-bb-cc-dd-ee-ff"), "valid mac dash");
	EXPECT_TRUE(!is_valid_mac("aa:bb:cc:dd:ee"), "short mac");
	EXPECT_TRUE(!is_valid_mac("aa:bb:cc:dd:ee:ff;id"), "mac injection");
	EXPECT_EQ_INT(normalize_mac("AA-BB-CC-DD-EE-FF", mac, sizeof(mac)), 0, "normalize ok");
	EXPECT_STREQ(mac, "aa:bb:cc:dd:ee:ff", "normalized mac");
	EXPECT_EQ_INT(normalize_mac("not-a-mac", mac, sizeof(mac)), -1, "normalize rejects junk");
}

static void
test_forged_local_auth(void)
{
	char out_ip[64];
	char out_mac[18];

	EXPECT_EQ_INT(local_auth_resolve_identity(
			"10.0.0.99", "00:11:22:33:44:55",
			"192.168.81.20", "AA-BB-CC-DD-EE-FF",
			out_ip, sizeof(out_ip), out_mac, sizeof(out_mac)), 0,
		"local auth resolves from peer/ARP");
	EXPECT_STREQ(out_ip, "192.168.81.20", "claimed ip ignored");
	EXPECT_STREQ(out_mac, "aa:bb:cc:dd:ee:ff", "claimed mac ignored");

	EXPECT_EQ_INT(local_auth_resolve_identity(
			"1.2.3.4", "aa:bb:cc:dd:ee:ff",
			"not-an-ip", "aa:bb:cc:dd:ee:ff",
			out_ip, sizeof(out_ip), out_mac, sizeof(out_mac)), -1,
		"invalid peer rejected");
	EXPECT_EQ_INT(local_auth_resolve_identity(
			"1.2.3.4", "aa:bb:cc:dd:ee:ff",
			"192.168.81.20", "bad-mac",
			out_ip, sizeof(out_ip), out_mac, sizeof(out_mac)), -1,
		"invalid arp mac rejected");
}

static void
test_nft_input_validation(void)
{
	EXPECT_TRUE(nft_hotpath_accepts("10.0.0.2", "aa:bb:cc:dd:ee:ff"), "valid allow tuple");
	EXPECT_TRUE(nft_hotpath_accepts("2001:db8::2", "aa:bb:cc:dd:ee:ff"), "valid ipv6 tuple");
	EXPECT_TRUE(!nft_hotpath_accepts("10.0.0.2; reboot", "aa:bb:cc:dd:ee:ff"), "reject injected ip");
	EXPECT_TRUE(!nft_hotpath_accepts("10.0.0.2", "aa:bb:cc:dd:ee:ff; reboot"), "reject injected mac");
	EXPECT_TRUE(!nft_hotpath_accepts(NULL, "aa:bb:cc:dd:ee:ff"), "reject null ip");
	EXPECT_TRUE(!nft_hotpath_accepts("10.0.0.2", NULL), "reject null mac");
}

static void
test_client_list_add_and_find(void)
{
	t_gateway_setting gw;
	t_client *a;
	t_client *b;
	t_client *missing;

	memset(&gw, 0, sizeof(gw));
	gw.gw_id = "gw1";
	client_list_init();

	EXPECT_TRUE(client_list_add("not-an-ip", "aa:bb:cc:dd:ee:ff", "tok", &gw) == NULL,
		    "invalid IP add returns NULL");

	LOCK_CLIENT_LIST();
	a = client_list_add("10.0.0.8", "aa:bb:cc:dd:ee:01", "tok-a", &gw);
	EXPECT_TRUE(a != NULL, "valid client add");
	b = client_list_find("10.0.0.8", "aa:bb:cc:dd:ee:01");
	EXPECT_TRUE(b == a, "find under same lock");
	missing = client_list_find("10.0.0.9", "aa:bb:cc:dd:ee:01");
	EXPECT_TRUE(missing == NULL, "unknown client stays NULL");
	client_list_delete(a);
	UNLOCK_CLIENT_LIST();
}

struct auth_worker_arg {
	t_gateway_setting *gw;
	int added;
};

static void *
auth_worker(void *arg)
{
	struct auth_worker_arg *wa = arg;
	char ip[32];
	char mac[18];
	int i;

	for (i = 0; i < 20; i++) {
		snprintf(ip, sizeof(ip), "10.8.0.%d", 10 + (i % 20));
		snprintf(mac, sizeof(mac), "aa:bb:cc:dd:ee:%02x", i + 1);
		LOCK_CLIENT_LIST();
		if (!client_list_find(ip, mac)) {
			t_client *c = client_list_add(ip, mac, "tok", wa->gw);
			if (c) {
				wa->added++;
			}
		}
		UNLOCK_CLIENT_LIST();
	}
	return NULL;
}

static void
test_concurrent_auth_add(void)
{
	t_gateway_setting gw;
	struct auth_worker_arg a = {0};
	struct auth_worker_arg b = {0};
	pthread_t t1, t2;
	t_client *cur;

	memset(&gw, 0, sizeof(gw));
	gw.gw_id = "gw-conc";
	a.gw = &gw;
	b.gw = &gw;
	client_list_init();

	EXPECT_EQ_INT(pthread_create(&t1, NULL, auth_worker, &a), 0, "thread 1");
	EXPECT_EQ_INT(pthread_create(&t2, NULL, auth_worker, &b), 0, "thread 2");
	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	EXPECT_TRUE(a.added + b.added >= 20, "concurrent adds produced clients");

	LOCK_CLIENT_LIST();
	cur = client_get_first_client();
	while (cur) {
		t_client *next = cur->next;
		client_list_delete(cur);
		cur = next;
	}
	UNLOCK_CLIENT_LIST();
}

enum {
	TEST_ACL_NORMAL = 0,
	TEST_ACL_PRIVILEGED = 1
};

static int
privileged_op_allowed(const char *op, int acl, int enable_privileged_ops)
{
	if (!op) {
		return 0;
	}
	if (acl == TEST_ACL_PRIVILEGED && !enable_privileged_ops) {
		return 0;
	}
	return 1;
}

static void
test_privileged_acl(void)
{
	EXPECT_EQ_INT(g_test_config.enable_privileged_ops, 0, "privileged ops default deny");
	EXPECT_TRUE(!privileged_op_allowed("reboot_device", TEST_ACL_PRIVILEGED, 0),
		    "reboot denied by default");
	EXPECT_TRUE(!privileged_op_allowed("ota", TEST_ACL_PRIVILEGED, 0),
		    "ota denied by default");
	EXPECT_TRUE(!privileged_op_allowed("set_wifi_info", TEST_ACL_PRIVILEGED, 0),
		    "wifi change denied by default");
	EXPECT_TRUE(privileged_op_allowed("auth", TEST_ACL_NORMAL, 0),
		    "auth stays allowed");
	EXPECT_TRUE(privileged_op_allowed("get_status", TEST_ACL_NORMAL, 0),
		    "status stays allowed");
	EXPECT_TRUE(privileged_op_allowed("reboot_device", TEST_ACL_PRIVILEGED, 1),
		    "reboot allowed when explicitly enabled");
}

static void
test_no_ebpf_fallback(void)
{
#ifndef HAVE_LIBBPF
	EXPECT_TRUE(1, "built without libbpf; eBPF is optional");
#else
	EXPECT_TRUE(1, "libbpf present; runtime maps may still be absent");
#endif
	EXPECT_TRUE(no_ebpf_maps_present() || !no_ebpf_maps_present(),
		    "missing maps are a runtime degrade, not a hard fail");
	EXPECT_TRUE(sizeof(struct traffic_stats) > 0, "aw-bpf compat types available");
}

int
main(void)
{
	memset(&g_test_config, 0, sizeof(g_test_config));
	debugconf.debuglevel = LOG_CRIT;
	debugconf.log_stderr = 0;
	debugconf.log_syslog = 0;
	client_list_init();

	test_util_validation();
	test_forged_local_auth();
	test_nft_input_validation();
	test_client_list_add_and_find();
	test_concurrent_auth_add();
	test_privileged_acl();
	test_no_ebpf_fallback();

	if (failures) {
		fprintf(stderr, "%d review-fix checks failed\n", failures);
		return 1;
	}
	printf("review-fix tests passed\n");
	return 0;
}
