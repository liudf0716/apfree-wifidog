// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "conf.h"
#include "safe.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "wd_util.h"
#include "version.h"
#include "wd_client.h"
#include "client_list.h"
#include "dns_snoop.h"

struct captive_entry {
	char domain[64];
	char ip[16];
};

static struct captive_entry captive_entries[] = {
	{"captive.apple.com", "1.1.1.1"},
	{"www.apple.com", "1.1.1.1"},
	{"connect.rom.miui.com", "1.1.1.1"},
	{"www.msftconnecttest.com", "1.1.1.1"},
	{"www.gstatic.com", "1.1.1.1"},
	{"www.gstatic.cn", "1.1.1.1"},
	{"www.google.cn", "1.1.1.1"},
	{"www.qualcomm.cn", "1.1.1.1"},
	{"conn1.oppomobile.com", "1.1.1.1"},
	{"conn2.oppomobile.com", "1.1.1.1"},
	{"connectivitycheck.platform.hicloud.com", "1.1.1.1"},
	{"connectivitycheck.cbg-app.huawei.com", "1.1.1.1"},
	{"connectivitycheck.gstatic.com", "1.1.1.1"},
	{"cp.cloudflare.com", "1.1.1.1"},
	{"wifi.vivo.com.cn", "1.1.1.1"},
	{"connectivitycheck.platform.hihonorcloud.com", "1.1.1.1"},
	{"detectportal.firefox.com", "1.1.1.1"},
	{"services.googleapis.cn", "1.1.1.1"},
	{"g.cn", "1.1.1.1"},
	{"developer.android.google.cn", "1.1.1.1"},
	{"source.android.google.cn", "1.1.1.1"},
	{"www.google-analytics.com", "1.1.1.1"},
	{"clients1.google.com", "1.1.1.1"},
	{"clients2.google.com", "1.1.1.1"},
	{"clients3.google.com", "1.1.1.1"},
	{"clients4.google.com", "1.1.1.1"},
	{"clients5.google.com", "1.1.1.1"},
	{"goo.gl", "1.1.1.1"},
	{"google.cn", "1.1.1.1"},
	{"google.com.hk", "1.1.1.1"},
	{"google.com.tw", "1.1.1.1"},
	{"google.com", "1.1.1.1"},
	{"googleapis.com", "1.1.1.1"},
	{"play.googleapis.com", "1.1.1.1"},
	{"www.g.cn", "1.1.1.1"},
	{"www.google.com.hk", "1.1.1.1"},
	{"www.google.com.tw", "1.1.1.1"},
	{"www.google.com", "1.1.1.1"},
	{"www.googleapis.com", "1.1.1.1"},
	{"www.youtube.com", "1.1.1.1"},
	{"yt.be", "1.1.1.1"}
};

extern time_t started_time;

int g_online_clients;
char *g_version;
char *g_type;
char *g_name;

#define CAPTIVE_FAKE_IP "1.1.1.1"

static void ping_work_cb(evutil_socket_t, short, void *);
static void process_ping_response(struct evhttp_request *, void *);

/* Seed the aw-bpf captive_domain_map with the default fake IP for every
 * captive detection domain. aw-bpf answers matching LAN DNS queries with
 * this IP at wire speed (the query still reaches dnsmasq), and dns_snoop
 * learns the real IPs back into the map from upstream responses. */
static void
init_captive_domains(void)
{
	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Not openwrt platform, skipping init captive domains setup");
		return;
	}

	/* One-time migration: older releases answered the captive domains via
	 * a dnsmasq addnhosts file. That must go, or dnsmasq keeps answering
	 * them locally and the fast-answer map never learns real IPs. */
	if (access("/etc/aw-captive-domains-hosts", F_OK) == 0) {
		execute("uci -q del_list dhcp.@dnsmasq[0].addnhosts='/etc/aw-captive-domains-hosts';"
			"uci -q delete dhcp.aw_captive_hosts;"
			"uci commit dhcp;"
			"rm -f /etc/aw-captive-domains-hosts;"
			"/etc/init.d/dnsmasq restart >/dev/null 2>&1", 0);
		unlink("/etc/aw-captive-domains-hosts");
		debug(LOG_INFO, "Removed legacy aw-captive-domains-hosts from dnsmasq");
	}

	// if no auth portal; skip it
	if (is_portal_auth_disabled()) {
		debug(LOG_DEBUG, "Portal authentication is disabled, no need to check firewall rules");
		return;
	}

	int seeded = 0;
	for (int i = 0; i < (int)(sizeof(captive_entries)/sizeof(captive_entries[0])); i++) {
		if (captive_domain_map_set(captive_entries[i].domain, CAPTIVE_FAKE_IP) == 0)
			seeded++;
	}

	if (seeded > 0) {
		debug(LOG_INFO, "Seeded %d captive domains into aw-bpf captive_domain_map", seeded);
	} else {
		debug(LOG_ERR, "Failed to seed captive_domain_map (aw-bpf too old or not loaded?)");
	}
}

		

static void
ping_work_cb(evutil_socket_t fd, short event, void *arg) {

	struct wd_request_context *factory_ctx = (struct wd_request_context *)arg;
	t_gateway_setting *gw_settings = get_gateway_settings();
	if (!gw_settings) {
		debug(LOG_INFO, "no gateway setting");
		return;
	}

	struct sys_info info;
	memset(&info, 0, sizeof(info));
	get_sys_info(&info);

	char *uri = get_ping_v2_uri(&info);
	if (!uri) return; // impossibe
	debug(LOG_DEBUG, "uri is %s", uri);

	/* Request-owned context: factory only supplies base/ssl. */
	struct wd_request_context *req_ctx = wd_request_context_new(
		factory_ctx->base, factory_ctx->ssl, get_auth_server()->authserv_use_ssl);
	if (!req_ctx) {
		debug(LOG_ERR, "Failed to create request context for ping");
		free(uri);
		return;
	}

	struct evhttp_request *req = NULL;
	struct evhttp_connection *evcon = NULL;
	if (wd_make_request(req_ctx, &evcon, &req, process_ping_response)) {
		debug(LOG_ERR, "Failed to make request to auth server");
		wd_request_context_destroy(req_ctx);
		free(uri);
		return;
	}
	
	if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri) != 0) {
		debug(LOG_ERR, "Failed to queue ping request to auth server");
		evhttp_request_free(req);
		evhttp_connection_free(evcon);
		wd_request_context_destroy(req_ctx);
	}
	/* success: process_ping_response destroys req_ctx */
	free(uri);	
}

/**
 * @brief ping process
 * 
 */
void
thread_ping(void *arg)
{
	// Always run the captive domains init: it also migrates away the
	// legacy dnsmasq hosts file on every platform that needs it.
	init_captive_domains();

	// Only parse trusted domains when portal auth is enabled
	if (!is_portal_auth_disabled()) {
		parse_user_trusted_domain_list();
		parse_inner_trusted_domain_list();
	} else {
		debug(LOG_INFO, "Portal authentication is disabled, skipping domain parsing");
	}

	if (is_local_auth_mode()) {
		debug(LOG_DEBUG, "auth mode is local, no need to ping auth server");
		while(1)
			sleep(60);
	} else {
		debug(LOG_DEBUG, "auth mode is cloud, start to ping auth server");
		wd_request_loop(ping_work_cb);
	}
}

static long
check_and_get_wifidog_uptime(long sys_uptime)
{
    long wifidog_uptime = time(NULL) - started_time;
    if (wifidog_uptime > sys_uptime) {
        started_time = time(NULL);
        return 0;
    } else  
    	return wifidog_uptime;
}

char *
get_ping_v2_uri(const struct sys_info *info)
{
	t_auth_serv *auth_server = get_auth_server();
	char *uri = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&uri, 
			"%s%sdevice_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&fm_version=%s&type=%s&name=%s&wired_passed=%d&aw_version=%s",
			 auth_server->authserv_path,
			 auth_server->authserv_ping_script_path_fragment,
			 get_device_id(),
			 info->sys_uptime,
			 info->sys_memfree,
			 info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
			 check_and_get_wifidog_uptime(info->sys_uptime),
			 g_online_clients,
			 offline_client_ageout(),
			 "null",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 config_get_config()->wired_passed,
			 VERSION);
	if (nret < 0)
		return NULL;

	return uri;
}

/**
 * @brief get ping uri
 * 
 * @param info The system info structure
 * @return NULL fail or ping uri
 * 
 */ 
char *
get_ping_uri(const struct sys_info *info, t_gateway_setting *gw_setting)
{
	t_auth_serv *auth_server = get_auth_server();
	char *uri = NULL;
	
	if (!info)
		return NULL;
	
	int nret = safe_asprintf(&uri, 
			"%s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&nf_conntrack_count=%lu&cpu_usage=%3.2lf&wifidog_uptime=%lu&online_clients=%d&offline_clients=%d&ssid=%s&fm_version=%s&type=%s&name=%s&gw_channel=%s&wired_passed=%d&aw_version=%s",
			 auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             gw_setting->gw_id,
             info->sys_uptime,
             info->sys_memfree,
             info->sys_load,
			 info->nf_conntrack_count,
			 info->cpu_usage,
             check_and_get_wifidog_uptime(info->sys_uptime),
			 g_online_clients,
			 offline_client_ageout(),
			 "null",
			 NULL != g_version?g_version:"null",
			 NULL != g_type?g_type:"null",
			 NULL != g_name?g_name:"null",
			 gw_setting->gw_channel,
             config_get_config()->wired_passed,
			 VERSION);
	if (nret < 0)
		return NULL;

	return uri;
}

/**
 * @brief Get CPU temperature from thermal sensors
 * 
 * @return CPU temperature in Celsius, or -1 if unable to read
 */ 
static int
get_cpu_temperature(void)
{
	const char *thermal_paths[] = {
		"/sys/class/thermal/thermal_zone0/temp",
		"/sys/class/thermal/thermal_zone1/temp",
		"/sys/class/thermal/thermal_zone2/temp",
		"/sys/class/hwmon/hwmon0/temp1_input",
		"/sys/class/hwmon/hwmon1/temp1_input",
		"/sys/class/hwmon/hwmon2/temp1_input",
		NULL
	};
	
	FILE *fh = NULL;
	int raw_temp = 0;
	int temp_celsius = -1;
	
	// Try each possible thermal sensor path
	for (int i = 0; thermal_paths[i] != NULL; i++) {
		fh = fopen(thermal_paths[i], "r");
		if (fh) {
			if (fscanf(fh, "%d", &raw_temp) == 1) {
				// Most thermal sensors report in millidegrees Celsius
				// Convert to degrees Celsius with proper rounding
				temp_celsius = (raw_temp + 500) / 1000;
				fclose(fh);
				debug(LOG_DEBUG, "CPU temperature read from %s: %d°C", thermal_paths[i], temp_celsius);
				break;
			}
			fclose(fh);
		}
	}
	
	if (temp_celsius == -1) {
		debug(LOG_DEBUG, "Unable to read CPU temperature from any thermal sensor");
	}
	
	return temp_celsius;
}

/**
 * @brief get system info to info param
 * 
 * @param info Out param to store system info
 * 
 */ 
void
get_sys_info(struct sys_info *info)
{
	FILE 	*fh = NULL;
	if (info == NULL)
		return;
	
	info->cpu_usage = get_cpu_usage();
	info->cpu_temp = get_cpu_temperature();
	
	// Set wifidog uptime based on started_time
	extern time_t started_time;
	info->wifidog_uptime = time(NULL) - started_time;
	
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &info->sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
    }
	
	if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &info->sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
	
	if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &info->sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
    }
	
	if ((fh = fopen("/proc/sys/net/netfilter/nf_conntrack_count", "r"))) {
        if (fscanf(fh, "%lu", &info->nf_conntrack_count) != 1)
            debug(LOG_CRIT, "Failed to read nf_conntrack_count");

        fclose(fh);
		fh = NULL;
    }
	
	if(!g_version) {
		FILE *release_file = fopen("/etc/openwrt_release", "r");
		if (release_file) {
			char line[256];
			while (fgets(line, sizeof(line), release_file)) {
				// Look for DISTRIB_REVISION line
				if (strncmp(line, "DISTRIB_REVISION=", 17) == 0) {
					char *value = line + 17;
					// Remove quotes if present
					if (value[0] == '\'' && strlen(value) > 1) {
						value++; // Skip opening quote
						char *end_quote = strchr(value, '\'');
						if (end_quote) {
							*end_quote = '\0'; // Terminate at closing quote
						}
					}
					// Remove newline
					char *newline = strchr(value, '\n');
					if (newline) {
						*newline = '\0';
					}
					
					// Extract revision number (e.g., r28790 from r28790-848c5902de)
					if (value[0] == 'r') {
						char *dash = strchr(value, '-');
						if (dash) {
							*dash = '\0'; // Terminate at dash to get just r28790
						}
						g_version = safe_strdup(value);
					}
					break;
				}
			}
			fclose(release_file);
		}
	}
	
	if(!g_type) {
		if ((fh = fopen("/var/sysinfo/board_type", "r"))) {
			char name[32] = {0};
			if (fgets(name, 31, fh)) {
				trim_newline(name);
				if(strlen(name) > 0)
					g_type = safe_strdup(name);
			}
			fclose(fh);
		}
	}
	
	if(!g_name) {
		if ((fh = fopen("/var/sysinfo/board_name", "r"))) {
			char name[32] = {0};
			if (fgets(name, 31, fh)) {
				trim_newline(name);
				if(strlen(name) > 0)
					g_name = safe_strdup(name);
			}
			fclose(fh);
		}
	}
}

static void
process_ping_response(struct evhttp_request *req, void *ctx)
{
	static int authdown = 0;
	struct wd_request_context *context = (struct wd_request_context *)ctx;
	
	if (!req) {
		mark_auth_offline();
		if (!authdown) {		
            fw_set_authdown();
            authdown = 1;
        }
		if (context)
			wd_request_context_destroy(context);
		return;
	}
	
	char buffer[MAX_BUF] = {0};
	int nread = evbuffer_remove(evhttp_request_get_input_buffer(req),
		    buffer, MAX_BUF-1);
	if (nread <= 0) {
		mark_auth_offline();
        debug(LOG_ERR, "There was a problem getting response from the auth server!");
        if (!authdown) {			
            fw_set_authdown();
            authdown = 1;
        }
    } else if (strstr(buffer, "Pong") == 0) {
		mark_auth_offline();
        debug(LOG_WARNING, "Auth server did NOT say Pong! the response [%s], error: %s", 
			buffer, strerror(errno));
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else {
    	mark_auth_online();
        debug(LOG_DEBUG, "Auth Server Says: Pong");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
    }

	if (context)
		wd_request_context_destroy(context);
}
