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
char *g_ssid;

#define CUSTOM_HOSTS_FILE "/etc/aw-captive-domains-hosts"

static void ping_work_cb(evutil_socket_t, short, void *);
static void process_ping_response(struct evhttp_request *, void *);

static void
update_captive_domains_with_real_ips(void)
{
	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Not openwrt platform, skipping update captive domains setup");
		return;
	}

	// First, delete existing addnhosts entries and restart dnsmasq to clear cache
	if (execute("uci -q delete dhcp.@dnsmasq[0].addnhosts && uci commit dhcp && /etc/init.d/dnsmasq restart >/dev/null 2>&1", 0) != 0) {
		debug(LOG_ERR, "Failed to remove existing addnhosts configuration");
		return;
	}

	// Wait a short moment for dnsmasq to fully restart
	usleep(100000);  // 100ms delay

	// Create or truncate the custom hosts file
	FILE *fp = fopen(CUSTOM_HOSTS_FILE, "w");
	if (!fp) {
		debug(LOG_ERR, "Failed to create custom hosts file: %s", strerror(errno));
		return;
	}

	// Get real IPs and write to file
	for (int i = 0; i < (int)(sizeof(captive_entries)/sizeof(captive_entries[0])); i++) {
		struct hostent *he = gethostbyname(captive_entries[i].domain);
		if (he != NULL) {
			struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
			if (addr_list[0] != NULL) {
				char real_ip[16];
				inet_ntop(AF_INET, addr_list[0], real_ip, sizeof(real_ip));
				fprintf(fp, "%s %s\n", real_ip, captive_entries[i].domain);
				continue;
			}
		}
		// If resolution failed, use default IP
		fprintf(fp, "%s %s\n", captive_entries[i].ip, captive_entries[i].domain);
	}
	fclose(fp);

	// Add new addnhosts entry as a list and restart dnsmasq
	if (execute("uci -q add_list dhcp.@dnsmasq[0].addnhosts='" CUSTOM_HOSTS_FILE "' && "
				"uci commit dhcp && /etc/init.d/dnsmasq restart >/dev/null 2>&1", 0) != 0) {
		debug(LOG_ERR, "Failed to update dnsmasq configuration");
		return;
	}

	debug(LOG_INFO, "Updated captive domains with real IPs");
}

static void
init_captive_domains(void)
{
	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Not openwrt platform, skipping init captive domains setup");
		return;
	}

	// Create or truncate the custom hosts file
	FILE *fp = fopen(CUSTOM_HOSTS_FILE, "w");
	if (!fp) {
		debug(LOG_ERR, "Failed to create custom hosts file: %s", strerror(errno));
		return;
	}

	// Write all entries to the file
	for (int i = 0; i < (int)(sizeof(captive_entries)/sizeof(captive_entries[0])); i++) {
		if (fprintf(fp, "%s %s\n", captive_entries[i].ip, captive_entries[i].domain) < 0) {
			debug(LOG_ERR, "Failed to write to custom hosts file: %s", strerror(errno));
			fclose(fp);
			return;
		}
	}
	fclose(fp);

	// Configure dnsmasq to use the custom hosts file
	// First, only delete CUSTOM_HOSTS_FILE entry if it exists
	if (execute("uci -q del_list dhcp.@dnsmasq[0].addnhosts='" CUSTOM_HOSTS_FILE "' >/dev/null 2>&1", 0) != 0) {
		debug(LOG_ERR, "Failed to delete existing custom hosts file from dnsmasq config");
		return;
	}
	
	// Add new addnhosts entry as a list
	if (execute("uci -q add_list dhcp.@dnsmasq[0].addnhosts='" CUSTOM_HOSTS_FILE "' >/dev/null 2>&1", 0) != 0) {
		debug(LOG_ERR, "Failed to add custom hosts file to dnsmasq config");
		return;
	}

	// Commit changes and restart dnsmasq
	if (execute("uci commit dhcp && /etc/init.d/dnsmasq restart >/dev/null 2>&1", 0) != 0) {
		debug(LOG_ERR, "Failed to commit changes and restart dnsmasq");
		return;
	}

	debug(LOG_INFO, "Initialized captive domains using custom hosts file");
}

static void
check_wifidogx_firewall_rules(void)
{
	if (!is_openwrt_platform()) 
		return;

	if (is_bypass_mode()) {
		debug(LOG_INFO, "Bypass mode, no need to check firewall rules");
		return;
	}

	FILE *fp = popen("nft list chain inet fw4 dstnat", "r");
	if (!fp) {
		debug(LOG_ERR, "Failed to list chain inet fw4 dstnat");
		return;
	}
	char line[512] = {0};
	int has_rule = 0;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "dstnat_wifidogx_outgoing")) {
			has_rule = 1;
			break;
		}
	}
	pclose(fp);

	if (!has_rule) {
		debug(LOG_ERR, "wifidogx's firewall rule is not completed, reload aw firewall rules");
		pid_t pid = getpid();
    	kill(pid, SIGUSR1);
	}
}
		

static void 
ping_work_cb(evutil_socket_t fd, short event, void *arg) {
	static int first_online = 1;
	int now_online = is_online();

	// When internet becomes available for the first time, update captive domains with real IPs
	if (now_online && first_online) {
		update_captive_domains_with_real_ips();
		first_online = 0;
	}

	// Check firewall rules in both local and cloud modes
	check_wifidogx_firewall_rules();

	struct wd_request_context *request_ctx = (struct wd_request_context *)arg;
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

	struct evhttp_request *req = NULL;
	struct evhttp_connection *evcon = NULL;
	if (wd_make_request(request_ctx, &evcon, &req, process_ping_response)) {
		debug(LOG_ERR, "Failed to make request to auth server");
		free(uri);
		return;
	}
	
	evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
	free(uri);	
}

/**
 * @brief ping process
 * 
 */
void
thread_ping(void *arg)
{
	parse_user_trusted_domain_list();
	parse_inner_trusted_domain_list();
	
	// Initialize captive domains with default IPs at startup
	init_captive_domains();

	if (is_local_auth_mode()) {
		debug(LOG_DEBUG, "auth mode is local, no need to ping auth server");
		int first_online = 1;
		while(1) {
			sleep(60);
			check_wifidogx_firewall_rules();
			
			// When internet becomes available for the first time in local mode, update captive domains with real IPs
			if (is_online() && first_online) {
				debug(LOG_INFO, "Internet is available in local mode, updating captive domains with real IPs");
				update_captive_domains_with_real_ips();
				first_online = 0;
			}
		}
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
			 NULL != g_ssid?g_ssid:"NULL",
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
			 NULL != g_ssid?g_ssid:"NULL",
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
 * @brief get system info to info param
 * 
 * @param info Out param to store system info
 * 
 */ 
void
get_sys_info(struct sys_info *info)
{
	FILE 	*fh = NULL;
	char	ssid[32] = {0};
	
	if (info == NULL)
		return;
	
	info->cpu_usage = get_cpu_usage();
	
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
	
	// get first ssid
	if (uci_get_value("wireless", "ssid", ssid, 31)) {
		trim_newline(ssid);
		if(strlen(ssid) > 0) {
			if(g_ssid) 
				free(g_ssid);
			g_ssid = evhttp_encode_uri(ssid);
		}
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
	
	if (!req) {
		mark_auth_offline();
		if (!authdown) {		
            fw_set_authdown();
            authdown = 1;
        }
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
}


