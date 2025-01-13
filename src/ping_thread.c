
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

const char *captive_domains[] = {
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
    "yt.be"
};

extern time_t started_time;

int g_online_clients;
char *g_version;
char *g_type;
char *g_name;
char *g_ssid;

static void ping_work_cb(evutil_socket_t, short, void *);
static void process_ping_response(struct evhttp_request *, void *);

static void
remove_captive_domains(void)
{
	for (int i = 0; i < (int)(sizeof(captive_domains)/sizeof(captive_domains[0])); i++) {
		char cmd[512];
		if (snprintf(cmd, sizeof(cmd),
			"uci -q del_list dhcp.@dnsmasq[0].address=/%s/1.1.1.1",
			captive_domains[i]) >= (int)sizeof(cmd)) {
			debug(LOG_ERR, "Command buffer too small");
			continue;
		}
		system(cmd);
	}
	system("uci commit dhcp && /etc/init.d/dnsmasq restart >/dev/null 2>&1");
	debug(LOG_INFO, "Removed captive domains");
}

static void
update_captive_domains(void)
{
	for (int i = 0; i < (int)(sizeof(captive_domains)/sizeof(captive_domains[0])); i++) {
		char cmd[512];
		if (snprintf(cmd, sizeof(cmd),
			"uci -q del_list dhcp.@dnsmasq[0].address=/%s/1.1.1.1",
			captive_domains[i]) >= (int)sizeof(cmd)) {
			debug(LOG_ERR, "Command buffer too small %s", captive_domains[i]);
			continue;
		}
		system(cmd);
		memset(cmd, 0, sizeof(cmd));
		if (snprintf(cmd, sizeof(cmd),
			"uci -q add_list dhcp.@dnsmasq[0].address=/%s/1.1.1.1",
			captive_domains[i]) >= (int)sizeof(cmd)) {
			debug(LOG_ERR, "Command buffer too small %s", captive_domains[i]);
			continue;
		}
		system(cmd);
	}
	system("uci commit dhcp && /etc/init.d/dnsmasq restart >/dev/null 2>&1");
	debug(LOG_INFO, "Added captive domains");
}

static void
make_captive_domains_query_responsable(void)
{
	static int was_online = 0;
	int now_online = is_online();

	if (!is_openwrt_platform()) {
		debug(LOG_INFO, "Not openwrt platform, skipping captive domains setup");
		return;
	}

	if (now_online && !was_online) {
		remove_captive_domains();
	} else if (!now_online && was_online) {
		update_captive_domains();
	}

	was_online = now_online;
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
		debug(LOG_INFO, "wifidogx's firewall rule is not completed, reload aw firewall rules");
		pid_t pid = getpid();
    	kill(pid, SIGUSR1);
	}
}
		

static void 
ping_work_cb(evutil_socket_t fd, short event, void *arg) {
	make_captive_domains_query_responsable();

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
	if (!is_online() && is_openwrt_platform()) {
		update_captive_domains();
	}

	parse_user_trusted_domain_list();
	parse_inner_trusted_domain_list();

	if (is_local_auth_mode()) {
		debug(LOG_DEBUG, "auth mode is local, no need to ping auth server");
		while(1) {
			sleep(60);
			make_captive_domains_query_responsable();
			check_wifidogx_firewall_rules();
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
		char version[32] = {0};
		if (uci_get_value("firmwareinfo", "firmware_version", version, 31)) {			
			trim_newline(version);
			if(strlen(version) > 0)
				g_version = safe_strdup(version);
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


