
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctlx_thread.h"
#include "uci_helper.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"
#include "wd_client.h"
#include "client_snapshot.h"
#include "hotplug_listener.h"
#include "api_handlers.h"

static struct sockaddr_un *create_unix_socket(const char *);

static void wdctl_status(struct bufferevent *, const char *);
static void wdctl_stop(struct bufferevent *);
static void wdctl_refresh(struct bufferevent *);
static void wdctl_clear_trusted_wildcard_domains(struct bufferevent *);
static void wdctl_show_trusted_wildcard_domains(struct bufferevent *);
static void wdctl_clear_trusted_iplist(struct bufferevent *);
static void wdctl_reparse_trusted_domains(struct bufferevent *);
static void wdctl_clear_trusted_domains(struct bufferevent *);
static void wdctl_show_trusted_domains(struct bufferevent *);
static void wdctl_show_roam_maclist(struct bufferevent *);
static void wdctl_clear_roam_maclist(struct bufferevent *);
static void wdctl_show_trusted_maclist(struct bufferevent *);
static void wdctl_clear_trusted_maclist(struct bufferevent *);
static void wdctl_show_trusted_local_maclist(struct bufferevent *);
static void wdctl_clear_trusted_local_maclist(struct bufferevent *);
static void wdctl_show_untrusted_maclist(struct bufferevent *);
static void wdctl_clear_untrusted_maclist(struct bufferevent *);
static void wdctl_user_cfg_save(struct bufferevent *);

static void wdctl_reset(struct bufferevent *, const char *);
static void wdctl_add_trusted_wildcard_domains(struct bufferevent *, const char *);
static void wdctl_del_trusted_wildcard_domains(struct bufferevent *, const char *);
static void wdctl_add_trusted_domains(struct bufferevent *, const char *);
static void wdctl_del_trusted_domains(struct bufferevent *, const char *);
static void wdctl_add_trusted_iplist(struct bufferevent *, const char *);
static void wdctl_del_trusted_iplist(struct bufferevent *, const char *);
static void wdctl_add_domain_ip(struct bufferevent *, const char *);
static void wdctl_add_roam_maclist(struct bufferevent *, const char *);
static void wdctl_add_trusted_maclist(struct bufferevent *, const char *);
static void wdctl_del_trusted_maclist(struct bufferevent *, const char *);
static void wdctl_add_trusted_local_maclist(struct bufferevent *, const char *);
static void wdctl_del_trusted_local_maclist(struct bufferevent *, const char *);
static void wdctl_add_untrusted_maclist(struct bufferevent *, const char *);
static void wdctl_del_untrusted_maclist(struct bufferevent *, const char *);
static void wdctl_add_online_client(struct bufferevent *, const char *);
static void wdctl_add_auth_client(struct bufferevent *, const char *);
static void wdctl_set_local_portal(struct bufferevent *, const char *);

static void wdctl_user_list(struct bufferevent *);
static void wdctl_user_info(struct bufferevent *, const char *);
static void wdctl_user_auth(struct bufferevent *, const char *);
static void wdctl_save_user(struct bufferevent *);
static void wdctl_restore_user(struct bufferevent *);
static void wdctl_add_anti_nat_permit_device(struct bufferevent *, const char *mac);
static void wdctl_del_anti_nat_permit_device(struct bufferevent *, const char *mac);

static void wdctl_hotplugin_event(struct bufferevent *fd, const char *event);
static void wdctl_bpf_add(struct bufferevent *fd, const char *args);
static void wdctl_bpf_del(struct bufferevent *fd, const char *args);
static void wdctl_bpf_list(struct bufferevent *fd, const char *args);
static void wdctl_bpf_flush(struct bufferevent *fd, const char *args);
static void wdctl_bpf_update(struct bufferevent *fd, const char *args);
static void wdctl_bpf_update_all(struct bufferevent *fd, const char *args);
static int wdctl_send_response_func(api_transport_context_t *transport, const char *message, size_t length);

static struct wd_request_context *request_ctx;
static const char *no_auth_response = "no auth server";

static struct wdctl_command {
    const char *command;
    void (*process_cmd)(struct bufferevent *bev);
    void (*process_param_cmd)(struct bufferevent *bev, const char *param);
} wdctl_cmd[] = {
    {"status", NULL, wdctl_status},
    {"stop", wdctl_stop, NULL},
    {"refresh", wdctl_refresh, NULL},
    {"clear_trusted_pdomains", wdctl_clear_trusted_wildcard_domains, NULL},
    {"show_trusted_pdomains", wdctl_show_trusted_wildcard_domains, NULL},
    {"clear_trusted_iplist", wdctl_clear_trusted_iplist, NULL},
    {"reparse_trusted_domains", wdctl_reparse_trusted_domains, NULL},
    {"clear_trusted_domains", wdctl_clear_trusted_domains, NULL},
    {"show_trusted_domains", wdctl_show_trusted_domains, NULL},
    {"show_roam_mac", wdctl_show_roam_maclist, NULL},
    {"clear_roam_mac", wdctl_clear_roam_maclist, NULL},
    {"show_trusted_mac", wdctl_show_trusted_maclist, NULL},
    {"clear_trusted_mac", wdctl_clear_trusted_maclist, NULL},
    {"show_trusted_local_mac", wdctl_show_trusted_local_maclist, NULL},
    {"clear_trusted_local_mac", wdctl_clear_trusted_local_maclist, NULL},
    {"show_untrusted_mac", wdctl_show_untrusted_maclist, NULL},
    {"clear_untrusted_mac", wdctl_clear_untrusted_maclist, NULL},
    {"user_cfg_save", wdctl_user_cfg_save, NULL},
    // has parameter
    {"reset", NULL, wdctl_reset},
    {"add_trusted_pdomains", NULL, wdctl_add_trusted_wildcard_domains},
    {"del_trusted_pdomains", NULL, wdctl_del_trusted_wildcard_domains},
    {"add_trusted_domains", NULL, wdctl_add_trusted_domains},
    {"del_trusted_domains", NULL, wdctl_del_trusted_domains},
    {"add_trusted_iplist", NULL, wdctl_add_trusted_iplist},
    {"del_trusted_iplist", NULL, wdctl_del_trusted_iplist},
    {"add_domain_ip", NULL, wdctl_add_domain_ip},
    {"add_roam_mac", NULL, wdctl_add_roam_maclist},
    {"add_trusted_mac", NULL, wdctl_add_trusted_maclist},
    {"del_trusted_mac", NULL, wdctl_del_trusted_maclist},
    {"add_trusted_local_mac", NULL, wdctl_add_trusted_local_maclist},
    {"del_trusted_local_mac", NULL, wdctl_del_trusted_local_maclist},
    {"add_untrusted_mac", NULL, wdctl_add_untrusted_maclist},
    {"del_untrusted_mac", NULL, wdctl_del_untrusted_maclist},
    {"add_online_client", NULL, wdctl_add_online_client},
    {"add_auth_client", NULL, wdctl_add_auth_client},
    {"set_local_portal", NULL, wdctl_set_local_portal},

    // apfree command
    {"user_list", wdctl_user_list, NULL},
    {"user_info", NULL, wdctl_user_info},
    {"user_auth", NULL, wdctl_user_auth},
    {"save_user", wdctl_save_user, NULL},
    {"restore_user", wdctl_restore_user, NULL},

    // hotplugin event
    {"hotplugin", NULL, wdctl_hotplugin_event},

    {"add_anti_nat_permit_device", NULL, wdctl_add_anti_nat_permit_device},
    {"del_anti_nat_permit_device", NULL, wdctl_del_anti_nat_permit_device},
    {"bpf_add", NULL, wdctl_bpf_add},
    {"bpf_del", NULL, wdctl_bpf_del},
    {"bpf_list", NULL, wdctl_bpf_list},
    {"bpf_flush", NULL, wdctl_bpf_flush},
    {"bpf_update_all", NULL, wdctl_bpf_update_all},
    {"bpf_update", NULL, wdctl_bpf_update},
};

static void 
wdctl_cmd_process(struct bufferevent *bev, const char *req)
{
    for (int i = 0; i < ARRAYLEN(wdctl_cmd); i++) {
        if (!strncmp(wdctl_cmd[i].command, req, strlen(wdctl_cmd[i].command))) {
            if (wdctl_cmd[i].process_cmd) {
                wdctl_cmd[i].process_cmd(bev);
            } else if (wdctl_cmd[i].process_param_cmd) {
                // 检查是否有参数
                const char *param_start = req + strlen(wdctl_cmd[i].command);
                if (*param_start == ' ') {
                    param_start++; // 跳过空格
                }
                // 如果参数为空或只是空格，传递空字符串
                if (*param_start == '\0' || *param_start == '\n' || *param_start == '\r') {
                    wdctl_cmd[i].process_param_cmd(bev, "");
                } else {
                    wdctl_cmd[i].process_param_cmd(bev, param_start);
                }
            }
            return;
        }
    }
    bufferevent_write(bev, UNSUPPORTED, strlen(UNSUPPORTED));
}

static struct sockaddr_un *
create_unix_socket(const char *sock_name)
{
    struct sockaddr_un *sa_un = malloc(sizeof(struct sockaddr_un));
    if (!sa_un) return NULL;
    memset(sa_un, 0, sizeof(struct sockaddr_un));

    if (!sock_name || strlen(sock_name) > (sizeof(sa_un->sun_path) - 1)) {
        /* TODO: Die handler with logging.... */
        debug(LOG_ERR, "WDCTL socket name too long");
        return NULL;
    }

    /* If it exists, delete... Not the cleanest way to deal. */
    unlink(sock_name);
    strcpy(sa_un->sun_path, sock_name);
    sa_un->sun_family = AF_UNIX;

    return sa_un;
}

static void 
wdctl_client_read_cb(struct bufferevent *bev, void *ctx)
{
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t nbytes =  evbuffer_get_length(input);
    if (!nbytes) return;

    char *buf = malloc(nbytes+1);
    if (!buf) return;
    memset(buf, 0, nbytes+1);

    if (evbuffer_remove(input, buf, nbytes) > 0) {
        wdctl_cmd_process(bev, buf);
    }
    free(buf);
}

static void
wdctl_client_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    if (what & BEV_EVENT_EOF) {
        evutil_closesocket(bufferevent_getfd(bev));
        bufferevent_free(bev);
    } else if (what & BEV_EVENT_ERROR) {
        debug(LOG_WARNING, "wdctl client connection error: %s", evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        evutil_closesocket(bufferevent_getfd(bev));
        bufferevent_free(bev);
    } else if (what & BEV_EVENT_TIMEOUT) {
        debug(LOG_DEBUG, "wdctl client connection timeout");
        evutil_closesocket(bufferevent_getfd(bev));
        bufferevent_free(bev);
    }
}

static void
wdctl_listen_new_client(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
    struct event_base *base = (struct event_base *)p;
    struct bufferevent *b_client = bufferevent_socket_new(
        base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    
    bufferevent_setcb(b_client, wdctl_client_read_cb, NULL, wdctl_client_event_cb, NULL);
    bufferevent_enable(b_client, EV_READ|EV_WRITE);
}

/** 
 * Launches a thread that monitors the control socket for request
 *  @param arg Must contain a pointer to a string containing the Unix domain socket to open
 */
void
thread_wdctl(void *arg)
{
    struct sockaddr_un *su_socket = create_unix_socket((char *)arg);
    if (!su_socket) termination_handler(0);
    free(arg);

    struct event_base *wdctl_base = event_base_new();
    if (!wdctl_base) termination_handler(0);

    if (get_auth_server()) {
        SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
        if (!ssl_ctx) termination_handler(0);

        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl) termination_handler(0);

        request_ctx = wd_request_context_new(
            wdctl_base, ssl, get_auth_server()->authserv_use_ssl);
        if (!request_ctx) termination_handler(0);
    }

    struct evconnlistener *listener = evconnlistener_new_bind(wdctl_base, wdctl_listen_new_client, wdctl_base,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
        -1, (struct sockaddr*)su_socket, sizeof(struct sockaddr_un));
    if (!listener) termination_handler(0);

    event_base_dispatch(wdctl_base);

    termination_handler(1);
}

static void
wdctl_status(struct bufferevent *fd, const char *arg)
{
    const char *type = arg;
    char *status = NULL;

    if (fw_counters_update())
	{
		debug(LOG_ERR, "Could not get counters from firewall!");
	}

    // Check if the connection is still valid before processing
    if (!fd || bufferevent_getfd(fd) < 0) {
        debug(LOG_WARNING, "Invalid client connection, skipping status response");
        return;
    }

    // 处理 arg 为 NULL 或空字符串的情况
    if (!type || strlen(type) == 0) {
        // 默认返回完整的文本状态
        status = get_status_text();
    } else if (!strcmp(type, "client")) {
        status = get_client_status_json();
    } else if (!strcmp(type, "auth")) {
        status = get_auth_status_json();
    } else if (!strcmp(type, "wifidogx")) {
        status = get_wifidogx_json();
    } else {
        // 未知参数，返回完整状态
        status = get_status_text();
    }

    if (status) {
        size_t len = strlen(status);
        int nret = bufferevent_write(fd, status, len);
        if (nret < 0) {
            debug(LOG_ERR, "Failed to write status response to client (client may have disconnected)");
        } else {
            debug(LOG_DEBUG, "Successfully sent status response (%zu bytes) to client", len);
        }
        free(status);
    } else {
        int nret = bufferevent_write(fd, "{}", 2);
        if (nret < 0) {
            debug(LOG_ERR, "Failed to write empty response to client (client may have disconnected)");
        }
    }
}

/** A bit of an hack, self kills.... */
/* coverity[+kill] */
static void
wdctl_stop(struct bufferevent *fd)
{
    bufferevent_write(fd, "Yes", 3);
    pid_t pid = getpid();
    kill(pid, SIGINT);
}

static void
wdctl_refresh(struct bufferevent *fd)
{
    bufferevent_write(fd, "Yes", 3);
    pid_t pid = getpid();
    kill(pid, SIGUSR1);
}

static void
wdctl_reset(struct bufferevent *fd, const char *arg)
{    
    if (!arg || strlen(arg) == 0) {
        bufferevent_write(fd, "No", 2);
        return;
    }

    t_client *node;

    LOCK_CLIENT_LIST();
    /* We get the node or return... */
    if ((node = client_list_find_by_ip(arg)) != NULL) ;
    else if ((node = client_list_find_by_mac(arg)) != NULL) ;
    else { 
        UNLOCK_CLIENT_LIST();
        debug(LOG_DEBUG, "Client not found.");
        bufferevent_write(fd, "No", 2);   /* Error handling in fucntion sufficient. */
        return;
    }
    UNLOCK_CLIENT_LIST();

    /* Immediately deny and remove the client locally, then save snapshot.
     * We avoid the async auth-server logout path here (ev_logout_client)
     * because wdctl reset should force immediate removal. */
    fw_deny(node);
    /* remove from client list and free */
    client_list_delete(node);

    /* Persist current client snapshot to disk */
    client_snapshot_save();

    bufferevent_write(fd, "Yes", 3);
}

void 
add_trusted_pdomains(const char *arg)
{
    parse_trusted_wildcard_domain_string(arg); 
    fw_set_wildcard_domains_trusted();
}

static void
wdctl_add_trusted_wildcard_domains(struct bufferevent *fd, const char *arg)
{
    add_trusted_pdomains(arg);
    bufferevent_write(fd, "Yes", 3);
}

void 
del_trusted_pdomains(const char *arg)
{
    debug(LOG_DEBUG, "Argument: %s ", arg);
   
    parse_del_trusted_wildcard_domain_string(arg);  
    fw_set_wildcard_domains_trusted();
}

static void
wdctl_del_trusted_wildcard_domains(struct bufferevent *fd, const char *arg)
{
    del_trusted_pdomains(arg);
}

void 
clear_trusted_pdomains(void)
{
    clear_trusted_wildcard_domains();
    fw_clear_wildcard_domains_trusted(); 
}

static void
wdctl_clear_trusted_wildcard_domains(struct bufferevent *fd)
{
    clear_trusted_pdomains();
}

char *
show_trusted_pdomains()
{
    return mqtt_get_trusted_wildcard_domains_text();
}

// todo
static void
wdctl_show_trusted_wildcard_domains(struct bufferevent *fd)
{
    char *status = get_trusted_wildcard_domains_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else 
        bufferevent_write(fd, "No", 2);

}

char *
show_trusted_iplist()
{
    return mqtt_get_trusted_iplist_text();
}

void 
add_trusted_iplist(const char *arg)
{
    add_trusted_ip_list(arg);
    fw_refresh_user_domains_trusted();  
}

static void
wdctl_add_trusted_iplist(struct bufferevent *fd, const char *arg)
{
    add_trusted_iplist(arg);
    bufferevent_write(fd, "Yes", 3);
}

void 
del_trusted_iplist(const char *arg)
{
    del_trusted_ip_list(arg);
    fw_refresh_user_domains_trusted();  
}

static void
wdctl_del_trusted_iplist(struct bufferevent *fd, const char *arg)
{
    del_trusted_iplist(arg);
    bufferevent_write(fd, "Yes", 3);
}

void 
clear_trusted_iplist(void)
{
    clear_trusted_ip_list();
    fw_refresh_user_domains_trusted();  
}

static void
wdctl_clear_trusted_iplist(struct bufferevent *fd)
{
    clear_trusted_iplist();
    bufferevent_write(fd, "Yes", 3);
}

void 
add_trusted_domains(const char *arg)
{
    parse_user_trusted_domain_string(arg);
    parse_user_trusted_domain_list();
}

static void
wdctl_add_trusted_domains(struct bufferevent *fd, const char *arg)
{
    add_trusted_domains(arg);
    bufferevent_write(fd, "Yes", 3);
}

void 
del_trusted_domains(const char *arg)
{
    parse_del_trusted_domain_string(arg);
    fw_refresh_user_domains_trusted();
}

static void
wdctl_del_trusted_domains(struct bufferevent *fd, const char *arg)
{
    del_trusted_domains(arg);
    bufferevent_write(fd, "Yes", 3);	
}

static void
wdctl_reparse_trusted_domains(struct bufferevent *fd)
{
    parse_user_trusted_domain_list();	
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_clear_trusted_domains(struct bufferevent *fd)
{
    clear_trusted_domains();
    fw_refresh_user_domains_trusted();
    bufferevent_write(fd, "Yes", 3);
}

char *
show_trusted_domains(void)
{
    return mqtt_get_trusted_domains_text();
}

static void
wdctl_show_trusted_domains(struct bufferevent *fd)
{
    char *status = get_trusted_domains_text();
    if(status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else 
        bufferevent_write(fd, "No", 2);
    
}

static void 
add_domain_ip(const char *args)
{
    add_domain_ip_pair(args, USER_TRUSTED_DOMAIN);
    fw_refresh_user_domains_trusted();  
}

static void
wdctl_add_domain_ip(struct bufferevent *fd, const char *args)
{
    add_domain_ip(args);
    bufferevent_write(fd, "Yes", 3);
}

// roam maclist
static void
wdctl_add_roam_maclist(struct bufferevent *fd, const char *args)
{
    LOCK_CONFIG();
    parse_roam_mac_list(args);	
    UNLOCK_CONFIG();
    
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_show_roam_maclist(struct bufferevent *fd)
{
    char *status = get_roam_maclist_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else {
        bufferevent_write(fd, "No", 2);
    }
}

static void
wdctl_clear_roam_maclist(struct bufferevent *fd)
{
    clear_roam_mac_list();
    fw_clear_roam_maclist();

    bufferevent_write(fd, "Yes", 3);
}

void 
del_trusted_maclist(const char *args)
{
    parse_del_trusted_mac_list(args);    
    fw_clear_trusted_maclist();
    fw_set_trusted_maclist();   
}

// trusted maclist
static void
wdctl_del_trusted_maclist(struct bufferevent *fd, const char *args)
{
    del_trusted_maclist(args);
    bufferevent_write(fd, "Yes", 3);

}

void 
add_trusted_maclist(const char *args)
{
    parse_trusted_mac_list(args);   
    fw_clear_trusted_maclist();
    fw_set_trusted_maclist();   
}

static void
wdctl_add_trusted_maclist(struct bufferevent *fd, const char *args)
{
    add_trusted_maclist(args);
    bufferevent_write(fd, "Yes", 3);
}

char *
show_trusted_maclist()
{
    return mqtt_get_serialize_maclist(TRUSTED_MAC);
}

static void
wdctl_show_trusted_maclist(struct bufferevent *fd)
{
    char *status = get_trusted_maclist_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else 
        bufferevent_write(fd, "No", 2);    
}

void
clear_trusted_maclist(void)
{
    clear_trusted_mac_list();   
    fw_clear_trusted_maclist();
}

static void
wdctl_clear_trusted_maclist(struct bufferevent *fd)
{
    clear_trusted_maclist();
    bufferevent_write(fd, "Yes", 3);
}

// trusted local maclist operation
void 
del_trusted_local_maclist(const char *args)
{
    parse_del_trusted_local_mac_list(args);      
    fw_clear_trusted_local_maclist();
    fw_set_trusted_local_maclist();   
}

// trusted maclist
static void
wdctl_del_trusted_local_maclist(struct bufferevent *fd, const char *args)
{
    del_trusted_local_maclist(args);
    bufferevent_write(fd, "Yes", 3);
}

void 
add_trusted_local_maclist(const char *args)
{
    parse_trusted_local_mac_list(args);     
    fw_clear_trusted_local_maclist();
    fw_set_trusted_local_maclist();   
}

static void
wdctl_add_trusted_local_maclist(struct bufferevent *fd, const char *args)
{
    add_trusted_local_maclist(args);
    bufferevent_write(fd, "Yes", 3);
}

char *
show_trusted_local_maclist()
{
    return mqtt_get_serialize_maclist(TRUSTED_LOCAL_MAC);
}

static void
wdctl_show_trusted_local_maclist(struct bufferevent *fd)
{
    char *status = get_trusted_local_maclist_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else 
        bufferevent_write(fd, "No", 2);
}

void
clear_trusted_local_maclist(void)
{
    clear_trusted_local_mac_list();   
    fw_clear_trusted_local_maclist();
}

static void
wdctl_clear_trusted_local_maclist(struct bufferevent *fd)
{
    clear_trusted_local_maclist();
    bufferevent_write(fd, "Yes", 3);
}

void
del_untrusted_maclist(const char *args)
{
    parse_del_untrusted_mac_list(args);      
    fw_clear_untrusted_maclist();   
    fw_set_untrusted_maclist();
}

// untrusted maclist
static void
wdctl_del_untrusted_maclist(struct bufferevent *fd, const char *args)
{
    del_untrusted_maclist(args);
    bufferevent_write(fd, "Yes", 3);
}

void
add_untrusted_maclist(const char *args)
{
    parse_untrusted_mac_list(args);        
    fw_clear_untrusted_maclist();   
    fw_set_untrusted_maclist();
}

static void
wdctl_add_untrusted_maclist(struct bufferevent *fd, const char *args)
{
    add_untrusted_maclist(args);
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_show_untrusted_maclist(struct bufferevent *fd)
{
    char *status = get_untrusted_maclist_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else
        bufferevent_write(fd, "No", 2);
    
}

void 
clear_untrusted_maclist(void)
{
    clear_untrusted_mac_list();  
    fw_clear_untrusted_maclist(); 
}

static void
wdctl_clear_untrusted_maclist(struct bufferevent *fd)
{
    clear_untrusted_maclist();
    bufferevent_write(fd, "Yes", 3);
}

/**
 * @brief save apfree wifidog' rule to /etc/config/wifidogx by uci 
 * this feature depends on openwrt system
 * 
 */ 
void
user_cfg_save(void)
{
    // todo
}

static void
wdctl_user_cfg_save(struct bufferevent *fd)
{
    user_cfg_save();	
    bufferevent_write(fd, "Yes", 3);
}

/**
 * @brief this interface should be called by dnsmasq by its new event
 * 
 * @args It's json of client's request like this:
 * {"mac":"device_mac", "ip":"device_ip"}
 * 
 */ 
static void
wdctl_add_online_client(struct bufferevent *fd, const char *args)
{  
    if (!request_ctx) {
        bufferevent_write(fd, no_auth_response, strlen(no_auth_response));
        return;
    }

    json_object *client_info = json_tokener_parse(args);
    if(is_error(client_info) || json_object_get_type(client_info) != json_type_object) { 
        goto OUT;
    }

    json_object *mac_jo = NULL;
    json_object *ip_jo 	= NULL;
    json_object *name_jo = NULL;
    if(!json_object_object_get_ex(client_info, "mac", &mac_jo) || 
       !json_object_object_get_ex(client_info, "ip", &ip_jo) || 
       !json_object_object_get_ex(client_info, "name", &name_jo)) { 
        goto OUT;
    }

    const char *mac  = json_object_get_string(mac_jo);
    const char *ip	 = json_object_get_string(ip_jo);
    if (!is_valid_mac(mac) || !is_valid_ip(ip) || !is_trusted_mac(mac))
        goto OUT;

    struct roam_req_info *roam = safe_malloc(sizeof(struct roam_req_info));
    memcpy(roam->ip, ip, strlen(ip));
    memcpy(roam->mac, mac, strlen(mac));
    make_roam_request(request_ctx, roam);
    
OUT:
    if (client_info) json_object_put(client_info);
    bufferevent_write(fd, "Yes", 3);
}

/**
 *@brief add auth client for testing
 *
 */
static void
wdctl_add_auth_client(struct bufferevent *fd, const char *args)
{
    json_object *client_info = json_tokener_parse(args);
    if(is_error(client_info) || json_object_get_type(client_info) != json_type_object) { 
        debug(LOG_ERR, "json_tokener_parse failed: args is %s", args);
        goto OUT;
    }

    json_object *mac_jo = NULL;
    json_object *ip_jo 	= NULL;
    if(!json_object_object_get_ex(client_info, "mac", &mac_jo) || 
       !json_object_object_get_ex(client_info, "ip", &ip_jo)) { 
        debug(LOG_ERR, "json_object_object_get_ex failed");
        goto OUT;
    }

    const char *mac  = json_object_get_string(mac_jo);
    const char *ip	 = json_object_get_string(ip_jo);
    if (!is_valid_mac(mac) || 
        !(is_valid_ip(ip) || is_valid_ip6(ip)) ) {
        debug(LOG_ERR, "is_valid_mac or is_valid_ip failed");
        goto OUT;
    }

    /* Determine which gateway setting this client belongs to. Prefer matching
     * by IP/network, then by interface, then fall back to head of gateway
     * list if nothing matches. */
    t_gateway_setting *gw = NULL;
    int addr_type = 0; /* 1 = ipv4, 2 = ipv6 */
    if (is_valid_ip(ip)) addr_type = 1;
    else if (is_valid_ip6(ip)) addr_type = 2;

    if (addr_type != 0) {
        gw = get_gateway_setting_by_addr(ip, addr_type);
    }

    if (!gw) {
        debug(LOG_WARNING, "wdctl_add_auth_client: cannot determine gateway for %s, using default settings", ip);
        gw = get_gateway_settings();
    }

    /* Add client to client list; token is not available for wdctl command
     * client_list_add() inserts at head and expects the caller to hold the
     * client list lock. Acquire the lock to avoid races. */
    t_client *client = NULL;
    LOCK_CLIENT_LIST();
    client = client_list_add(ip, mac, NULL, gw);
    UNLOCK_CLIENT_LIST();
    if (!client) {
        debug(LOG_ERR, "wdctl_add_auth_client: failed to add client %s %s", ip, mac);
        goto OUT;
    }

    client->is_online = 1;
    if (fw_allow(client, FW_MARK_KNOWN) != 0) {
        debug(LOG_WARNING, "wdctl_add_auth_client: fw_allow failed for %s %s", ip, mac);
    } else {
        client_snapshot_save();
        debug(LOG_INFO, "wdctl_add_auth_client: client %s %s added, allowed and snapshot saved", ip, mac);
    }
    
OUT:
    if (client_info) json_object_put(client_info);
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_set_local_portal(struct bufferevent *fd, const char *portal)
{
    s_config *config = config_get_config();
    char *old_local_portal = NULL;

    if (!config || !portal || *portal == '\0') {
        bufferevent_write(fd, "Error: missing local portal URL", strlen("Error: missing local portal URL"));
        return;
    }

    if (config->auth_server_mode != AUTH_MODE_LOCAL) {
        bufferevent_write(fd, "Error: local portal can only be changed in local mode", strlen("Error: local portal can only be changed in local mode"));
        return;
    }

    char *new_local_portal = safe_strdup(portal);
    if (!new_local_portal) {
        bufferevent_write(fd, "Error: failed to allocate local portal", strlen("Error: failed to allocate local portal"));
        return;
    }

    if (uci_set_value("wifidogx", "common", "local_portal", portal) != 0) {
        free(new_local_portal);
        bufferevent_write(fd, "Error: failed to save local portal to UCI", strlen("Error: failed to save local portal to UCI"));
        return;
    }

    LOCK_CONFIG();
    old_local_portal = config->local_portal;
    config->local_portal = new_local_portal;
    UNLOCK_CONFIG();

    if (old_local_portal) {
        free(old_local_portal);
    }

    debug(LOG_INFO, "Local portal updated to %s", portal);
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_user_list(struct bufferevent *fd)
{
    char *json_user_list = client_snapshot_dump_json();
    if (json_user_list) {
        size_t len = strlen(json_user_list);
        bufferevent_write(fd, json_user_list, len);
        free(json_user_list);
    } else
        bufferevent_write(fd, "{}", 2);
}

static void
wdctl_save_user(struct bufferevent *fd)
{
    client_snapshot_save();
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_restore_user(struct bufferevent *fd)
{
    LOCK_CLIENT_LIST();
    __client_snapshot_load();
    UNLOCK_CLIENT_LIST();
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_user_info(struct bufferevent *fd, const char *args)
{
    if (!is_valid_ip(args)) {
        bufferevent_write(fd, "{}", 2);
        return;
    }
}

static void
wdctl_user_auth(struct bufferevent *fd, const char *json_value)
{
    json_object *root = json_tokener_parse(json_value);
    if (!root || json_object_get_type(root) != json_type_object) {
        debug(LOG_ERR, "Failed to parse json value: %s", json_value);
        goto OUT;
    }

    json_object *user_array = NULL;
    if (!json_object_object_get_ex(root, "user", &user_array) ||
        json_object_get_type(user_array) != json_type_array) {
        debug(LOG_ERR, "Failed to get user array");
        goto OUT;
    }

    // iterate over the user array
    for (int i = 0; i < json_object_array_length(user_array); i++) {
        json_object *user = json_object_array_get_idx(user_array, i);
        if (!user) {
            debug(LOG_ERR, "User array is empty");
            continue;
        }

        json_object *serial_jo = NULL;
        json_object *time_jo = NULL;
        json_object *mac_jo = NULL;
        json_object *nat_jo = NULL;

        if (!json_object_object_get_ex(user, "serial", &serial_jo) ||
            !json_object_object_get_ex(user, "time", &time_jo) ||
            !json_object_object_get_ex(user, "mac", &mac_jo) ||
            !json_object_object_get_ex(user, "nat", &nat_jo)) {
            debug(LOG_ERR, "Failed to get required fields from user object");
            continue;
        }

        const char *serial = json_object_get_string(serial_jo);
        const char *time_str = json_object_get_string(time_jo);
        const char *mac = json_object_get_string(mac_jo);
        const char *nat = json_object_get_string(nat_jo);           

        debug(LOG_DEBUG, "Parsed values - serial: %s, time: %s, mac: %s, nat: %s",
              serial, time_str, mac, nat);
        uint32_t remaining_time = atoi(time_str);
        uint16_t anti_nat = atoi(nat);
        if (remaining_time == 0) {
            client_snapshot_remove_trusted_mac(mac);
        } else {
            client_snapshot_add_trusted_mac(mac, remaining_time, serial);
            if (anti_nat) {
                fw_add_anti_nat_permit_device(mac); 
            }
        }
    }

OUT:
    if (root) json_object_put(root);
    client_snapshot_save();
    
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_add_anti_nat_permit_device(struct bufferevent *fd, const char *mac)
{
    if (!is_valid_mac(mac)) {
        debug(LOG_ERR, "Invalid mac address: %s", mac);
        return;
    }

    fw_add_anti_nat_permit_device(mac);
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_del_anti_nat_permit_device(struct bufferevent *fd, const char *mac)
{
    if (!is_valid_mac(mac)) {
        debug(LOG_ERR, "Invalid mac address: %s", mac);
        return;
    }

    fw_del_anti_nat_permit_device(mac);
    bufferevent_write(fd, "Yes", 3);
}

static void 
wdctl_hotplugin_event(struct bufferevent *fd, const char *event_json_data) {
    hotplug_handle_event(fd, event_json_data);
}

static int wdctl_send_response_func(api_transport_context_t *transport, const char *message, size_t length)
{
    struct bufferevent *bev = (struct bufferevent *)transport->transport_ctx;
    if (bev) {
        bufferevent_write(bev, message, length);
        return 0;
    }
    return -1;
}

static void wdctl_bpf_add(struct bufferevent *fd, const char *args) {
    char table[16], addr[64];
    if (sscanf(args, "%15s %63s", table, addr) != 2) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    json_object_object_add(j_req, "address", json_object_new_string(addr));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_add_request(j_req, &transport);
    json_object_put(j_req);
}

static void wdctl_bpf_del(struct bufferevent *fd, const char *args) {
    char table[16], addr[64];
    if (sscanf(args, "%15s %63s", table, addr) != 2) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    json_object_object_add(j_req, "address", json_object_new_string(addr));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_del_request(j_req, &transport);
    json_object_put(j_req);
}

static void wdctl_bpf_flush(struct bufferevent *fd, const char *args) {
    char table[16];
    if (sscanf(args, "%15s", table) != 1) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_flush_request(j_req, &transport);
    json_object_put(j_req);
}

static void wdctl_bpf_list(struct bufferevent *fd, const char *args) {
    char table[16];
    if (sscanf(args, "%15s", table) != 1) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_json_request(j_req, &transport);
    json_object_put(j_req);
}

static void wdctl_bpf_update(struct bufferevent *fd, const char *args) {
    char table[16], target[64];
    long long down, up;
    if (sscanf(args, "%15s %63s %lld %lld", table, target, &down, &up) != 4) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    json_object_object_add(j_req, "target", json_object_new_string(target));
    json_object_object_add(j_req, "downrate", json_object_new_int64(down));
    json_object_object_add(j_req, "uprate", json_object_new_int64(up));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_update_request(j_req, &transport);
    json_object_put(j_req);
}

static void wdctl_bpf_update_all(struct bufferevent *fd, const char *args) {
    char table[16];
    long long down, up;
    if (sscanf(args, "%15s %lld %lld", table, &down, &up) != 3) return;
    
    json_object *j_req = json_object_new_object();
    json_object_object_add(j_req, "table", json_object_new_string(table));
    json_object_object_add(j_req, "downrate", json_object_new_int64(down));
    json_object_object_add(j_req, "uprate", json_object_new_int64(up));
    
    api_transport_context_t transport = { .transport_ctx = fd, .send_response = wdctl_send_response_func };
    handle_bpf_update_all_request(j_req, &transport);
    json_object_put(j_req);
}
