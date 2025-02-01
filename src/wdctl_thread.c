
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
#include "wdctl_thread.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"
#include "wd_client.h"

static struct sockaddr_un *create_unix_socket(const char *);

static void wdctl_status(struct bufferevent *, const char *);
static void wdctl_stop(struct bufferevent *);
static void wdctl_refresh(struct bufferevent *);
static void wdctl_clear_trusted_pan_domains(struct bufferevent *);
static void wdctl_show_trusted_pan_domains(struct bufferevent *);
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
static void wdctl_add_trusted_pan_domains(struct bufferevent *, const char *);
static void wdctl_del_trusted_pan_domains(struct bufferevent *, const char *);
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

static void wdctl_user_list(struct bufferevent *);
static void wdctl_user_info(struct bufferevent *, const char *);
static void wdctl_user_auth(struct bufferevent *, const char *);
static void wdctl_save_user(struct bufferevent *);
static void wdctl_restore_user(struct bufferevent *);
static void wdctl_add_anti_nat_permit_device(struct bufferevent *, const char *mac);
static void wdctl_del_anti_nat_permit_device(struct bufferevent *, const char *mac);

static void wdctl_hotplugin_event(struct bufferevent *fd, const char *event);

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
    {"clear_trusted_pdomains", wdctl_clear_trusted_pan_domains, NULL},
    {"show_trusted_pdomains", wdctl_show_trusted_pan_domains, NULL},
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
    {"add_trusted_pdomains", NULL, wdctl_add_trusted_pan_domains},
    {"del_trusted_pdomains", NULL, wdctl_del_trusted_pan_domains},
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
};

static void 
wdctl_cmd_process(struct bufferevent *bev, const char *req)
{
    for (int i = 0; i < ARRAYLEN(wdctl_cmd); i++) {
        if (!strncmp(wdctl_cmd[i].command, req, strlen(wdctl_cmd[i].command))) {
            if (wdctl_cmd[i].process_cmd) {
                wdctl_cmd[i].process_cmd(bev);
            } else if (wdctl_cmd[i].process_param_cmd) {
                wdctl_cmd[i].process_param_cmd(bev, req + strlen(wdctl_cmd[i].command) + 1);
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
    if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {     
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

#ifdef AW_FW3
	if (-1 == iptables_fw_counters_update()) 
#else
	if (-1 == nft_fw_counters_update()) 
#endif
	{
		debug(LOG_ERR, "Could not get counters from firewall!");
	}

    if (!strcmp(type, "client")) {
        status = get_client_status_json();
    } else if (!strcmp(type, "auth")) {
        status = get_auth_status_json();
    } else if (!strcmp(type, "wifidogx")) {
        status = get_wifidogx_json();
    } else {
        status = get_status_text();
    }

    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);
        free(status);
    } else {
        bufferevent_write(fd, "{}", 2);
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
    if (!request_ctx) {
        bufferevent_write(fd, no_auth_response, strlen(no_auth_response));
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

    /* deny.... */
    ev_logout_client(request_ctx, node);
    bufferevent_write(fd, "Yes", 3);
}

void 
add_trusted_pdomains(const char *arg)
{
    parse_trusted_pan_domain_string(arg); 
    fw_set_pan_domains_trusted();
}

static void
wdctl_add_trusted_pan_domains(struct bufferevent *fd, const char *arg)
{
    add_trusted_pdomains(arg);
    bufferevent_write(fd, "Yes", 3);
}

void 
del_trusted_pdomains(const char *arg)
{
    debug(LOG_DEBUG, "Argument: %s ", arg);
   
    parse_del_trusted_pan_domain_string(arg);  
    fw_set_pan_domains_trusted();
}

static void
wdctl_del_trusted_pan_domains(struct bufferevent *fd, const char *arg)
{
    del_trusted_pdomains(arg);
}

void 
clear_trusted_pdomains(void)
{
    clear_trusted_pan_domains();
    fw_clear_pan_domains_trusted(); 
}

static void
wdctl_clear_trusted_pan_domains(struct bufferevent *fd)
{
    clear_trusted_pdomains();
}

char *
show_trusted_pdomains()
{
    return mqtt_get_trusted_pan_domains_text();
}

// todo
static void
wdctl_show_trusted_pan_domains(struct bufferevent *fd)
{	
    char *status = get_trusted_pan_domains_text();
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
 * {"mac":"device_mac", "ip":"device_ip", "name":"device_name"}
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
    if (!request_ctx) {
        bufferevent_write(fd, no_auth_response, strlen(no_auth_response));
        return;
    }
    
    json_object *client_info = json_tokener_parse(args);
    if(is_error(client_info) || json_object_get_type(client_info) != json_type_object) { 
        debug(LOG_ERR, "json_tokener_parse failed: args is %s", args);
        goto OUT;
    }

    json_object *mac_jo = NULL;
    json_object *ip_jo 	= NULL;
    json_object *name_jo = NULL;
    if(!json_object_object_get_ex(client_info, "mac", &mac_jo) || 
       !json_object_object_get_ex(client_info, "ip", &ip_jo) || 
       !json_object_object_get_ex(client_info, "name", &name_jo)) { 
        debug(LOG_ERR, "json_object_object_get_ex failed");
        goto OUT;
    }

    const char *mac  = json_object_get_string(mac_jo);
    const char *ip	 = json_object_get_string(ip_jo);
    if (!is_valid_mac(mac) || 
        !(is_valid_ip(ip) && is_valid_ip6(ip)) || 
        !is_trusted_mac(mac)) {
        debug(LOG_ERR, "is_valid_mac or is_valid_ip or is_trusted_mac failed");
        goto OUT;
    }

    auth_req_info *auth = safe_malloc(sizeof(auth_req_info));
    memcpy(auth->ip, ip, strlen(ip));
    memcpy(auth->mac, mac, strlen(mac));
    make_auth_request(request_ctx, auth);
    
OUT:
    if (client_info) json_object_put(client_info);
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_user_list(struct bufferevent *fd)
{
    char *json_user_list = dump_bypass_user_list_json();
    if (json_user_list) {
        size_t len = strlen(json_user_list);
        bufferevent_write(fd, json_user_list, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(json_user_list);
    } else
        bufferevent_write(fd, "{}", 2);
}

static void
wdctl_save_user(struct bufferevent *fd)
{
    save_bypass_user_list();
    bufferevent_write(fd, "Yes", 3);
}

static void
wdctl_restore_user(struct bufferevent *fd)
{
    load_bypass_user_list();
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
        uint16_t remaining_time = atoi(time_str);
        uint16_t anti_nat = atoi(nat);
        if (remaining_time == 0) {
            remove_bypass_user(mac);
        } else {
            add_bypass_user(mac, remaining_time, serial);
            if (anti_nat) {
                fw_add_anti_nat_permit_device(mac);
            }
        }
    }

OUT:
    if (root) json_object_put(root);
    save_bypass_user_list();
    
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

// Helper function to parse IP address string into components
static bool 
parse_ip_address(const char *ip_str, unsigned int *parts) {
    if (!ip_str || !parts) return false;
    return sscanf(ip_str, "%u.%u.%u.%u", &parts[0], &parts[1], &parts[2], &parts[3]) == 4;
}

// Helper function to check network conflict
static bool 
check_network_conflict(const unsigned int *net1, const unsigned int *net2) {
    if (!net1 || !net2) return false;
    for (int i = 0; i < 4; i++) {
        if (net1[i] != net2[i]) return false;
    }
    return true;
}

// Helper function to get network configuration using UCI
static bool 
get_network_config(char *ip, size_t ip_size, char *mask, size_t mask_size) {
    char cmd[256];
    FILE *fp;
    bool success = true;

    // Get LAN IP
    snprintf(cmd, sizeof(cmd), "uci -q get network.lan.ipaddr");
    if (!(fp = popen(cmd, "r")) || !fgets(ip, ip_size, fp)) {
        debug(LOG_ERR, "Failed to get LAN IP address");
        success = false;
    }
    if (fp) pclose(fp);
    if (success) ip[strcspn(ip, "\n")] = 0;

    // Get netmask
    if (success) {
        snprintf(cmd, sizeof(cmd), "uci -q get network.lan.netmask");
        if (!(fp = popen(cmd, "r")) || !fgets(mask, mask_size, fp)) {
            debug(LOG_ERR, "Failed to get LAN netmask");
            success = false;
        }
        if (fp) pclose(fp);
        if (success) mask[strcspn(mask, "\n")] = 0;
    }

    return success;
}

static void 
wdctl_hotplugin_event(struct bufferevent *fd, const char *event_json_data) {
    json_object *root = NULL;
    bool success = true;
    char *wan_ip = NULL;

    if (!is_openwrt_platform()) {
        debug(LOG_INFO, "Hotplugin events are only supported on OpenWrt platform");
        bufferevent_write(fd, "Not Support", strlen("Not Support"));
        return;
    }

    // Parse JSON
    root = json_tokener_parse(event_json_data);
    if (!root || json_object_get_type(root) != json_type_object) {
        debug(LOG_ERR, "Failed to parse event json data: %s", event_json_data);
        success = false;
        goto cleanup;
    }

    // Extract JSON fields
    json_object *interface_jo = NULL, *action_jo = NULL, *device_jo = NULL;
    if (!json_object_object_get_ex(root, "interface", &interface_jo) ||
        !json_object_object_get_ex(root, "action", &action_jo) ||
        !json_object_object_get_ex(root, "device", &device_jo)) {
        debug(LOG_ERR, "Missing required fields in event json");
        success = false;
        goto cleanup;
    }

    const char *interface = json_object_get_string(interface_jo);
    const char *action = json_object_get_string(action_jo);
    const char *device = json_object_get_string(device_jo);

    // Only process WWAN or WAN interface up events
    if ((strcmp(interface, "wwan") != 0 && strcmp(interface, "wan") != 0) || strcmp(action, "ifup") != 0) {
        debug(LOG_DEBUG, "Ignoring event for interface %s action %s", interface, action);
        goto cleanup;
    }

    // Get IP configurations
    wan_ip = get_iface_ip(device);
    char lan_ip[16] = {0}, lan_mask[16] = {0};
    if (!wan_ip || !get_network_config(lan_ip, sizeof(lan_ip), lan_mask, sizeof(lan_mask))) {
        debug(LOG_ERR, "Failed to get network configuration");
        success = false;
        goto cleanup;
    }

    // Parse IP addresses
    unsigned int wwan_ip_parts[4], lan_ip_parts[4], mask_parts[4];
    unsigned int wwan_network[4], lan_network[4];
    
    if (!parse_ip_address(wan_ip, wwan_ip_parts) ||
        !parse_ip_address(lan_ip, lan_ip_parts) ||
        !parse_ip_address(lan_mask, mask_parts)) {
        debug(LOG_ERR, "Failed to parse IP addresses");
        success = false;
        goto cleanup;
    }

    // Calculate network addresses
    for (int i = 0; i < 4; i++) {
        wwan_network[i] = wwan_ip_parts[i] & mask_parts[i];
        lan_network[i] = lan_ip_parts[i] & mask_parts[i];
    }

    // Handle network conflict
    if (check_network_conflict(wwan_network, lan_network)) {
        debug(LOG_NOTICE, "Network conflict detected, adjusting LAN IP");
        
        // Increment third octet with overflow handling
        lan_ip_parts[2] = (lan_ip_parts[2] + 1) % 256;
        if (lan_ip_parts[2] == 0) {
            lan_ip_parts[1] = (lan_ip_parts[1] + 1) % 256;
        }

        char cmd[256], new_ip[16];
        snprintf(new_ip, sizeof(new_ip), "%u.%u.%u.%u", 
                lan_ip_parts[0], lan_ip_parts[1], 
                lan_ip_parts[2], lan_ip_parts[3]);

        snprintf(cmd, sizeof(cmd), "uci set network.lan.ipaddr='%s' && uci commit network && reboot",
                new_ip);
        
        if (system(cmd) != 0) {
            debug(LOG_ERR, "Failed to update network configuration");
            success = false;
            goto cleanup;
        }

        debug(LOG_NOTICE, "Changed LAN IP to %s", new_ip);
    }

cleanup:
    if (root) json_object_put(root);
    if (wan_ip) free(wan_ip);
    bufferevent_write(fd, success ? "Yes" : "No", success ? 3 : 2);
}