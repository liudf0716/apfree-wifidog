/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file wdctl_thread.c
    @brief Monitoring and control of wifidog, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
	@author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#define _GNU_SOURCE

#include "common.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"
#include "wd_client.h"

static struct sockaddr_un *create_unix_socket(const char *);

static void wdctl_status(struct bufferevent *);
static void wdctl_stop(struct bufferevent *);
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

static struct wd_request_context *request_ctx;

static struct wdctl_command {
    const char *command;
    void (*process_cmd)(struct bufferevent *bev);
    void (*process_param_cmd)(struct bufferevent *bev, const char *param);
} wdctl_cmd[] = {
    {"status", wdctl_status, NULL},
    {"stop", wdctl_stop, NULL},
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
	struct bufferevent *b_client = bufferevent_socket_new(
        request_ctx->base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    
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
	
	struct event_base *wdctl_base = event_base_new();
    if (!wdctl_base) termination_handler(0);

    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) termination_handler(0);

    SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) termination_handler(0);

    request_ctx = wd_request_context_new(
        wdctl_base, ssl, get_auth_server()->authserv_use_ssl);
	if (!request_ctx) termination_handler(0);

    struct evconnlistener *listener = evconnlistener_new_bind(wdctl_base, wdctl_listen_new_client, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)su_socket, sizeof(struct sockaddr_un));
    if (!listener) termination_handler(0);

    event_base_dispatch(wdctl_base);

    termination_handler(1);
}

static void
wdctl_status(struct bufferevent *fd)
{
    char *status = get_status_text();
    if (status) {
        size_t len = strlen(status);
        bufferevent_write(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */
        free(status);
    } else 
        bufferevent_write(fd, "No", 2);  
}

/** A bit of an hack, self kills.... */
/* coverity[+kill] */
static void
wdctl_stop(struct bufferevent *fd)
{
    pid_t pid = getpid();
    kill(pid, SIGINT);
}

static void
wdctl_reset(struct bufferevent *fd, const char *arg)
{
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

void 
clear_trusted_domains()
{
    clear_trusted_domains_();
    fw_refresh_user_domains_trusted();
}

static void
wdctl_clear_trusted_domains(struct bufferevent *fd)
{
	clear_trusted_domains();
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
	LOCK_CONFIG();
	__clear_roam_mac_list();		
	UNLOCK_CONFIG();	

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
    iptables_fw_save_online_clients();
    
    const char *trusted_maclist     	= get_serialize_maclist(TRUSTED_MAC);
	const char *trusted_local_maclist	= get_serialize_maclist(TRUSTED_LOCAL_MAC);
    const char *untrusted_maclist   	= get_serialize_maclist(UNTRUSTED_MAC);
    const char *trusted_domains     	= get_serialize_trusted_domains();
    const char *trusted_iplist      	= get_serialize_iplist();
    const char *trusted_pan_domains 	= get_serialize_trusted_pan_domains();

    if(trusted_pan_domains) {
        uci_set_value("wifidogx", "wifidog", "trusted_pan_domains", trusted_pan_domains);
    } else {
        uci_del_value("wifidogx", "wifidog", "trusted_pan_domains");
    }
    
    if(trusted_domains) {
        uci_set_value("wifidogx", "wifidog", "trusted_domains", trusted_domains);
    } else {
        uci_del_value("wifidogx", "wifidog", "trusted_domains");
    }
    
    if(trusted_iplist) {
        uci_set_value("wifidogx", "wifidog", "trusted_iplist", trusted_iplist);
    } else {
        uci_del_value("wifidogx", "wifidog", "trusted_iplist");
    }
    
    if(trusted_maclist) {
        uci_set_value("wifidogx", "wifidog", "trusted_maclist", trusted_maclist);
    } else {
        uci_del_value("wifidogx", "wifidog", "trusted_maclist");
    }
    
	if(trusted_local_maclist) {
        uci_set_value("wifidogx", "wifidog", "trusted_local_maclist", trusted_local_maclist);
    } else {
        uci_del_value("wifidogx", "wifidog", "trusted_local_maclist");
    }
	
    if(untrusted_maclist) {
        uci_set_value("wifidogx", "wifidog", "untrusted_maclist", untrusted_maclist);
    } else {
        uci_del_value("wifidogx", "wifidog", "untrusted_maclist");
    }
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
    json_object *name_jo = NULL;
    if(!json_object_object_get_ex(client_info, "mac", &mac_jo) || 
	   !json_object_object_get_ex(client_info, "ip", &ip_jo) || 
	   !json_object_object_get_ex(client_info, "name", &name_jo)) { 
        debug(LOG_ERR, "json_object_object_get_ex failed");
        goto OUT;
    }

    const char *mac  = json_object_get_string(mac_jo);
    const char *ip	 = json_object_get_string(ip_jo);
    if (!is_valid_mac(mac) || !is_valid_ip(ip) || !is_trusted_mac(mac)) {
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
