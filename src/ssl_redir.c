/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file https_server.c
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com.cn>
  */

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>

#include "common.h"
#include "ssl_redir.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "wd_util.h"
#include "util.h"
#include "firewall.h"
#include "safe.h"
#include "wd_client.h"
#include "http.h"

static struct event_base *base		= NULL;
static struct evdns_base *dnsbase 	= NULL;

static void check_internet_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr);

static void 
die_most_horribly_from_openssl_error (const char *func) { 
	debug (LOG_ERR,  "%s failed:\n", func);
	termination_handler(0);
}

/**
 * @brief the main
 * 
 */ 
static void
process_ssl_request_cb (struct evhttp_request *req, void *arg) {  
	if (!is_online()){
        ev_http_reply_client_error(req, INTERNET_OFFLINE, NULL, NULL, NULL, NULL, NULL);
        return;
    }  

    char *remote_host;
    uint16_t port;
    ev_http_connection_get_peer(evhttp_request_get_connection(req), &remote_host, &port);
	if (!remote_host) {
		evhttp_send_error(req, 200, "Cant get client's ip");
		return;
	}

	struct bufferevent *bev = evhttp_connection_get_bufferevent(evhttp_request_get_connection(req));
    evutil_socket_t fd = bufferevent_getfd(bev);
    if (fd < 0) {
        debug(LOG_ERR, "evhttp_connection_get_fd failed: %s", strerror(errno));
        evhttp_send_error(req, 200, "Cant get client's fd");
        return;
    }

    char if_name[IFNAMSIZ] = {0};
    if (!get_ifname_by_address(remote_host, if_name)) {
        debug(LOG_ERR, "get_ifname_by_address [%s] failed", remote_host);
        evhttp_send_error(req, 200, "Cant get client's interface name");
        return;
    }
	if_name[IFNAMSIZ-1] = '\0';
    t_gateway_setting *gw_setting = get_gateway_setting_by_ifname(if_name);
    if (!gw_setting) {
        debug(LOG_ERR, "get_gateway_setting_by_ifname [%s] failed", if_name);
        evhttp_send_error(req, 200, "Cant get gateway setting by interface name");
        return;
    }

    char mac[MAC_LENGTH] = {0};
    if(!br_arp_get_mac(gw_setting, remote_host, mac)) {
        evhttp_send_error(req, 200, "Cant get client's mac by its ip");
        return;
    }

	s_config *config = config_get_config();
	if (!is_auth_online() || config->auth_server_mode == 2) {
		debug(LOG_INFO, "Auth server is offline");
		char gw_https_port[8] = {0};
		snprintf(gw_https_port, sizeof(gw_https_port), "%d", config_get_config()->gw_https_port);
        ev_http_reply_client_error(req, AUTHSERVER_OFFLINE, 
			gw_setting->gw_address_v4?gw_setting->gw_address_v4:gw_setting->gw_address_v6, 
			gw_https_port, "https", remote_host, mac);
        return;
    }
	
	char *redir_url = wd_get_redir_url_to_auth(req, gw_setting, mac, remote_host, config->gw_https_port, config->device_id, 1);
    if (!redir_url) {
        evhttp_send_error(req, 200, "Cant get client's redirect to auth server's url");
        return;
    }

	if (config->js_redir)
        ev_http_send_js_redirect(req, redir_url);
	else
        ev_http_send_redirect(req, redir_url, "Redirect to login page");

	free(redir_url);
}

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent* 
ssl_bevcb (struct event_base *base, void *arg) { 
  	SSL_CTX *ctx = (SSL_CTX *) arg;
  	return bufferevent_openssl_socket_new (base, -1,
                SSL_new (ctx), BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
}

static void 
server_setup_certs (SSL_CTX *ctx, const char *certificate_chain, const char *private_key) { 
  	if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_certificate_chain_file");

  	if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");

  	if (1 != SSL_CTX_check_private_key (ctx))
    	die_most_horribly_from_openssl_error ("SSL_CTX_check_private_key");
}

/**
 * @brief check internet Ok or not
 * 
 */ 
static void 
check_internet_available(t_popular_server *popular_server) {
	if (!popular_server)
		return;

	mark_offline_time();

	struct evutil_addrinfo hints;
	memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
	
	evdns_getaddrinfo( dnsbase, popular_server->hostname, NULL ,
          &hints, check_internet_available_cb, popular_server);
	
}

/**
 * @brief Callback function to check whether internet OK or not
 * 
 */
static void 
check_internet_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr) {
	if (errcode) { 
		t_popular_server *popular_server = ptr;
		debug (LOG_ERR, "dns query error : %s", evutil_gai_strerror(errcode));
		if (popular_server)
			check_internet_available(popular_server->next);
	} else {
		if (addr) {
			// popular server dns resolve success
			debug (LOG_DEBUG, "Internet is available, mark online !\n");
			mark_online();
			evutil_freeaddrinfo(addr);
		}
	}
}

static int
is_address_exist(t_ip_trusted **ips, const char *ip, int family) {
	t_ip_trusted *ipt = *ips;
	int ip_len = strlen(ip);
	while(ipt) {
		int ipt_len = strlen(ipt->ip);
		debug(LOG_INFO, "ip [%s] ipt->ip [%s]", ip, ipt->ip);
		if (ipt_len == ip_len && !strncmp(ipt->ip, ip, ip_len)) {
			debug(LOG_INFO, "ip [%s] already exist", ip);
			return 1;
		}
		ipt = ipt->next;
	}

	t_ip_trusted *new_ip = (t_ip_trusted *)safe_malloc(sizeof(t_ip_trusted));
	snprintf(new_ip->ip, (family == AF_INET)?INET_ADDRSTRLEN:INET6_ADDRSTRLEN, "%s", ip);
	new_ip->ip_type = (family == AF_INET)?IP_TYPE_IPV4:IP_TYPE_IPV6;
	new_ip->next = *ips;
	*ips = new_ip;

	return 0;
}

/**
 * @brief Callback function to check whether auth server's ip changed or not
 * 
 */ 
static void 
check_auth_server_available_cb(int errcode, struct evutil_addrinfo *res, void *ptr) {
	t_auth_serv *auth_server = (t_auth_serv *)ptr;
	t_ip_trusted **ips_auth_server = &auth_server->ips_auth_server;
	if (errcode || !res) { 
		debug (LOG_INFO, "dns query error : %s", evutil_gai_strerror(errcode));
		mark_auth_offline();
		mark_auth_server_bad(auth_server);
		return;
	}

	struct evutil_addrinfo *addr = res;
	for (; addr != NULL; addr = addr->ai_next) {
		if (addr->ai_family == PF_INET) {
			char ip[INET_ADDRSTRLEN] = {0};
			struct sockaddr_in *sin = (struct sockaddr_in*)addr->ai_addr;
			evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, INET_ADDRSTRLEN-1);
			if (is_address_exist(ips_auth_server, ip, AF_INET)) {
				continue;
			}
			if (auth_server->last_ip) {
				free(auth_server->last_ip);
			}
			auth_server->last_ip = safe_strdup(ip);
			fw_set_authservers();
		} else if (addr->ai_family == PF_INET6) {
			char ip[INET6_ADDRSTRLEN] = {0};
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)addr->ai_addr;
			evutil_inet_ntop(AF_INET6, &sin6->sin6_addr, ip, INET6_ADDRSTRLEN-1);
			if (is_address_exist(ips_auth_server, ip, AF_INET6)) {
				continue;
			}
			if (auth_server->last_ip) {
				free(auth_server->last_ip);
			}
			auth_server->last_ip = safe_strdup(ip);
			fw_set_authservers();
		}
	}

	evutil_freeaddrinfo(res);
}

/**
 * @brief Check auth server
 * 
 */ 
static void 
check_auth_server_available() {
    t_auth_serv *auth_server = get_auth_server();
	if (!auth_server) {
		debug(LOG_INFO, "no auth server");
		return;
	}
    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = EVUTIL_AI_CANONNAME;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    evdns_getaddrinfo( dnsbase, auth_server->authserv_hostname, NULL ,
              &hints, check_auth_server_available_cb, auth_server);
}

/**
 * @brief periodically check whether internet and auth server were Ok or not
 * 
 */ 
static void 
schedule_work_cb(evutil_socket_t fd, short event, void *arg) {
	static uint32_t update_domain_interval = 1;

	debug(LOG_DEBUG, "check internet and auth server periodically %u", update_domain_interval);

	check_internet_available(config_get_config()->popular_servers);
	check_auth_server_available();
	
	// if config->update_domain_interval not 0
	if (update_domain_interval == config_get_config()->update_domain_interval) {
		// reparse trusted domain and refresh its firewall rule every 
		// update_domain_interval * checkinterval seconds
		parse_user_trusted_domain_list();
		parse_inner_trusted_domain_list();

		update_domain_interval = 1;
	} else
		update_domain_interval++;
}

static int 
ssl_redirect_loop () { 	
	struct event timeout;
	struct timeval tv;
	s_config *config = config_get_config();
	t_https_server *https_server = config->https_server;
	t_auth_serv *auth_server = get_auth_server();
	struct evconnlistener *listener_ipv6;
	struct sockaddr_in6 sin_ipv6;
	

  	base = event_base_new ();
  	if ( !base ) { 
		debug (LOG_ERR, "Couldn't create an event_base: exiting\n");
		termination_handler(0);
	}					
	
  	// Create a new evhttp object to handle requests.
  	struct evhttp *http = evhttp_new (base);
  	if ( !http ) { 
		debug (LOG_ERR, "couldn't create evhttp. Exiting.\n");
		termination_handler(0);
    }
 	evhttp_set_allowed_methods(http,
            EVHTTP_REQ_GET |
            EVHTTP_REQ_POST |
            EVHTTP_REQ_OPTIONS);
	
 	SSL_CTX *ctx = SSL_CTX_new (SSLv23_server_method ());
  	SSL_CTX_set_options (ctx,
                       SSL_OP_SINGLE_DH_USE |
                       SSL_OP_SINGLE_ECDH_USE |
                       SSL_OP_NO_SSLv2);

	/* Cheesily pick an elliptic curve to use with elliptic curve ciphersuites.
	* We just hardcode a single curve which is reasonably decent.
	* See http://www.mail-archive.com/openssl-dev@openssl.org/msg30957.html */
	EC_KEY *ecdh = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
	if (! ecdh)
    	die_most_horribly_from_openssl_error ("EC_KEY_new_by_curve_name");
  	if (1 != SSL_CTX_set_tmp_ecdh (ctx, ecdh))
    	die_most_horribly_from_openssl_error ("SSL_CTX_set_tmp_ecdh");
	
	struct stat st;
	if (stat(https_server->svr_crt_file, &st) || stat(https_server->svr_key_file, &st)) {
		debug(LOG_ERR, "couldn't find crt [%s] or key file [%s]", https_server->svr_crt_file, https_server->svr_key_file);
		termination_handler(0);
	}
	server_setup_certs (ctx, https_server->svr_crt_file, https_server->svr_key_file);

	// This is the magic that lets evhttp use SSL.
	evhttp_set_bevcb (http, ssl_bevcb, ctx);
 
	if (auth_server) {
		SSL_CTX *ssl_ctx = NULL;
		SSL *ssl = NULL;
        ssl_ctx = SSL_CTX_new(SSLv23_method());
        if (!ssl_ctx) termination_handler(0);

        ssl = SSL_new(ssl_ctx);
        if (!ssl) termination_handler(0);

        // authserv_hostname is the hostname of the auth server, must be domain name
        if (!SSL_set_tlsext_host_name(ssl, auth_server->authserv_hostname)) {
            debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
            termination_handler(0);
        }
    
		struct wd_request_context *request_ctx = wd_request_context_new(
            base, ssl, get_auth_server()->authserv_use_ssl);
        if (!request_ctx) termination_handler(0);
		evhttp_set_cb(http, "/wifidog", ev_http_callback_wifidog, NULL);
		evhttp_set_cb(http, "/wifidog/auth", ev_http_callback_auth, request_ctx);
		evhttp_set_cb(http, "/wifidog/temporary_pass", ev_http_callback_temporary_pass, NULL);
	} else {
		evhttp_set_cb(http, "/wifidog/local_auth", ev_http_callback_local_auth, NULL);
	}

	// This is the callback that gets called when a request comes in.
	evhttp_set_gencb (http, process_ssl_request_cb, NULL);

	memset(&sin_ipv6, 0, sizeof(sin_ipv6));
	sin_ipv6.sin6_family = AF_INET6;
	sin_ipv6.sin6_port = htons(config->gw_https_port);
	sin_ipv6.sin6_addr = in6addr_any;

	listener_ipv6 = evconnlistener_new_bind(base, NULL, NULL,
		LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC,
		-1, (struct sockaddr*)&sin_ipv6, sizeof(sin_ipv6));
	if (!listener_ipv6) {
		debug(LOG_ERR, "Failed to bind ipv6 address to port %d", config->gw_https_port);
		termination_handler(0);
	}

	if (!evhttp_bind_listener(http, listener_ipv6)) {
		debug(LOG_ERR, "Failed to bind listener to port %d", config->gw_https_port);
		termination_handler(0);
	}

	// check whether internet available or not
	dnsbase = evdns_base_new(base, 0);
	if (!dnsbase) {
		debug (LOG_ERR, "dnsbase new failed. \n");
		termination_handler(0);
	} else if ( 0 != evdns_base_resolv_conf_parse(dnsbase, DNS_OPTION_NAMESERVERS, "/tmp/resolv.conf.auto") ) {
		debug (LOG_ERR, "evdns_base_resolv_conf_parse failed. \n");
		if (!dnsbase) 
			termination_handler(0);
	}
	evdns_base_set_option(dnsbase, "timeout", config->dns_timeout);
	evdns_base_set_option(dnsbase, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
	
	t_popular_server *popular_server = config->popular_servers;
	check_internet_available(popular_server);
	check_auth_server_available();

	event_assign(&timeout, base, -1, EV_PERSIST, schedule_work_cb, NULL);
	evutil_timerclear(&tv);
	tv.tv_sec = config->checkinterval;
    event_add(&timeout, &tv);
	
	debug(LOG_INFO, "https server started on port %d", config->gw_https_port);
	
    event_base_dispatch (base);

	event_del(&timeout);
	if (http) evhttp_free(http);
	if (dnsbase) evdns_base_free(dnsbase, 0);
	event_base_free(base);
	
  	/* not reached; runs forever */
  	return 0;
}

void 
thread_ssl_redirect(void *args) {
	init_apfree_wifidog_cert();
   	ssl_redirect_loop ();
}
