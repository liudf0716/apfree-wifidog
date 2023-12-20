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

extern struct evbuffer *evb_internet_offline_page, *evb_authserver_offline_page;
extern struct redir_file_buffer *wifidog_redir_html;

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
        ev_http_reply_client_error(req, INTERNET_OFFLINE);
        return;
    }  

    if (!is_auth_online()) {
        ev_http_reply_client_error(req, AUTHSERVER_OFFLINE);
        return;
    } 

    char *remote_host;
    uint16_t port;
    evhttp_connection_get_peer(evhttp_request_get_connection(req), &remote_host, &port);

    char mac[MAC_LENGTH] = {0};
    if(!br_arp_get_mac(remote_host, mac)) {
        evhttp_send_error(req, 200, "Cant get client's mac by its ip");
        return;
    }

	char *redir_url = wd_get_redir_url_to_auth(req, mac, remote_host);
    if (!redir_url) {
        evhttp_send_error(req, 200, "Cant get client's redirect to auth server's url");
        return;
    }

	ev_http_send_js_redirect(req, redir_url);
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

/**
 * @brief Callback function to check whether auth server's ip changed or not
 * 
 */ 
static void 
check_auth_server_available_cb(int errcode, struct evutil_addrinfo *addr, void *ptr) {
	t_auth_serv *auth_server = (t_auth_serv *)ptr;
	if (errcode || !addr) { 
		debug (LOG_INFO, "dns query error : %s", evutil_gai_strerror(errcode));
		mark_auth_offline();
		mark_auth_server_bad(auth_server);
		return;
	}

	for (int i = 0; addr; addr = addr->ai_next, i++) {
		if (addr->ai_family == PF_INET) {
			char ip[128] = {0};
			struct sockaddr_in *sin = (struct sockaddr_in*)addr->ai_addr;
			evutil_inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)-1);

			if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
				/*
					* But the IP address is different from the last one we knew
					* Update it
					*/
				debug(LOG_INFO, "Updating last_ip IP of server [%s] to [%s]", 
					auth_server->authserv_hostname, ip);
				if (auth_server->last_ip)
					free(auth_server->last_ip);
				auth_server->last_ip = safe_strdup(ip);

				/* Update firewall rules */
				fw_clear_authservers();
				fw_set_authservers();

				evutil_freeaddrinfo(addr);
				break;
			} 
		}
	}
}

/**
 * @brief Check auth server
 * 
 */ 
static void 
check_auth_server_available() {
	s_config *config = config_get_config();
    t_auth_serv *auth_server = config->auth_servers;
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
ssl_redirect_loop (char *gw_ip,  t_https_server *https_server) { 	
	struct event timeout;
	struct timeval tv;

  	base = event_base_new ();
  	if (! base) { 
		debug (LOG_ERR, "Couldn't create an event_base: exiting\n");
      	exit(EXIT_FAILURE);
    }
	
  	// Create a new evhttp object to handle requests.
  	struct evhttp *http = evhttp_new (base);
  	if (! http) { 
		debug (LOG_ERR, "couldn't create evhttp. Exiting.\n");
      	exit(EXIT_FAILURE);
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
		exit(EXIT_FAILURE);
	}
	server_setup_certs (ctx, https_server->svr_crt_file, https_server->svr_key_file);

	// This is the magic that lets evhttp use SSL.
	evhttp_set_bevcb (http, ssl_bevcb, ctx);
 
	evhttp_set_cb(http, "/wifidog/temporary_pass", ev_http_callback_temporary_pass, NULL);

	// This is the callback that gets called when a request comes in.
	evhttp_set_gencb (http, process_ssl_request_cb, NULL);

	// Now we tell the evhttp what port to listen on. 
	struct evhttp_bound_socket *handle = evhttp_bind_socket_with_handle (http, gw_ip, https_server->gw_https_port);
	if (! handle) { 
		debug (LOG_ERR, "couldn't bind to port %d. Exiting.\n",
               (int) https_server->gw_https_port);
		exit(EXIT_FAILURE);
    }
    
	// check whether internet available or not
	dnsbase = evdns_base_new(base, 0);
	if (!dnsbase) {
		debug (LOG_ERR, "dnsbase new failed. \n");
		exit(EXIT_FAILURE);
	} else if ( 0 != evdns_base_resolv_conf_parse(dnsbase, DNS_OPTION_NAMESERVERS, "/tmp/resolv.conf.auto") ) {
		debug (LOG_ERR, "evdns_base_resolv_conf_parse failed. \n");
		if (!dnsbase) exit(EXIT_FAILURE);
	}
	evdns_base_set_option(dnsbase, "timeout", config_get_config()->dns_timeout);
	evdns_base_set_option(dnsbase, "randomize-case:", "0");//TurnOff DNS-0x20 encoding
	
	t_popular_server *popular_server = config_get_config()->popular_servers;
	check_internet_available(popular_server);
	check_auth_server_available();

	event_assign(&timeout, base, -1, EV_PERSIST, schedule_work_cb, NULL);
	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval;
    event_add(&timeout, &tv);

	
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
	s_config *config = config_get_config();
	init_apfree_wifidog_cert();
   	ssl_redirect_loop (config->gw_address, config->https_server);
}
