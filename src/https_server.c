
#include "https_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#ifndef S_ISDIR
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

#ifdef _WIN32
#define stat _stat
#define fstat _fstat
#define open _open
#define close _close
#define O_RDONLY _O_RDONLY
#endif

#include <syslog.h>

#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "wd_util.h"
#include "firewall.h"

enum reply_type {
	INTERNET_OFFLINE,
	AUTHSERVER_OFFLINE
};

// !!!remember to free the return url
char *
evhttp_get_request_url(struct evhttp_request *req) {
	char *url = malloc(256); // only get 256 char from request url
	memset(url, 0, 256);
	
	snprintf(url, 256, "%s://%s:%d/%s/%s",
		evhttp_uri_get_scheme(req->uri_elems),
		evhttp_uri_get_host(req->uri_elems),
		evhttp_uri_get_scheme(req->uri_elems),
		evhttp_uri_get_path(req->uri_elems),
		evhttp_uri_get_query(req->uri_elems));
	return url;
}

// !!!remember to free the return redir_url
char *
evhttpd_get_full_redir_url(const char *mac, const char *ip, const char *orig_url) {
	struct evbuffer *evb = evbuffer_new();
	s_config *config = config_get_config();
	char *protocol = NULL;
    int port = 80;
    t_auth_serv *auth_server = get_auth_server();

    if (auth_server->authserv_use_ssl) {
        protocol = "https";
        port = auth_server->authserv_ssl_port;
    } else {
        protocol = "http";
        port = auth_server->authserv_http_port;
    }
	
	evbuffer_add_printf(evb, "%s://%s:%d%s%sgw_address=%s&gw_port=%d&gw_id=%s&channel_path=%s&ssid=%s&ip=%s&mac=%s&url=%s",
					protocol, auth_server->authserv_hostname, port, auth_server->authserv_path,
					auth_server->authserv_login_script_path_fragment,
					config->gw_address, config->gw_port, config->gw_id, 
					g_channel_path?g_channel_path:"null",
					g_ssid?g_ssid:"null",
					ip, mac, orig_url);
	
	size_t len = evbuffer_get_length(evb)+1;
	char *redir_url = (char *)malloc(len);
	memset(redir_url, 0, len);
	evbuffer_copyout(evb, redir_url, len);
	
	evbuffer_free(evb);
	
	return redir_url;
}

void
evhttpd_gw_reply(struct evhttp_request *req, enum reply_type type) {
	struct evbuffer *evb = NULL;
	switch (type) {
	case INTERNET_OFFLINE:
		evb = evb_internet_offline_page;
	case AUTHSERVER_OFFLINE:
		evb = evb_authserver_offline_page;
	}
	
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_send_reply (req, 200, "OK", evb); 	
}

/* This callback gets invoked when we get any http request that doesn't match
 * any other callback.  Like any evhttp server callback, it has a simple job:
 * it must eventually call evhttp_send_error() or evhttp_send_reply().
 */
static void
process_https_cb (struct evhttp_request *req, void *arg) { 
	struct evbuffer *evb = NULL;
  	const char *req_url = evhttp_get_request_url (req); 	
	
	/* Determine peer */
	char *peer_addr;
	ev_uint16_t peer_port;
	struct evhttp_connection *con = evhttp_request_get_connection (req);
	evhttp_connection_get_peer (con, &peer_addr, &peer_port);
	
	debug (LOG_INFO, "Got a GET request for <%s> from <%s>:<%d>\n", req_url, peer_addr, peer_port);
	
	if (!is_online()) {    
        debug(LOG_INFO, "Sent %s an apology since I am not online - no point sending them to auth server",
              peer_addr);
		return evhttpd_gw_reply(req, INTERNET_OFFLINE);
    } else if (!is_auth_online()) {  
        debug(LOG_INFO, "Sent %s an apology since auth server not online - no point sending them to auth server",
              peer_addr);
		return evhttpd_gw_reply(req, AUTHSERVER_OFFLINE);
    }
	
	char *mac = (char *)arp_get(peer_addr);
	char *redir_url = evhttpd_get_full_redir_url(mac?mac:"ff:ff:ff:ff:ff:ff", peer_addr, req_url);

	evb = evbuffer_new ();		
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evbuffer_add_buffer(evb, wifidog_redir_html->evb_front);
	
	evbuffer_add_printf(evb, WIFIDOG_REDIR_HTML_CONTENT, redir_url);
	
	evbuffer_add_buffer(evb, wifidog_redir_html->evb_rear);
	evhttp_send_reply (req, 200, "OK", evb);
		
	free(req_url);
	free(redir_url);
	evbuffer_free (evb);
	free(peer_addr);
}

/**
 * This callback is responsible for creating a new SSL connection
 * and wrapping it in an OpenSSL bufferevent.  This is the way
 * we implement an https server instead of a plain old http server.
 */
static struct bufferevent* bevcb (struct event_base *base, void *arg) { 
	struct bufferevent* r;
  	SSL_CTX *ctx = (SSL_CTX *) arg;

  	r = bufferevent_openssl_socket_new (base,
                                      -1,
                                      SSL_new (ctx),
                                      BUFFEREVENT_SSL_ACCEPTING,
                                      BEV_OPT_CLOSE_ON_FREE);
  	return r;
}

static void server_setup_certs (SSL_CTX *ctx,
                                const char *certificate_chain,
                                const char *private_key) { 
	info_report ("Loading certificate chain from '%s'\n"
               "and private key from '%s'\n",
               certificate_chain, private_key);

  	if (1 != SSL_CTX_use_certificate_chain_file (ctx, certificate_chain))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_certificate_chain_file");

  	if (1 != SSL_CTX_use_PrivateKey_file (ctx, private_key, SSL_FILETYPE_PEM))
    	die_most_horribly_from_openssl_error ("SSL_CTX_use_PrivateKey_file");

  	if (1 != SSL_CTX_check_private_key (ctx))
    	die_most_horribly_from_openssl_error ("SSL_CTX_check_private_key");
}

static int serve_some_http (char *gw_ip,  t_https_server *https_server) { 
	struct event_base *base;
  	struct evhttp *http;
  	struct evhttp_bound_socket *handle;

  	base = event_base_new ();
  	if (! base) { 
		fprintf (stderr, "Couldn't create an event_base: exiting\n");
      	return 1;
    }

  	/* Create a new evhttp object to handle requests. */
  	http = evhttp_new (base);
  	if (! http) { 
		fprintf (stderr, "couldn't create evhttp. Exiting.\n");
      	return 1;
    }
 
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

	server_setup_certs (ctx, https_server->svr_crt_file, https_server->svr_key_file);

	/* This is the magic that lets evhttp use SSL. */
	evhttp_set_bevcb (http, bevcb, ctx);
 
	/* This is the callback that gets called when a request comes in. */
	evhttp_set_gencb (http, process_https_cb, NULL);

	/* Now we tell the evhttp what port to listen on */
	handle = evhttp_bind_socket_with_handle (http, gw_ip, https_server->gw_https_port);
	if (! handle) { 
		debug (LOG_ERR, "couldn't bind to port %d. Exiting.\n",
               (int) https_server->gw_https_port);
		return 1;
    }
    
    event_base_dispatch (base);

  	/* not reached; runs forever */
  	return 0;
}

void thread_https_server(void *args) {
	s_config *config = config_get_config();
	common_setup ();              /* Initialize OpenSSL */
   	serve_some_http (config->gw_address, config->https_server);
}
