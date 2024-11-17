
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "util.h"
#include "wd_util.h"
#include "wd_client.h"
#include "gateway.h"

/**
 * @brief Extract and encode the original URL from an HTTP request
 * 
 * @param req The HTTP request to extract URL from
 * @param is_ssl Flag indicating if the connection is SSL/TLS (1) or not (0)
 * @return char* The encoded URL string that must be freed by caller, or NULL on failure
 *
 * This function reconstructs the original URL that the client requested by:
 * 1. Extracting the URI components (path, query, etc.)
 * 2. Getting the scheme (http/https), host and port
 * 3. Building the full URL
 * 4. URL-encoding the result
 */
char *
wd_get_orig_url(struct evhttp_request *req, int is_ssl) 
{
	const struct evhttp_uri *uri;
	const char *scheme, *host;
	char path[4096] = {0};
	int port;
	char *full_url = NULL;
	char *encoded_url = NULL;

	// Get URI from request
	if (!(uri = evhttp_request_get_evhttp_uri(req))) {
		debug(LOG_DEBUG, "Failed to get URI from request");
		return NULL;
	}

	// Reconstruct path and query
	if (evhttp_uri_join((struct evhttp_uri *)uri, path, sizeof(path) - 1) == -1) {
		debug(LOG_DEBUG, "Failed to join URI components");
		return NULL;
	}
	debug(LOG_DEBUG, "Path: %s", path);

	// Get URI components
	scheme = evhttp_uri_get_scheme(uri);
	host = evhttp_uri_get_host(uri);
	port = evhttp_uri_get_port(uri);

	// Use default scheme based on SSL flag if not specified
	if (!scheme) {
		scheme = is_ssl ? "https" : "http";
	}

	// Fall back to request host header if URI has no host
	if (!host && !(host = evhttp_request_get_host(req))) {
		debug(LOG_DEBUG, "No host found in URI or request");
		return NULL;
	}

	// Build full URL, including port if non-standard
	if (port > 0 && port != 80 && port != 443) {
		safe_asprintf(&full_url, "%s://%s:%d%s", scheme, host, port, path);
	} else {
		safe_asprintf(&full_url, "%s://%s%s", scheme, host, path);
	}

	if (!full_url) {
		debug(LOG_DEBUG, "Failed to build full URL");
		return NULL;
	}
	debug(LOG_DEBUG, "Full URL: %s", full_url);

	// URL-encode the full URL
	encoded_url = evhttp_encode_uri(full_url);
	free(full_url);

	return encoded_url;
}

/**
 * @brief Constructs the full redirect URL for authenticating a client with the auth server
 * 
 * @param req The HTTP request from the client
 * @param gw_setting Gateway settings containing configuration values
 * @param mac Client's MAC address
 * @param remote_host Client's IP address (can be IPv4 or IPv6)
 * @param gw_port Gateway port number
 * @param device_id Unique device identifier
 * @param is_ssl Flag indicating if connection is SSL/TLS (1) or not (0)
 * @return char* The complete redirect URL that must be freed by caller, or NULL on failure
 *
 * This function builds the complete URL to redirect clients to the authentication server.
 * It includes all necessary parameters like:
 * - Gateway address (IPv4 or IPv6)
 * - Gateway port, ID and channel
 * - Client IP and MAC
 * - Original requested URL
 * - SSID information
 * - Protocol (http/https)
 */
char *
wd_get_redir_url_to_auth(struct evhttp_request *req, 
						 t_gateway_setting *gw_setting, 
						 const char *mac,
						 const char *remote_host,
						 const uint16_t gw_port,
						 const char *device_id,
						 int is_ssl)
{
	t_auth_serv *auth_server = get_auth_server();
	char *orig_url = wd_get_orig_url(req, is_ssl);
	char *gw_address;
	char *redir_url = NULL;
	int is_ipv6 = is_valid_ip6(remote_host);

	// Use fallback value if original URL extraction fails
	if (!orig_url) {
		orig_url = safe_strdup("null");
	}

	// Select appropriate gateway address based on IP version
	gw_address = is_ipv6 ? gw_setting->gw_address_v6 : gw_setting->gw_address_v4;

	// Build the complete redirect URL with all parameters
	safe_asprintf(&redir_url, 
		"%s://%s:%d%s%s"  // Auth server base URL
		"gw_address=%s"    // Gateway address
		"&is_ipv6=%d"      // IPv6 flag
		"&gw_port=%d"      // Gateway port
		"&device_id=%s"    // Device ID
		"&gw_id=%s"        // Gateway ID
		"&gw_channel=%s"   // Gateway channel
		"&ssid=%s"         // SSID
		"&ip=%s"           // Client IP
		"&mac=%s"          // Client MAC
		"&protocol=%s"     // Protocol
		"&url=%s",         // Original URL
		// Parameter values
		auth_server->authserv_use_ssl ? "https" : "http",
		auth_server->authserv_hostname,
		auth_server->authserv_use_ssl ? auth_server->authserv_ssl_port : auth_server->authserv_http_port,
		auth_server->authserv_path,
		auth_server->authserv_login_script_path_fragment,
		gw_address,
		is_ipv6,
		gw_port,
		device_id,
		gw_setting->gw_id,
		gw_setting->gw_channel ? gw_setting->gw_channel : "null",
		g_ssid ? g_ssid : "null",
		remote_host,
		mac,
		is_ssl ? "https" : "http",
		orig_url
	);

	free(orig_url);
	return redir_url;
}

/**
 * @brief free wifidog request context
 * 
 */ 
void
wd_request_context_free(struct wd_request_context *context)
{
	if (context) free(context);
}

/**
 * @brief Creates a new wifidog request context for HTTP/HTTPS connections
 * 
 * @param base The libevent event_base for event handling
 * @param ssl SSL context for HTTPS connections, NULL for HTTP
 * @param authserv_use_ssl Flag indicating if auth server uses SSL/TLS (1) or not (0)
 * @return struct wd_request_context* New context that must be freed by caller, or NULL on failure
 *
 * This function initializes a request context by:
 * 1. Creating an appropriate bufferevent based on SSL/non-SSL connection
 * 2. Setting buffer event options for reliable operation
 * 3. Allocating and initializing the context structure
 *
 * The caller is responsible for freeing the returned context using wd_request_context_free()
 */
struct wd_request_context *
wd_request_context_new(struct event_base *base, SSL *ssl, int authserv_use_ssl)
{
	struct bufferevent *bev = NULL;
	struct wd_request_context *context = NULL;

	if (!base) return NULL;

	// Create appropriate bufferevent based on SSL usage
	if (!authserv_use_ssl) {
		bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
	} else {
		if (!ssl) return NULL;
		bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
	}

	if (!bev) return NULL;

	// Allow dirty shutdown for SSL connections
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	// Initialize context structure
	context = safe_malloc(sizeof(struct wd_request_context));
	if (!context) {
		bufferevent_free(bev);
		return NULL;
	}

	context->base = base;
	context->ssl = ssl;
	context->bev = bev;

	return context;
}

/**
 * @brief Initialize and run a periodic event loop for auth server communication
 * 
 * @param callback Function to be called periodically during the event loop
 *                 Signature: void (*callback)(evutil_socket_t, short, void *)
 *
 * This function:
 * 1. Sets up SSL/TLS context and configuration for secure connections
 * 2. Initializes libevent base and request context
 * 3. Creates a timer event to periodically execute the callback
 * 4. Runs the event loop until program termination
 * 
 * The callback function is executed:
 * - Once immediately before starting the event loop
 * - Every checkinterval seconds thereafter (configured in wifidog.conf)
 *
 * @note This function will terminate the program if critical initialization fails
 */
void
wd_request_loop(void (*callback)(evutil_socket_t, short, void *))
{
	SSL_CTX *ssl_ctx = NULL;
	SSL *ssl = NULL;
	struct event_base *base = NULL;
	struct wd_request_context *request_ctx = NULL;
	struct event evtimer;
	struct timeval tv;
	t_auth_serv *auth_server = get_auth_server();

	// Initialize OpenSSL random number generator
	if (!RAND_poll()) {
		debug(LOG_ERR, "Failed to initialize RAND");
		goto cleanup;
	}

	// Initialize SSL context and configuration
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		debug(LOG_ERR, "Failed to create SSL context");
		goto cleanup;
	}

	ssl = SSL_new(ssl_ctx);
	if (!ssl) {
		debug(LOG_ERR, "Failed to create SSL connection");
		goto cleanup;
	}

	// Set Server Name Indication (SNI) for SSL connections
	if (!SSL_set_tlsext_host_name(ssl, auth_server->authserv_hostname)) {
		debug(LOG_ERR, "Failed to set SSL hostname");
		goto cleanup;
	}

	// Initialize libevent base
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "Failed to create event base");
		goto cleanup;
	}

	// Create request context
	request_ctx = wd_request_context_new(base, ssl, auth_server->authserv_use_ssl);
	if (!request_ctx) {
		debug(LOG_ERR, "Failed to create request context");
		goto cleanup;
	}

	// Execute callback immediately before starting event loop
	if (callback) {
		callback(-1, EV_PERSIST, request_ctx);
	}

	// Set up periodic timer event
	event_assign(&evtimer, base, -1, EV_PERSIST, callback, (void*)request_ctx);
	evutil_timerclear(&tv);
	tv.tv_sec = config_get_config()->checkinterval;
	event_add(&evtimer, &tv);

	// Run event loop
	event_base_dispatch(base);

	// Cleanup
	if (evtimer_initialized(&evtimer)) {
		event_del(&evtimer);
	}

cleanup:
	if (base) event_base_free(base);
	if (ssl) SSL_free(ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);
	if (request_ctx) wd_request_context_free(request_ctx);
	
	termination_handler(0);
}

/**
 * @brief Set wifidog request header when connection auth server
 * 
 * @param req The http request
 * @param host The auth server's host
 */ 
void
wd_set_request_header(struct evhttp_request *req, const char *host)
{
	struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);

	evhttp_add_header(output_headers, "Host", host);
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", "text/html");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Cache-Control", "no-store, must-revalidate");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Expires", "0");
	evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Pragma", "no-cache");
	evhttp_add_header(output_headers, "Connection", "close");
	evhttp_add_header(output_headers, "User-Agent", "ApFree-WiFiDog");
}

/**
 * @brief make http client request to auth server 
 * 
 * @param request_ctx which has set event_base and bufferevent
 * @param evcon it's out param
 * @param req	it's out param
 * @param cb  it's callback function for evhttp_request_new
 * @return 1 fail or 0 success
 * 
 */
int
wd_make_request(struct wd_request_context *request_ctx, 
	struct evhttp_connection **evcon, struct evhttp_request **req,
	void (*cb)(struct evhttp_request *, void *))
{
	struct bufferevent *bev = request_ctx->bev;
	struct event_base *base = request_ctx->base;
	t_auth_serv *auth_server = get_auth_server();
	
	debug(LOG_DEBUG, "auth_server->authserv_use_ssl: %d", auth_server->authserv_use_ssl);
	if (!auth_server->authserv_use_ssl) {
		*evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_http_port);
	} else {
		*evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
				auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	}
	if (!*evcon) {
		debug(LOG_ERR, "evhttp_connection_base_bufferevent_new failed");
		return 1;
	}

	evhttp_connection_set_timeout(*evcon, WD_CONNECT_TIMEOUT); // 2 seconds

	*req = evhttp_request_new(cb, request_ctx);
	if (!*req) {
		debug(LOG_ERR, "evhttp_request_new failed");
		evhttp_connection_free(*evcon);
		return 1;
	}

	wd_set_request_header(*req, auth_server->authserv_hostname);

	return 0;
}
