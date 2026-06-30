
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WD_CLIENT_H_
#define _WD_CLIENT_H_

/** @brief Connection timeout in seconds for auth server requests */
#define WD_CONNECT_TIMEOUT  2

/**
 * @brief Context structure for wifidog HTTP requests
 * 
 * @param ssl Borrowed SSL template used to derive per-request SSL objects
 * @param base Event base for libevent
 * @param clt_req Client HTTP request
 * @param data Additional user data
 */
struct wd_request_context {
    SSL *ssl;
    struct event_base *base;
    struct evhttp_request *clt_req;
    void *data; /**< Additional user data. Its lifecycle is managed by the user of this context,
                     *   not by wd_request_context_destroy(). The callback or the setup code
                     *   is responsible for allocating and freeing this data if necessary. */
    int per_request; /**< If set, context was created for a single request and should be
                        * destroyed by the response callback after handling. */
};

/**
 * @brief Get URL-encoded original URL from client request
 * @param request HTTP request object
 * @param is_ssl 
 * @return Encoded URL string, must be freed by caller
 */
char *wd_get_orig_url(struct evhttp_request *request, int is_ssl, int url_encode);

/**
 * @brief Generate full redirect URL for auth server
 * @param request Original HTTP request
 * @param settings Gateway settings
 * @param mac Client MAC address
 * @param ip Client IP address
 * @param port Port number
 * @param url Original URL
 * @param is_ssl 
 * @return Full redirect URL, must be freed by caller
 */
char *wd_get_redir_url_to_auth(struct evhttp_request *request, t_gateway_setting *settings, 
                              const char *mac, const char *ip, const uint16_t port, 
                              const char *url, int is_ssl);

/**
 * @brief Destroy request context and associated resources
 * @param context Request context to destroy
 * @note This function does NOT free the memory pointed to by context->data.
 *       The lifecycle of context->data must be managed externally.
 * @note The SSL object stored in context is borrowed and owned by the caller.
 */
void wd_request_context_destroy(struct wd_request_context *context);

/**
 * @brief Set required headers for auth server request
 * @param request HTTP request object
 * @param mac Client MAC address
 */
void wd_set_request_header(struct evhttp_request *request, const char *mac);

/**
 * @brief Create new request context
 * @param base Event base for libevent
 * @param ssl Borrowed SSL template, required when auth server uses SSL
 * @param authserv_use_ssl Whether the auth server uses SSL/TLS
 * @return New request context or NULL on failure
 */
struct wd_request_context *wd_request_context_new(struct event_base *base, SSL *ssl, int authserv_use_ssl);

/**
 * @brief Initialize and make HTTP request to auth server
 * @param context Request context
 * @param evcon Connection object pointer
 * @param req Request object pointer
 * @param cb Callback function for request completion
 * @return 0 on success, 1 on failure
 * @note The returned connection is scheduled for automatic release on
 *       request completion. If queueing the request fails, the caller must
 *       free both @p req and @p evcon.
 */
int wd_make_request(struct wd_request_context *context, struct evhttp_connection **evcon,
                   struct evhttp_request **req, void (*cb)(struct evhttp_request *, void *));

/**
 * @brief Start request event loop
 * @param callback Function to call on event trigger
 */
void wd_request_loop(void (*callback)(evutil_socket_t, short, void *));

#endif
