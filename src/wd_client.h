
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WD_CLIENT_H_
#define _WD_CLIENT_H_

#include <openssl/ssl.h>

#define WD_CONNECT_TIMEOUT  2 // 2 senconds timeout to connect auth server

struct event_base;
struct bufferevent;
struct evhttp_request;

struct wd_request_context {
    SSL *ssl;
	struct event_base *base;
	struct bufferevent *bev;
    struct evhttp_request *clt_req;
    void *data;
};

/** @brief get client's encoded original url */
char *wd_get_orig_url(struct evhttp_request *, int);
/** @brief wifidog get full redirect url to auth server */
char *wd_get_redir_url_to_auth(struct evhttp_request *, t_gateway_setting *, const char *, const char *, const uint16_t, const char *, int);
/** @brief free wifidog request context*/
void wd_request_context_free(struct wd_request_context *);
/** @brief set wifidog request header for connectiong auth server */ 
void wd_set_request_header(struct evhttp_request *, const char *);
/** @brief wifidog make a request context for auth server  */
struct wd_request_context *wd_request_context_new(struct event_base *, SSL *, int);
/** @brief wifidog make http request for auth server */
int wd_make_request(struct wd_request_context *, struct evhttp_connection **, struct evhttp_request **, void (*cb)(struct evhttp_request *, void *));
/** @brief a loop for wifidog connect auth server */
void wd_request_loop(void (*callback)(evutil_socket_t, short, void *));

#endif