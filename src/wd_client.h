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
/** @file wd_client.h
    @brief Wifidog client functions
    @author Copyright (C) 2018 Dengfeng Liu <liudf0716@gmail.com.cn>
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
char *wd_get_orig_url(struct evhttp_request *);
/** @brief wifidog get full redirect url to auth server */
char *wd_get_redir_url_to_auth(struct evhttp_request *, const char *, const char *);
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