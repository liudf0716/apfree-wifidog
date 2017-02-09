/* vim: set sw=4 ts=4 sts=4 et : */
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

#ifndef _SIMPLE_HTTP_H_
#define _SIMPLE_HTTP_H_

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/keyvalq_struct.h>

#define CHUNK   16384  

// (default)
#define HTTP_CONTENT_TYPE_URL_ENCODED   "application/x-www-form-urlencoded"   
// (use for files: picture, mp3, tar-file etc.)                                        
#define HTTP_CONTENT_TYPE_FORM_DATA     "multipart/form-data"                 
// (use for plain text)
#define HTTP_CONTENT_TYPE_TEXT_PLAIN    "text/plain"

#define REQUEST_POST_FLAG               2
#define REQUEST_GET_FLAG                3

#define windowBits 		15
#define GZIP_ENCODING 	16


typedef void (*user_process_data_cb)(void *, int);
typedef void (*request_done_cb)(struct evhttp_request *, void *);

struct http_request_get {
	user_process_data_cb	user_cb;
    struct evhttp_uri *uri;
    struct event_base *base;
    struct evhttp_connection *cn;
    struct evhttp_request *req;
};

struct http_request_post {
	user_process_data_cb	user_cb;
    struct evhttp_uri *uri;
    struct event_base *base;
    struct evhttp_connection *cn;
    struct evhttp_request *req;
    char *content_type;
    char *post_data;	
};

struct evhttps_request_context {
    struct event_base  *base;
    SSL_CTX     *ssl_ctx;
    void        *data;
};

void http_process_user_data(struct evhttp_request *, struct http_request_get *);

void http_request_post_cb(struct evhttp_request *, void *);

void http_request_get_cb(struct evhttp_request *, void *);

int start_url_request(struct http_request_get *, int);

void start_http_request(const char *, int , 
						const char *, const char* , 
						user_process_data_cb);

void *http_request_new(struct event_base* , const char *, int , 
                       const char *, const char* );

void http_request_free(struct http_request_get *, int);

int inflate_read(char *, int , char **, int *, int );

int deflate_write(char *, int, char **, int *, int);

char *http_get(const int, const char *);

char *http_get_ex(const int, const char *, int);

struct evhttps_request_context * evhttps_context_init(void);

void evhttps_context_exit(struct evhttps_request_context *);

void evhttps_request(struct evhttps_request_context *, const char *, int, request_done_cb, void *);

void evhttp_set_request_header(struct evhttp_request *);

#endif                          /* defined(_SIMPLE_HTTP_H_) */
