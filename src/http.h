// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _HTTP_H_
#define _HTTP_H_

/**
 * @brief Error types for client replies
 */
enum reply_client_page_type {
    INTERNET_OFFLINE,    /**< Internet connection is not available */
    AUTHSERVER_OFFLINE,  /**< Authentication server is not reachable */
    LOCAL_AUTH,          /**< Local authentication mode */
    LOCAL_CUSTROM_AUTH,  /**< Local custom authentication mode */
};

/* HTTP Request Callback Functions */
void ev_http_callback_404(struct evhttp_request *, void *);
void ev_http_callback_wifidog(struct evhttp_request *, void *);
void ev_http_callback_about(struct evhttp_request *, void *);
void ev_http_callback_status(struct evhttp_request *, void *);
void ev_http_callback_auth(struct evhttp_request *, void *);
void ev_http_callback_disconnect(struct evhttp_request *, void *);
void ev_http_callback_temporary_pass(struct evhttp_request *, void *);
void ev_http_callback_local_auth(struct evhttp_request *, void *);
void ev_http_callback_device(struct evhttp_request *, void *);

/* HTTP Response Functions */
void ev_http_send_redirect_to_auth(struct evhttp_request *, const char *, const char *);
void ev_http_send_js_redirect(struct evhttp_request *, const char *);
void ev_http_reply_client_error(struct evhttp_request *, enum reply_client_page_type, 
                               char *, char *, char *, char *, char *);
void ev_http_send_user_redirect_page(struct evhttp_request *, const char *);

/* HTTP Utility Functions */
struct evbuffer *ev_http_read_html_file(const char *, struct evbuffer *);
char *ev_http_find_query(struct evhttp_request *, const char *);
int ev_http_connection_get_peer(struct evhttp_connection *, char **, uint16_t *);

#endif /* _HTTP_H_ */
