
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _HTTP_H_
#define _HTTP_H_

struct evhttp_request;
struct evbuffer;

enum reply_client_error_type {
    INTERNET_OFFLINE,
    AUTHSERVER_OFFLINE
};

/** @brief callback for evhttp, main entry point for captive portal */
void ev_http_callback_404(struct evhttp_request *, void *);
/** @brief callback for evhttp */
void ev_http_callback_wifidog(struct evhttp_request *, void *);
/** @brief callback for evhttp */
void ev_http_callback_about(struct evhttp_request *, void *);
/** @brief callback for evhttp */
void ev_http_callback_status(struct evhttp_request *, void *);
/** @brief callback for evhttp */
void ev_http_callback_auth(struct evhttp_request *, void *);
/** @brief callback for evhttp, disconnect user from network */
void ev_http_callback_disconnect(struct evhttp_request *, void *);
/** @brief callback for evhttp, temporary allow user to access network one minute  */
void ev_http_callback_temporary_pass(struct evhttp_request *, void *);

/** @brief resend client's request */
void ev_http_resend(struct evhttp_request *);
/** @brief read html file to evbuffer */
struct evbuffer *ev_http_read_html_file(const char *, struct evbuffer *);
/** @brief Sends a HTML page to web browser */
void ev_send_http_page(struct evhttp_request *, const char *, const char *);
/** @brief Sends a redirect to the web browser */
void ev_http_send_redirect(struct evhttp_request *, const char *, const char *);
/** @brief Convenience function to redirect the web browser to the authe server */
void ev_http_send_redirect_to_auth(struct evhttp_request *, const char *, const char *);
/** @brief send the web browser's page which redirect to auth server by js */
void ev_http_send_js_redirect(struct evhttp_request *, const char *);
/** @brief reply client error of gw internet offline or auth server offline */
void ev_http_reply_client_error(struct evhttp_request *, enum reply_client_error_type, 
     char *,  char *,  char *,  char *,  char *);
/** @brief */
void ev_http_send_apple_redirect(struct evhttp_request *, const char *);
/** @brief send apple wisper detect request again */
void ev_http_replay_wisper(struct evhttp_request *);

/** @brief get query's value according to key */
char *ev_http_find_query(struct evhttp_request *, const char *);

void ev_http_callback_local_auth(struct evhttp_request *, void *);

int ev_http_connection_get_peer(struct evhttp_connection *, char **, uint16_t *);

#endif /* _HTTP_H_ */
