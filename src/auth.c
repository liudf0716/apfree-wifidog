
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"
#include "ping_thread.h"
#include "wd_client.h"

static void client_timeout_check_cb(evutil_socket_t, short, void *);

/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_client_timeout_check(const void *arg)
{
    wd_request_loop(client_timeout_check_cb);
}

static void 
client_timeout_check_cb(evutil_socket_t fd, short event, void *arg) {
	struct wd_request_context *context = (struct wd_request_context *)arg;
	
	debug(LOG_DEBUG, "client_timeout_check_cb begin");
#ifdef AUTHSERVER_V2
    ev_fw_sync_with_authserver_v2(context);
#else
    ev_fw_sync_with_authserver(context);
#endif
}

/**
 * @brief Logout a client and report to auth server.
 *
 * @param context Points to request context
 * @param client Points to the client to be logged out; the client will be free 
 *               in this function
 * 
 */
void
ev_logout_client(struct wd_request_context *context, t_client *client)
{
    assert(client);

    char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, ONLINE_CLIENT, client);
    if (!uri) {
        return;
    }

    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req      = NULL;
    assert(context->data == NULL);
    context->data = client;
    if (!wd_make_request(context, &evcon, &req, process_auth_server_logout))
        evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    else {
        debug(LOG_ERR, "wd_make_request failed");
        context->data = NULL;
    }
    free(uri);
}

/** 
 * @brief authenticate login clients
 * 
 * Authenticates a single client against the central server and returns when done
 * Alters the firewall rules depending on what the auth server says
 * 
 * @param req  evhttp_request to reply client
 * @param context wd_request_context for http client request
 * @param client client by authenticated
 */
void
ev_authenticate_client(struct evhttp_request *req, 
        struct wd_request_context *context, t_client *client)
{
    char *uri = get_auth_uri(REQUEST_TYPE_LOGIN, ONLINE_CLIENT, client);
    if (!uri) {
        debug(LOG_ERR, "get_auth_uri failed");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
        return;
    }

    debug(LOG_DEBUG, "client login request [%s]", uri);

    struct evhttp_connection *wd_evcon = NULL;
    struct evhttp_request *wd_req      = NULL;
    assert(context->data == NULL);
    context->data = client;
    context->clt_req = req; 
    if (!wd_make_request(context, &wd_evcon, &wd_req, process_auth_server_login)) {
        evhttp_make_request(wd_evcon, wd_req, EVHTTP_REQ_GET, uri);
    } else {
        debug(LOG_ERR, "wd_make_request failed");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
    }
    free(uri);
}

