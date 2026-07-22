
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "http.h"
#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "util.h"
#include "wd_util.h"
#include "ping_thread.h"
#include "wd_client.h"
#include "auth.h"


/**
 * @brief Callback function for checking client timeouts and syncing with auth server
 *
 * This callback is triggered periodically to:
 * 1. Check for client timeouts
 * 2. Synchronize firewall rules with the authentication server
 *
 * @param fd The socket file descriptor (unused)
 * @param event The event type that triggered this callback (unused)
 * @param arg Pointer to the request context
 */
static void 
client_timeout_check_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct wd_request_context *context = (struct wd_request_context *)arg;
    
    debug(LOG_DEBUG, "Starting client timeout check");

#ifdef AUTHSERVER_V2
    ev_fw_sync_with_authserver_v2(context);
#else
    ev_fw_sync_with_authserver(context);
#endif
}

/**
 * @brief Initializes and runs the client timeout checking thread
 *
 * This function starts a loop that periodically checks for client timeouts
 * and synchronizes the firewall state with the authentication server.
 *
 * @param arg Thread arguments (unused)
 */
void
*thread_client_timeout_check(void *arg)
{
    wd_request_loop(client_timeout_check_cb);
    return NULL;
}

/**
 * @brief Logs out a client and notifies the authentication server
 *
 * This function handles the client logout process by:
 * 1. Generating the logout URI for the auth server
 * 2. Setting up the HTTP request
 * 3. Sending the logout notification
 *
 * @param context The request context for the operation
 * @param client The client to be logged out
 * 
 * @note The client structure will be freed by the callback function
 * @note context->data is modified to point to the client during the request
 */
void
ev_logout_client(struct wd_request_context *context, t_client *client)
{
    if (!context || !client) {
        debug(LOG_ERR, "Invalid parameters to ev_logout_client");
        return;
    }

    // Keep a stable snapshot across async request/response lifecycle.
    // The original client may be removed by other threads before callback.
    t_client *client_snapshot = client_dup(client);
    if (!client_snapshot) {
        debug(LOG_ERR, "Failed to duplicate client for logout request");
        return;
    }

    // Generate logout URI for this client
    char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, ONLINE_CLIENT, client_snapshot);
    if (!uri) {
        debug(LOG_ERR, "Failed to generate logout URI");
        client_free_node(client_snapshot);
        return;
    }

    debug(LOG_DEBUG, "Processing logout request with URI [%s]", uri);

    // Setup auth server request
    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req = NULL;

    // Create a dedicated request context so logout does not race on
    // shared context->data when multiple async requests are in-flight.
    struct wd_request_context *req_ctx = wd_request_context_new(
        context->base,
        context->ssl,
        get_auth_server()->authserv_use_ssl);
    if (!req_ctx) {
        debug(LOG_ERR, "Failed to create request context for logout");
        client_free_node(client_snapshot);
        free(uri);
        return;
    }

    req_ctx->data = client_snapshot;

    /* wd_make_request returns 0 on success, non-zero on failure. */
    if (wd_make_request(req_ctx, &evcon, &req, process_auth_server_logout)) {
        debug(LOG_ERR, "Failed to create auth server logout request");
        client_free_node(client_snapshot);
        req_ctx->data = NULL;
        wd_request_context_destroy(req_ctx);
    } else if (evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri) != 0) {
        debug(LOG_ERR, "Failed to queue auth server logout request");
        if (req) evhttp_request_free(req);
        if (evcon) evhttp_connection_free(evcon);
        client_free_node(client_snapshot);
        req_ctx->data = NULL;
        wd_request_context_destroy(req_ctx);
    }

    free(uri);
}

/** 
 * @brief Authenticates a client against the central server
 * 
 * This function handles the authentication process for a single client by:
 * 1. Generating the authentication URI
 * 2. Setting up the HTTP request to the auth server
 * 3. Processing the auth server's response via callback
 * 
 * @param req The client's original HTTP request to respond to
 * @param context Shared request context (only base/ssl are borrowed; not mutated)
 * @param client The client to be authenticated (live list node; callback owns cleanup on failure paths)
 * 
 * @note Like logout/counter, a dedicated request-owned context carries data/clt_req
 *       so concurrent logins do not overwrite each other's async state.
 * @note The function will free the client structure if authentication fails before
 *       the auth-server request is successfully queued.
 */
void
ev_authenticate_client(struct evhttp_request *req, 
    struct wd_request_context *context, t_client *client)
{
    if (!req || !context || !client) {
        debug(LOG_ERR, "Invalid parameters to ev_authenticate_client");
        if (req) evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        if (client) safe_client_list_delete(client);
        return;
    }

    // Generate authentication URI for this client
    char *uri = get_auth_uri(REQUEST_TYPE_LOGIN, ONLINE_CLIENT, client);
    if (!uri) {
        debug(LOG_ERR, "Failed to generate auth URI");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
        return;
    }

    debug(LOG_DEBUG, "Processing login request with URI [%s]", uri);

    // Dedicated context so concurrent logins do not race on shared data/clt_req.
    // Reuse base/ssl from the shared HTTP auth context (infrastructure only).
    struct wd_request_context *req_ctx = wd_request_context_new(
        context->base,
        context->ssl,
        get_auth_server()->authserv_use_ssl);
    if (!req_ctx) {
        debug(LOG_ERR, "Failed to create request context for login");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
        free(uri);
        return;
    }

    // Keep the live client list node: login must update firewall and list state
    // on the real entry (unlike logout, which only needs a snapshot for id lookup).
    req_ctx->data = client;
    req_ctx->clt_req = req;

    // Setup and send auth server request
    struct evhttp_connection *wd_evcon = NULL;
    struct evhttp_request *wd_req = NULL;

    /* wd_make_request returns 0 on success, non-zero on failure. */
    if (wd_make_request(req_ctx, &wd_evcon, &wd_req, process_auth_server_login)) {
        debug(LOG_ERR, "Failed to create auth server login request");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
        req_ctx->data = NULL;
        req_ctx->clt_req = NULL;
        wd_request_context_destroy(req_ctx);
    } else if (evhttp_make_request(wd_evcon, wd_req, EVHTTP_REQ_GET, uri) != 0) {
        debug(LOG_ERR, "Failed to queue auth server login request");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        if (wd_req) evhttp_request_free(wd_req);
        if (wd_evcon) evhttp_connection_free(wd_evcon);
        safe_client_list_delete(client);
        req_ctx->data = NULL;
        req_ctx->clt_req = NULL;
        wd_request_context_destroy(req_ctx);
    }
    /* On success: process_auth_server_login owns req_ctx and destroys it when done. */

    free(uri);
}
