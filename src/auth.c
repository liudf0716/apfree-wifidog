
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
thread_client_timeout_check(const void *arg)
{
    wd_request_loop(client_timeout_check_cb);
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

    // Generate logout URI for this client
    char *uri = get_auth_uri(REQUEST_TYPE_LOGOUT, ONLINE_CLIENT, client);
    if (!uri) {
        debug(LOG_ERR, "Failed to generate logout URI");
        return;
    }

    debug(LOG_DEBUG, "Processing logout request with URI [%s]", uri);

    // Setup auth server request
    struct evhttp_connection *evcon = NULL;
    struct evhttp_request *req = NULL;
    
    assert(context->data == NULL);
    context->data = client;

    if (!wd_make_request(context, &evcon, &req, process_auth_server_logout)) {
        evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
    } else {
        debug(LOG_ERR, "Failed to create auth server request");
        context->data = NULL;
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
 * @param context Request context containing connection state and callbacks
 * @param client The client to be authenticated
 * 
 * @note The function will free the client structure if authentication fails
 * @note context->data and context->clt_req are modified by this function
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

    // Validate context state
    if (context->data != NULL) {
        debug(LOG_WARNING, "Context data not NULL, potential memory leak");
        context->data = NULL;
    }

    // Setup request context
    context->data = client;
    context->clt_req = req;

    // Setup and send auth server request
    struct evhttp_connection *wd_evcon = NULL;
    struct evhttp_request *wd_req = NULL;
    
    if (!wd_make_request(context, &wd_evcon, &wd_req, process_auth_server_login)) {
        evhttp_make_request(wd_evcon, wd_req, EVHTTP_REQ_GET, uri);
    } else {
        debug(LOG_ERR, "Failed to create auth server request");
        evhttp_send_error(req, HTTP_INTERNAL, "Internal Server Error");
        safe_client_list_delete(client);
        context->data = NULL;
        context->clt_req = NULL;
    }
    
    free(uri);
}

