
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _AUTH_H_
#define _AUTH_H_

#include "client_list.h"

/**
 * @brief Authentication codes returned by auth server.
 *
 * Defines possible authentication states returned by the authentication server,
 * ranging from error conditions to successful authentication.
 */
typedef enum {
    AUTH_ERROR = -1,        /**< Authentication process error */
    AUTH_DENIED = 0,        /**< Access denied by auth server */
    AUTH_ALLOWED = 1,       /**< Access granted by auth server */
    AUTH_VALIDATION = 5,    /**< Client in 15-minute probation period */
    AUTH_VALIDATION_FAILED = 6, /**< Failed to validate account within time limit */
    AUTH_LOCKED = 254       /**< Account is locked */
} t_authcode;

/**
 * @brief Authentication response structure
 *
 * Contains the server's response data including authentication status
 * and client identification.
 */
typedef struct _t_authresponse {
    t_authcode authcode;         /**< Authentication result code */
    unsigned long long client_id; /**< Unique client identifier */
} t_authresponse;

struct wd_request_context;

/**
 * @brief Handles client logout process
 * @param context Request context
 * @param client Client to be logged out
 */
void ev_logout_client(struct wd_request_context *context, t_client *client);

/**
 * @brief Processes client authentication
 * @param request HTTP request object
 * @param context Request context
 * @param client Client to authenticate
 */
void ev_authenticate_client(struct evhttp_request *request, 
                          struct wd_request_context *context, 
                          t_client *client);

/**
 * @brief Periodic connection timeout checker
 * @param arg Thread arguments
 */
void thread_client_timeout_check(const void *arg);

#endif
