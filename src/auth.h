
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
 * Authentication result codes returned by auth_server_request() corresponding
 * to result code from the central server itself.
 */
typedef enum {
    AUTH_ERROR = -1, /**< An error occured during the validation process*/
    AUTH_DENIED = 0, /**< Client was denied by the auth server */
    AUTH_ALLOWED = 1, /**< Client was granted access by the auth server */
    AUTH_VALIDATION = 5, /**< A misnomer.  Client is in 15 min probation to validate his new account */
    AUTH_VALIDATION_FAILED = 6, /**< Client had X minutes to validate account by email and didn't = too late */
    AUTH_LOCKED = 254 /**< Account has been locked */
} t_authcode;

/** 
 * @brief This structure contains all the information returned by the  authentication server
 */
typedef struct _t_authresponse {
    t_authcode authcode; /**< Authentication code returned by the server */
    unsigned long long client_id;
} t_authresponse;

struct wd_request_context;

/** @brief Logout a client and report to auth server. */
void ev_logout_client(struct wd_request_context *, t_client *);
/** @brief Authenticate a single client against the central server */
void ev_authenticate_client(struct evhttp_request *, struct wd_request_context *, t_client *);

/** @brief Periodically check if connections expired */
void thread_client_timeout_check(const void *arg);

#endif
