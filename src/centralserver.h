
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

#include <json-c/json.h>

/** @brief Ask the central server to login a client */
#define REQUEST_TYPE_LOGIN     "login"
/** @brief Notify the the central server of a client logout */
#define REQUEST_TYPE_LOGOUT    "logout"
/** @brief Update the central server's traffic counters */
#define REQUEST_TYPE_COUNTERS  "counters"
/** @brief New version of updating the central server's traffic counters*/
#define REQUEST_TYPE_COUNTERS_V2    "counters_v2"

/** @brief Sent when the user's token is denied by the central server */
#define GATEWAY_MESSAGE_DENIED     "denied"
/** @brief Sent when the user's token is accepted, but user is on probation  */
#define GATEWAY_MESSAGE_ACTIVATE_ACCOUNT     "activate"
/** @brief  Sent when the user's token is denied by the central server because the probation period is over */
#define GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED     "failed_validation"
/** @brief Sent after the user performed a manual log-out on the gateway  */
#define GATEWAY_MESSAGE_ACCOUNT_LOGGED_OUT     "logged-out"

typedef enum {
    ONLINE_CLIENT,
    TRUSTED_CLIENT
} client_type_t;

struct roam_req_info {
    char ip[HTTP_IP_ADDR_LEN];
    char mac[HTTP_MAC_LEN];
};

typedef struct roam_req_info auth_req_info;

struct evhttp_request;
struct wd_request_context;


/** @brief wifidog make roam quest to auth server */
void make_roam_request(struct wd_request_context *, struct roam_req_info *);
/** @brief wifidog make auth quest to auth server */
void make_auth_request(struct wd_request_context *, auth_req_info *);
/** @brief get client's auth uri */
char *get_auth_uri(const char *, client_type_t , void *);

/** @brief process wifidog's client logout response */
void process_auth_server_logout(struct evhttp_request *, void *);
/** @brief process wifidog's client login response */
void process_auth_server_login(struct evhttp_request *, void *);
/** @brief process wifidog's client counter response */
void process_auth_server_counter(struct evhttp_request *, void *);
/** @brief process v2 of wifidog's client counter response */
void process_auth_server_counter_v2(struct evhttp_request *, void *);
/** @brief get auth counter v2 uri*/
char *get_auth_counter_v2_uri(void);

#endif                          /* _CENTRALSERVER_H_ */
