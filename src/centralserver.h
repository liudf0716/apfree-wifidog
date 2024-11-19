
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

/* Request type definitions */
#define REQUEST_TYPE_LOGIN         "login"
#define REQUEST_TYPE_LOGOUT        "logout"
#define REQUEST_TYPE_COUNTERS      "counters"
#define REQUEST_TYPE_COUNTERS_V2   "counters_v2"

/* Gateway message definitions */
#define GATEWAY_MESSAGE_DENIED                     "denied"
#define GATEWAY_MESSAGE_ACTIVATE_ACCOUNT           "activate"
#define GATEWAY_MESSAGE_ACCOUNT_VALIDATION_FAILED  "failed_validation"

/* Type definitions */
typedef enum {
    ONLINE_CLIENT,
    TRUSTED_CLIENT
} client_type_t;

struct roam_req_info {
    char ip[HTTP_IP_ADDR_LEN];
    char mac[HTTP_MAC_LEN];
};

typedef struct roam_req_info auth_req_info;

/* Forward declarations */
struct evhttp_request;
struct wd_request_context;

/* Authentication URI functions */
char *get_auth_uri(const char *url, client_type_t type, void *info);
char *get_auth_counter_v2_uri(void);

/* Request handler functions */
void make_roam_request(struct wd_request_context *context, struct roam_req_info *info);
void make_auth_request(struct wd_request_context *context, auth_req_info *info);

/* Response processor functions */
void process_auth_server_login(struct evhttp_request *req, void *ctx);
void process_auth_server_logout(struct evhttp_request *req, void *ctx);
void process_auth_server_counter(struct evhttp_request *req, void *ctx);
void process_auth_server_counter_v2(struct evhttp_request *req, void *ctx);

#endif /* _CENTRALSERVER_H_ */
