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

/* $Id$ */
/** @file centralserver.h
    @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
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
