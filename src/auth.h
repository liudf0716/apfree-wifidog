
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _AUTH_H_
#define _AUTH_H_

#include <stdint.h>
#include "client_list.h"

typedef enum {
    AUTH_ERROR = -1,
    AUTH_DENIED = 0,
    AUTH_ALLOWED = 1,
    AUTH_VALIDATION = 5,
    AUTH_VALIDATION_FAILED = 6,
    AUTH_LOCKED = 254
} t_authcode;

typedef struct _t_authresponse {
    t_authcode authcode;
    unsigned long long client_id;
    int qos_present;
    uint32_t qos_downrate_bps;
    uint32_t qos_uprate_bps;
} t_authresponse;

/** Deny locally and notify AWAS over the long connection. */
void logout_client(t_client *client);

#endif
