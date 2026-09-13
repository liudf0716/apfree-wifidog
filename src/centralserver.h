
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _CENTRALSERVER_H_
#define _CENTRALSERVER_H_

#include <json-c/json.h>

struct wd_request_context;

void process_auth_server_counter_v2_json(json_object *json_response, struct wd_request_context *context);

#endif /* _CENTRALSERVER_H_ */
