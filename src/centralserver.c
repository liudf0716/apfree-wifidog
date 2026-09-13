// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "wd_util.h"
#include "auth.h"
#include "conf.h"
#include "centralserver.h"
#include "firewall.h"
#include "debug.h"
#include "client_list.h"
#include <limits.h>

static time_t
client_last_activity(const t_client *client)
{
    if (!client)
        return 0;

    return (client->counters6.last_updated > client->counters.last_updated)
               ? client->counters6.last_updated
               : client->counters.last_updated;
}

static void
client_counter_request_reply_v2(t_authresponse *authresponse,
    struct evhttp_request *req, struct wd_request_context *context)
{
    s_config *config = config_get_config();

    (void)req;
    (void)context;

    LOCK_CLIENT_LIST();
    t_client *client = client_list_find_by_client_id(authresponse->client_id);
    if (!client) {
        UNLOCK_CLIENT_LIST();
        return;
    }

    time_t current_time = time(NULL);
    time_t last_activity = client_last_activity(client);
    time_t idle_time = current_time - last_activity;
    time_t timeout = config->checkinterval * config->clienttimeout;

    t_client *client_snapshot = client_dup(client);
    UNLOCK_CLIENT_LIST();

    if (!client_snapshot) {
        debug(LOG_ERR, "Failed to duplicate client snapshot");
        return;
    }

    if (idle_time >= timeout) {
        debug(LOG_DEBUG, "Client %s timed out after %ld seconds of inactivity",
            client_snapshot->ip, idle_time);
        logout_client(client_snapshot);
        client_free_node(client_snapshot);
    } else {
        fw_client_process_from_authserver_response(authresponse, client_snapshot);
        client_free_node(client_snapshot);
    }
}

static void
handle_json_object_from_auth_server(json_object *j_result, struct evhttp_request *req, void *ctx)
{
    json_object *j_gw_id = json_object_object_get(j_result, "gw_id");
    json_object *j_auth_op = json_object_object_get(j_result, "auth_op");

    if (!j_gw_id || !j_auth_op || json_object_get_type(j_auth_op) != json_type_array) {
        debug(LOG_ERR, "Invalid JSON object format from auth server");
        return;
    }

    int auth_op_count = json_object_array_length(j_auth_op);
    for (int idx = 0; idx < auth_op_count; idx++) {
        json_object *j_op = json_object_array_get_idx(j_auth_op, idx);
        if (!j_op) continue;

        json_object *j_id = json_object_object_get(j_op, "id");
        json_object *j_auth_code = json_object_object_get(j_op, "auth_code");
        if (!j_id || !j_auth_code) continue;

        t_authresponse authresponse = {
            .client_id = json_object_get_int64(j_id),
            .authcode = json_object_get_int(j_auth_code),
            .qos_present = 0,
            .qos_downrate_bps = 0,
            .qos_uprate_bps = 0
        };
        {
            json_object *j_qos_present = json_object_object_get(j_op, "qos_present");
            json_object *j_down = json_object_object_get(j_op, "downrate_bps");
            json_object *j_up = json_object_object_get(j_op, "uprate_bps");
            if (j_qos_present && json_object_get_boolean(j_qos_present) &&
                j_down && j_up) {
                int64_t down = json_object_get_int64(j_down);
                int64_t up = json_object_get_int64(j_up);
                if (down < 0) down = 0;
                if (up < 0) up = 0;
                if (down > UINT32_MAX) down = UINT32_MAX;
                if (up > UINT32_MAX) up = UINT32_MAX;
                authresponse.qos_present = 1;
                authresponse.qos_downrate_bps = (uint32_t)down;
                authresponse.qos_uprate_bps = (uint32_t)up;
            }
        }
        client_counter_request_reply_v2(&authresponse, req, ctx);
    }
}

static void
handle_json_array_from_auth_server(json_object *j_result, struct evhttp_request *req, void *ctx)
{
    if (json_object_get_type(j_result) != json_type_array) {
        debug(LOG_ERR, "Expected JSON array from auth server");
        return;
    }

    int result_count = json_object_array_length(j_result);
    for (int idx = 0; idx < result_count; idx++) {
        json_object *j_op = json_object_array_get_idx(j_result, idx);
        if (j_op) {
            handle_json_object_from_auth_server(j_op, req, ctx);
        }
    }
}

void
process_auth_server_counter_v2_json(json_object *json_response, struct wd_request_context *context)
{
    if (!json_response) {
        debug(LOG_ERR, "Failed to parse JSON counter response");
        return;
    }

    json_object *result_array = NULL;
    if (!json_object_object_get_ex(json_response, "result", &result_array)) {
        debug(LOG_ERR, "No 'result' field in JSON counter response");
        return;
    }

    handle_json_array_from_auth_server(result_array, NULL, context);
}
