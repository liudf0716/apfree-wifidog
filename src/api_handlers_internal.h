// SPDX-License-Identifier: GPL-3.0-only
#ifndef _API_HANDLERS_INTERNAL_H_
#define _API_HANDLERS_INTERNAL_H_

#include "api_handlers.h"

void send_json_response(api_transport_context_t *transport, json_object *j_response);
int send_response(api_transport_context_t *transport, const char *message);
void api_transport_set_req_id(api_transport_context_t *transport, json_object *req_id);
int run_command_capture(const char *cmd, char **out_str, int *exit_status);
json_object *api_response_new(const char *type);
json_object *api_response_get_data(json_object *j_response);
void api_response_set_success(json_object *j_response, const char *message);
void api_response_set_error(json_object *j_response, int code, const char *message);

#endif /* _API_HANDLERS_INTERNAL_H_ */
