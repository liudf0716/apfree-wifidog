// SPDX-License-Identifier: GPL-3.0-only
#ifndef _API_HANDLERS_INTERNAL_H_
#define _API_HANDLERS_INTERNAL_H_

#include "api_handlers.h"

void send_json_response(api_transport_context_t *transport, json_object *j_response);
int send_response(api_transport_context_t *transport, const char *message);
int run_command_capture(const char *cmd, char **out_str, int *exit_status);

#endif /* _API_HANDLERS_INTERNAL_H_ */
