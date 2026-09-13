// SPDX-License-Identifier: GPL-3.0-only
#ifndef _LONG_CONN_H_
#define _LONG_CONN_H_

#include <json-c/json.h>

/** Record a successful application-level ACK from AWAS (heartbeat/counters). */
void long_conn_note_ack(void);

/**
 * True when MQTT or WebSocket is up and AWAS has ACKed within the stale window.
 * HTTP ping/counter should be skipped while this is true.
 */
int long_conn_is_healthy(void);

/** Handle a c2s/response JSON object from MQTT or WebSocket. */
void long_conn_handle_server_response(json_object *jobj);

/** Build and publish counters_v2 payload on the active long connection. */
void long_conn_publish_counters(void);

/** Notify AWAS that a client logged out on the gateway. */
void long_conn_publish_logout(const char *gw_id, const char *mac, const char *ip);

#endif
