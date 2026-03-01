
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WS_THREAD_H_
#define _WS_THREAD_H_

#include <stdint.h>

/**
 * Maximum size of WebSocket output buffer in bytes
 */
#define MAX_OUTPUT (512*1024)
#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_HEARTBEAT_INTERVAL 60

/**
 * Network byte order conversion for 64-bit integers
 * Handles both big and little endian architectures
 */
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

#define WS_KEY_LEN 		24
#define WS_ACCEPT_LEN 	28

struct ws_header {
    uint8_t fin;               // Final fragment flag
    uint8_t rsv1;              // Reserved flag 1
    uint8_t rsv2;              // Reserved flag 2
    uint8_t rsv3;              // Reserved flag 3
    uint8_t opcode;            // Opcode
    uint8_t mask;              // Masking flag
    uint64_t payload_length;   // Payload length
    uint8_t masking_key[4];    // Masking key
};

// Forward declaration of WebSocket frame types
enum WebSocketFrameType {
    ERROR_FRAME = 0xFF,
    INCOMPLETE_DATA = 0xFE,
    CLOSING_FRAME = 0x8,
    INCOMPLETE_FRAME = 0x81,
    TEXT_FRAME = 0x1,
    BINARY_FRAME = 0x2,
    PING_FRAME = 0x9,
    PONG_FRAME = 0xA
};

void thread_websocket(void *arg);
void ws_request_reconnect(void);

// WebSocket utility functions for handlers
void ws_send(struct evbuffer *buf, const char *msg, const size_t len, enum WebSocketFrameType frame_type);

#endif