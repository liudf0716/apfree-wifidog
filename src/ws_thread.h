
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WS_THREAD_H_
#define _WS_THREAD_H_

#include <stdint.h>

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

void start_ws_thread(void *arg);

void stop_ws_thread();

#endif