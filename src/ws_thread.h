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