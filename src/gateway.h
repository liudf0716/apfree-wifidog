
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _GATEWAY_H_
#define _GATEWAY_H_

struct redir_file_buffer {
    char    *front;
    int     front_len;
    char    *rear;
    int     rear_len;
};

void sigchld_handler(int s);
void append_x_restartargv(void);


/** @brief actual program entry point. */
int gw_main(int, char **);

/** @brief exits cleanly and clear the firewall rules. */
void termination_handler(int s);

#endif                          /* _GATEWAY_H_ */
