
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _GATEWAY_H_
#define _GATEWAY_H_

/**
 * @brief Structure to hold redirect file buffer data
 */
typedef struct {
    char    *front;         /**< Front buffer content */
    int     front_len;      /**< Length of front buffer */
    char    *rear;          /**< Rear buffer content */
    int     rear_len;       /**< Length of rear buffer */
} redir_file_buffer_t;

/**
 * @brief Handler for SIGCHLD signals
 * @param s Signal number
 */
void sigchld_handler(int s);

/**
 * @brief Appends restart arguments to program
 */
void append_x_restartargv(void);

/**
 * @brief Main entry point for the gateway
 * @param argc Argument count
 * @param argv Argument vector
 * @return Program exit status
 */
int gw_main(int argc, char **argv);

/**
 * @brief Handles program termination and cleanup
 * @param s Signal number
 */
void termination_handler(int s);

#endif                          /* _GATEWAY_H_ */
