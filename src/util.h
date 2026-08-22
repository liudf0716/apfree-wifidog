
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <stddef.h>
#include <stdbool.h>

/** @brief Initialize the ICMP socket */
int init_icmp_socket(void);

/** @brief Close the ICMP socket. */
void close_icmp_socket(void);

/** @brief ICMP Ping an IP */
void icmp_ping(const char *);

void icmp6_ping(const char *);

/** @brief Save pid of this wifidog in pid file */
void save_pid_file(const char *);

bool is_valid_ip(const char *);

bool is_valid_ip6(const char *);

bool is_valid_mac(const char *);

/** Normalize MAC to lowercase colon form (aa:bb:cc:dd:ee:ff). */
int normalize_mac(const char *mac, char *out, size_t out_len);

float get_cpu_usage();

bool is_file_exist(const char *file);

#endif                          /* _UTIL_H_ */
