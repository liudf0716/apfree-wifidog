
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>
#include <sys/socket.h>

/** @brief Initialize the ICMP socket */
int init_icmp_socket(void);

/** @brief Close the ICMP socket. */
void close_icmp_socket(void);

/** @brief ICMP Ping an IP */
void icmp_ping(const char *);

void icmp6_ping(const char *);

/** @brief Save pid of this wifidog in pid file */
void save_pid_file(const char *);

int is_valid_ip(const char *);

int is_valid_ip6(const char *);

int is_valid_mac(const char *);

int wd_connect(int, const struct sockaddr *, socklen_t, int);

float get_cpu_usage();

#endif                          /* _UTIL_H_ */
