/* vim: set et ts=4 sts=4 sw=4 : */
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

/** @file util.h
    @brief Misc utility functions
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#ifndef _UTIL_H_
#define _UTIL_H_

#include <sys/types.h>
#include <sys/socket.h>
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

int is_valid_ip(const char *);

int is_valid_ip6(const char *);

bool is_valid_mac(const char *);

int wd_connect(int, const struct sockaddr *, socklen_t, int);

float get_cpu_usage();

void wd_sleep(unsigned, unsigned );

#endif                          /* _UTIL_H_ */
