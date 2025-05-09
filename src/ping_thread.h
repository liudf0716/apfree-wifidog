
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _PING_THREAD_H_
#define _PING_THREAD_H_

#define MINIMUM_STARTED_TIME 1041379200 /* 2003-01-01 */
#define SSID_LENGTH         32

struct sys_info {
    unsigned long int   sys_uptime;
    unsigned int        sys_memfree;  
    unsigned long int   nf_conntrack_count;
    unsigned long int   wifidog_uptime;
    float   sys_load;
    float   cpu_usage;
};

/** @brief get system info */
void get_sys_info(struct sys_info *);
/** @brief get ping uri */
char *get_ping_uri(const struct sys_info *, t_gateway_setting *);
char *get_ping_v2_uri(const struct sys_info *);
/** @brief Periodically checks on the auth server to see if it's alive. */
void thread_ping(void *);

#endif
