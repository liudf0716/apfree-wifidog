
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _WDCTL_THREAD_H_
#define _WDCTL_THREAD_H_

#define DEFAULT_WDCTL_SOCK	"/tmp/wdctl.sock"

/** @brief Listen for WiFiDog control messages on a unix domain socket */
void thread_wdctl(void *arg);

void close_wdctl_socket();

void user_cfg_save(void);

void clear_untrusted_maclist(void);
void add_untrusted_maclist(const char *args);
void del_untrusted_maclist(const char *args);

char *show_trusted_maclist(void);
void clear_trusted_maclist(void);
void add_trusted_maclist(const char *args);
void del_trusted_maclist(const char *args);

char *show_trusted_local_maclist(void);
void clear_trusted_local_maclist(void);
void add_trusted_local_maclist(const char *args);
void del_trusted_local_maclist(const char *args);

char *show_trusted_domains(void);
void add_trusted_domains(const char *args);
void del_trusted_domains(const char *args);

char *show_trusted_iplist(void);
void clear_trusted_iplist(void);
void del_trusted_iplist(const char *args);
void add_trusted_iplist(const char *args);

char *show_trusted_pdomains(void);
void clear_trusted_pdomains(void);
void add_trusted_pdomains(const char *args);
void del_trusted_pdomains(const char *args);


#endif
