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

/* $Id$ */
/** @file wdctl_thread.h
    @brief WiFiDog monitoring thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
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
void clear_trusted_domains(void);
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
