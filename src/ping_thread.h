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

/* $Id$ */
/** @file ping_thread.h
    @brief WiFiDog heartbeat thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
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

void get_sys_info(struct sys_info *);

char *get_ping_uri(const struct sys_info *);

char *get_ping_request(const struct sys_info *);

/** @brief Periodically checks on the auth server to see if it's alive. */
void thread_ping(void *arg);

#endif
