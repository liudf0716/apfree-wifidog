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

/** @file wd_util.h
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#ifndef _WD_UTIL_H_
#define _WD_UTIL_H_

/** @brief Client server this session. */
extern long served_this_session;

/** @brief Sets hint that an online action (dns/connect/etc using WAN) succeeded */
void mark_online(void);

/** @brief Sets hint that an online action (dns/connect/etc using WAN) failed */
void mark_offline(void);

/** @brief Returns a guess (true or false) on whether we're online or not based on previous calls to mark_online and mark_offline */
int is_online(void);

/** @brief Sets hint that an auth server online action succeeded */
void mark_auth_online(void);

/** @brief Sets hint that an auth server online action failed */
void mark_auth_offline(void);

/** @brief Returns a guess (true or false) on whether we're an auth server is online or not based on previous calls to mark_auth_online and mark_auth_offline */
int is_auth_online(void);

/** @brief Creates a human-readable paragraph of the status of wifidog */
char *get_status_text(void);

#endif /* _WD_UTIL_H_ */
