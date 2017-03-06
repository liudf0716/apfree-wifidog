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

/** @file debug.h
    @brief Debug output routines
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#ifndef _WIFIDOG_DEBUG_H_
#define _WIFIDOG_DEBUG_H_

#include <string.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

typedef struct _debug_conf {
    int debuglevel;      /**< @brief Debug information verbosity */
    int log_stderr;      /**< @brief Output log to stdout */
    int log_syslog;      /**< @brief Output log to syslog */
    int syslog_facility; /**< @brief facility to use when using syslog for logging */
} debugconf_t;

extern debugconf_t debugconf;


/** Used to output messages.
 * The messages will include the filename and line number, and will be sent to syslog if so configured in the config file 
 * @param level Debug level
 * @param format... sprintf like format string
 */

#define debug(level, format...) _debug(__FILENAME__, __LINE__, level, format)

/** @internal */
void _debug(const char *, int, int, const char *, ...);

#endif /* _DEBUG_H_ */
