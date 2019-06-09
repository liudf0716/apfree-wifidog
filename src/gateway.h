/* vim: set et sw=4 ts=4 sts=4 : */
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
/** @file gateway.h
    @brief Main loop
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
    @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#ifndef _GATEWAY_H_
#define _GATEWAY_H_

struct redir_file_buffer {
    char    *front;
    int     front_len;
    char    *rear;
    int     rear_len;
};

void sigchld_handler(int s);
void append_x_restartargv(void);


/** @brief actual program entry point. */
int gw_main(int, char **);

/** @brief exits cleanly and clear the firewall rules. */
void termination_handler(int s);

#endif                          /* _GATEWAY_H_ */
