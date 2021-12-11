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

#ifndef _SSH_CLIENT_
#define _SSH_CLIENT_

#include <libssh2.h>

#define	IP_LENGTH	16

struct {
	int		m_sock;
	char 	srv_ip[IP_LENGTH];
	short	srv_port;
	char	ch_end;
	char	reserve;
	char	*username;
	char	*password;
	LIBSSH2_SESSION	*m_session;
	LIBSSH2_CHANNEL	*m_channel;
} libssh_client;

struct libssh_client *new_libssh_client(char *srv_ip, short srv_port, char ch_end, char *username, char *password);

void free_libssh_client(struct libssh_client *ssh_client);

#endif
