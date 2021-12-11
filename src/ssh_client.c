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
/** @file https_server.h
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com> 
 */

#include "ssh_client.h"

struct libssh_client *new_libssh_client(char *srv_ip, short srv_port, char ch_end, char *username, char *password)
{
  struct libssh_client *ssh_client = malloc(sizeof(struct libssh_client));
  memset(ssh_client, 0, sizeof(struct libssh_client));
  
}

void free_libssh_client(struct libssh_client *ssh_client)
{
  if (!ssh_client) return;
  if(ssh_client->username) free(ssh_client->username);
  if(ssh_client->password) free(ssh_client->password);
  if(ssh_client->m_channel) libssh2_channel_free(ssh_client->m_channel);
  if(ssh_client->m_session) {
    libssh2_session_disconnect(ssh_client->m_session, "Bye, Thank you");
    libssh2_session_free(ssh_client->m_session);
  }
  if(ssh_client->m_sock > 0) {
    close(ssh_client-);
  }
  libssh2_exit();
  free(ssh_client);
}
