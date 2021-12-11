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

#define	DEFAULT_SSH_PORT	22

char *s_password;

static void S_KbdCallback(const char *name, int name_len,
                         const char *instruction, int instruction_len,
                         int num_prompts,
                         const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                         LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                         void **abstract)
{
    (void)name;
    (void)name_len;
    (void)instruction;
    (void)instruction_len;
    if (num_prompts == 1)
    {
        responses[0].text   = s_password;
        responses[0].length = strlen(s_password);
    }
    (void)prompts;
    (void)abstract;
}

struct libssh_client *new_libssh_client(char *srv_ip, short srv_port, char ch_end, char *username, char *password)
{
	if (!srv_ip || !usename || !password)
		return NULL;
	
  struct libssh_client *ssh_client = malloc(sizeof(struct libssh_client));
  memset(ssh_client, 0, sizeof(struct libssh_client));
  strncpy(ssh_client->srv_ip, srv_ip, IPV4_LENGTH-1);
	ssh_client->srv_port 	= srv_port == 0?DEFAULT_SSH_PORT:srv_port;
	ssh_client->ch_end 		= ch_end;
	ssh_client->username	= strdup(username);
	ssh_client->password	= strdup(password);
	s_password = ssh_client->password;
	libssh2_init(0);
	
	return ssh_client;
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

int ssh_client_connect(struct libssh_client *ssh_client)
{
	ssh_client->m_sock = socket(AF_INET, SOCK_STREAM, 0);

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(ssh_client->srv_port);
	sin.sin_addr.s_addr = inet_addr(ssh_client->srv_ip);
	if ( connect( ssh_client->m_sock, (sockaddr*)(&sin), sizeof(sockaddr_in) ) != 0 )
	{
			free_libssh_client(ssh_client);
			return 0;
	}

	m_session = libssh2_session_init();
	if ( libssh2_session_handshake(m_session, m_sock) )
	{
			free_libssh_client(ssh_client);
			return 0;
	}

	int auth_pw = 0;
	char *fingerprint = libssh2_hostkey_hash(ssh_client->m_session, LIBSSH2_HOSTKEY_HASH_SHA1);
	char *userauthlist = libssh2_userauth_list( m_session, userName.c_str(), (int)userName.size() );
	if ( strstr( userauthlist, "password") != NULL )
	{
			auth_pw |= 1;
	}
	if ( strstr( userauthlist, "keyboard-interactive") != NULL )
	{
			auth_pw |= 2;
	}
	if ( strstr(userauthlist, "publickey") != NULL)
	{
			auth_pw |= 4;
	}

	if (auth_pw & 1)
	{
		 /* We could authenticate via password */
			if ( libssh2_userauth_password(ssh_client->m_session, ssh_client->username, ssh_client->password ) )
			{
					free_libssh_client(ssh_client);
					return 0;
			}
	}
	else if (auth_pw & 2)
	{
		 /* Or via keyboard-interactive */
			s_password = userPwd;
			if (libssh2_userauth_keyboard_interactive(ssh_client->m_session, ssh_client->username, &S_KbdCallback) )
			{
					free_libssh_client(ssh_client);
					return 0;
			}
	}
	else
	{
			free_libssh_client(ssh_client);
			return 0;
	}

	return 1;
}

void ssh_client_create_channel(struct libssh_client *ssh_client, char *pty_type)
{
	// request a shell
	ssh_client->m_channel = libssh2_channel_open_session(ssh_client->m_session);
	if (!ssh_client->m_channel) {
		return;
	}
	
	/* Request a terminal with pty_type terminal emulation
	 * See/etc/termcap for more options
	 */
	if ( libssh2_channel_request_pty(ssh_client->m_channel, pty_type==NULL?"vanilla":pty_type ) )
	{
			libssh2_channel_free(ssh_client->m_channel);
			return;
	}

   /* Open a SHELL on that pty */
	if ( libssh2_channel_shell(ssh_client->m_channel) )
	{
			libssh2_channel_free(ssh_client->m_channel);
			return;
	}
}

char* ssh_client_channel_read(struct libssh_client *ssh_client, int timeout)
{
	char *data = NULL;
	LIBSSH2_POLLFD *fds = new LIBSSH2_POLLFD;
	fds->type = LIBSSH2_POLLFD_CHANNEL;
	fds->fd.channel = m_channel;
	fds->events = LIBSSH2_POLLFD_POLLIN | LIBSSH2_POLLFD_POLLOUT;
	
	if( timeout % 50 )
	{
			timeout += timeout %50;
	}
	
	while(timeout>0)
	{
			int rc = (libssh2_poll(fds, 1, 10));
			if (rc < 1)
			{
					timeout -= 50;
					usleep(50*1000);
					continue;
			}

			if ( fds->revents & LIBSSH2_POLLFD_POLLIN )
			{
					char buffer[64*1024] = {0};
					size_t n = libssh2_channel_read( m_channel, buffer, sizeof(buffer) );
					if ( n == LIBSSH2_ERROR_EAGAIN )
					{
						 //fprintf(stderr, "will read again\n");
					}
					else if (n <= 0)
					{
							return data;
					}
					else
					{
							data += std::string(buffer);
							if( "" == strend )
							{
									return data;
							}
							size_t pos = data.rfind(strend);
							if( pos != std::string::npos && data.substr(pos, strend.size()) == strend  )
							{
									return data;
							}
					}
			}
			timeout -= 50;
			usleep(50*1000);
	}
}

int ssh_client_channel_write(struct libssh_client *ssh_client, char *data, int len)
{
}
