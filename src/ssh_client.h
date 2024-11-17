
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef _SSH_CLIENT_
#define _SSH_CLIENT_


#include <libssh2.h>

#define	IPV4_LENGTH				16
#define	DEFAULT_SSH_PORT		22
#define	CHANNEL_READ_TIMTOUT	3000

struct libssh_client {
	int		m_sock;
	char 	srv_ip[IPV4_LENGTH];
	short	srv_port;
	char	ch_end;
	char	reserve;
	char	*username;
	char	*password;
	LIBSSH2_SESSION	*m_session;
	LIBSSH2_CHANNEL	*m_channel;
};

struct libssh_client *new_libssh_client(char *srv_ip, short srv_port, char ch_end, char *username, char *password);

void free_libssh_client(struct libssh_client *ssh_client);

int ssh_client_connect(struct libssh_client *ssh_client);

char* ssh_client_create_channel(struct libssh_client *ssh_client, char *pty_type);

char* ssh_client_channel_read(struct libssh_client *ssh_client, int timeout);

int ssh_client_channel_write(struct libssh_client *ssh_client, char *data, int len);

#endif

