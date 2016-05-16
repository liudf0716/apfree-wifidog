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
/** @file wdctl_thread.c
    @brief Monitoring and control of wifidog, server part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "common.h"
#include "httpd.h"
#include "util.h"
#include "wd_util.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw_iptables.h"
#include "firewall.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "commandline.h"
#include "gateway.h"
#include "safe.h"


static int create_unix_socket(const char *);
static int write_to_socket(int, char *, size_t);
static void *thread_wdctl_handler(void *);
static void wdctl_status(int);
static void wdctl_stop(int);
static void wdctl_reset(int, const char *);
static void wdctl_restart(int);
//>>> liudf added 20151225
static void wdctl_add_trusted_domains(int, const char *);
static void wdctl_del_trusted_domains(int, const char *);
static void wdctl_add_trusted_iplist(int, const char *);
static void wdctl_clear_trusted_iplist(int);
static void wdctl_reparse_trusted_domains(int);
static void wdctl_clear_trusted_domains(int);
static void wdctl_show_trusted_domains(int);
static void wdctl_add_domain_ip(int, const char *);
static void wdctl_add_roam_maclist(int, const char *);
static void wdctl_show_roam_maclist(int);
static void wdctl_clear_roam_maclist(int);
static void wdctl_add_trusted_maclist(int, const char *);
static void wdctl_show_trusted_maclist(int);
static void wdctl_clear_trusted_maclist(int);
static void wdctl_add_untrusted_maclist(int, const char *);
static void wdctl_show_untrusted_maclist(int);
static void wdctl_clear_untrusted_maclist(int);
static void wdctl_user_cfg_save(int);
static void wdctl_add_online_client(int, const char *);
//<<< liudf added end

static int wdctl_socket_server;

void
close_wdctl_socket()
{
	close(wdctl_socket_server);
}

static int
create_unix_socket(const char *sock_name)
{
    struct sockaddr_un sa_un;
    int sock;

    memset(&sa_un, 0, sizeof(sa_un));

    if (strlen(sock_name) > (sizeof(sa_un.sun_path) - 1)) {
        /* TODO: Die handler with logging.... */
        debug(LOG_ERR, "WDCTL socket name too long");
        return -1;
    }

    sock = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);

    if (sock < 0) {
        debug(LOG_DEBUG, "Could not get unix socket: %s", strerror(errno));
        return -1;
    }
    debug(LOG_DEBUG, "Got unix socket %d", sock);

    /* If it exists, delete... Not the cleanest way to deal. */
    unlink(sock_name);

    debug(LOG_DEBUG, "Filling sockaddr_un");
    strcpy(sa_un.sun_path, sock_name);
    sa_un.sun_family = AF_UNIX;

    debug(LOG_DEBUG, "Binding socket (%s) (%d)", sa_un.sun_path, strlen(sock_name));

    /* Which to use, AF_UNIX, PF_UNIX, AF_LOCAL, PF_LOCAL? */
    if (bind(sock, (struct sockaddr *)&sa_un, sizeof(struct sockaddr_un))) {
        debug(LOG_ERR, "Could not bind unix socket: %s", strerror(errno));
        close(sock);
        return -1;
    }

    if (listen(sock, 5)) {
        debug(LOG_ERR, "Could not listen on control socket: %s", strerror(errno));
        close(sock);
        return -1;
    }
    return sock;
}

/** Launches a thread that monitors the control socket for request
@param arg Must contain a pointer to a string containing the Unix domain socket to open
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_wdctl(void *arg)
{
    int *fd;
    char *sock_name;
    struct sockaddr_un sa_un;
    int result;
    pthread_t tid;
    socklen_t len;

    debug(LOG_DEBUG, "Starting wdctl.");

    sock_name = (char *)arg;
    debug(LOG_DEBUG, "Socket name: %s", sock_name);

    debug(LOG_DEBUG, "Creating socket");
    wdctl_socket_server = create_unix_socket(sock_name);
    if (-1 == wdctl_socket_server) {
        termination_handler(0);
    }
	
	register_fd_cleanup_on_fork(wdctl_socket_server);

    while (1) {
        len = sizeof(sa_un);
        memset(&sa_un, 0, len);
        fd = (int *)safe_malloc(sizeof(int));
        if ((*fd = accept(wdctl_socket_server, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "Accept failed on control socket: %s", strerror(errno));
            free(fd);
        } else {
            debug(LOG_DEBUG, "Accepted connection on wdctl socket %d (%s)", fd, sa_un.sun_path);
            result = pthread_create(&tid, NULL, &thread_wdctl_handler, (void *)fd);
            if (result != 0) {
                debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl handler) - exiting");
                free(fd);
                termination_handler(0);
            }
            pthread_detach(tid);
        }
    }
}

static void *
thread_wdctl_handler(void *arg)
{
    int fd, done;
    char request[MAX_BUF];
    size_t read_bytes, i;
    ssize_t len;

    debug(LOG_DEBUG, "Entering thread_wdctl_handler....");

    fd = *((int *)arg);
    free(arg);
    debug(LOG_DEBUG, "Read bytes and stuff from %d", fd);

    /* Init variables */
    read_bytes = 0;
    done = 0;
    memset(request, 0, sizeof(request));

    /* Read.... */
    while (!done && read_bytes < (sizeof(request) - 1)) {
        len = read(fd, request + read_bytes, sizeof(request) - read_bytes);
        /* Have we gotten a command yet? */
        for (i = read_bytes; i < (read_bytes + (size_t) len); i++) {
            if (request[i] == '\r' || request[i] == '\n') {
                request[i] = '\0';
                done = 1;
            }
        }

        /* Increment position */
        read_bytes += (size_t) len;
    }

    if (!done) {
        debug(LOG_ERR, "Invalid wdctl request.");
        shutdown(fd, 2);
        close(fd);
        pthread_exit(NULL);
    }

    debug(LOG_DEBUG, "Request received: [%s]", request);

    if (strncmp(request, "status", 6) == 0) {
        wdctl_status(fd);
    } else if (strncmp(request, "stop", 4) == 0) {
        wdctl_stop(fd);
    } else if (strncmp(request, "reset", 5) == 0) {
        wdctl_reset(fd, (request + 6));
    } else if (strncmp(request, "restart", 7) == 0) {
        wdctl_restart(fd);
	//>>> liudf added 20151225
	} else if (strncmp(request, "add_trusted_domains", strlen("add_trusted_domains")) == 0) {
		wdctl_add_trusted_domains(fd, (request + strlen("add_trusted_domains") + 1));

	} else if (strncmp(request, "del_trusted_domains", strlen("del_trusted_domains")) == 0) {
		wdctl_del_trusted_domains(fd, (request + strlen("del_trusted_domains") + 1));

	} else if (strncmp(request, "add_trusted_iplist", strlen("add_trusted_iplist")) == 0) {
		wdctl_add_trusted_iplist(fd, (request + strlen("add_trusted_iplist") + 1));

	} else if (strncmp(request, "clear_trusted_iplist", strlen("clear_trusted_iplist")) == 0) {
		wdctl_clear_trusted_iplist(fd);

	} else if (strncmp(request, "reparse_trusted_domains", strlen("reparse_trusted_domains")) == 0) {
		wdctl_reparse_trusted_domains(fd);

	} else if (strncmp(request, "clear_trusted_domains", strlen("clear_trusted_domains")) == 0) {
		wdctl_clear_trusted_domains(fd);

	} else if (strncmp(request, "show_trusted_domains", strlen("show_trusted_domains")) == 0) {
		wdctl_show_trusted_domains(fd);

	} else if (strncmp(request, "add_domain_ip", strlen("add_domain_ip")) == 0) {
		wdctl_add_domain_ip(fd, (request + strlen("add_domain_ip") + 1));

	} else if (strncmp(request, "add_roam_maclist", strlen("add_roam_maclist")) == 0) {
		wdctl_add_roam_maclist(fd, (request + strlen("add_roam_maclist") + 1));

	} else if (strncmp(request, "show_roam_maclist", strlen("show_roam_maclist")) == 0) {
		wdctl_show_roam_maclist(fd);

	} else if (strncmp(request, "clear_roam_maclist", strlen("clear_roam_maclist")) == 0) {
		wdctl_clear_roam_maclist(fd);

	} else if (strncmp(request, "add_trusted_mac", strlen("add_trusted_mac")) == 0) {
		wdctl_add_trusted_maclist(fd, (request + strlen("add_trusted_mac") + 1));	

	} else if (strncmp(request, "show_trusted_mac", strlen("show_trusted_maclist")) == 0) {
		wdctl_show_trusted_maclist(fd);

	} else if (strncmp(request, "clear_trusted_mac", strlen("clear_trusted_mac")) == 0) {
		wdctl_clear_trusted_maclist(fd);

	} else if (strncmp(request, "add_untrusted_mac", strlen("add_untrusted_mac")) == 0) {
		wdctl_add_untrusted_maclist(fd, (request + strlen("add_untrusted_mac") + 1));	

	} else if (strncmp(request, "show_untrusted_mac", strlen("show_untrusted_mac")) == 0) {
		wdctl_show_untrusted_maclist(fd);

	} else if (strncmp(request, "clear_untrusted_mac", strlen("clear_untrusted_mac")) == 0) {
		wdctl_clear_untrusted_maclist(fd);
	
	} else if (strncmp(request, "user_cfg_save", strlen("user_cfg_save")) == 0) {
		wdctl_user_cfg_save(fd);

	} else if (strncmp(request, "add_online_client", strlen("add_online_client")) == 0) {
		wdctl_add_online_client(fd, (request + strlen("add_online_client") + 1));

	//<<< liudf added end
    } else {
        debug(LOG_ERR, "Request was not understood!");
    }

    shutdown(fd, 2);
    close(fd);
    debug(LOG_DEBUG, "Exiting thread_wdctl_handler....");

    return NULL;
}

static int
write_to_socket(int fd, char *text, size_t len)
{
    ssize_t retval;
    size_t written;

    written = 0;
    while (written < len) {
        retval = write(fd, (text + written), len - written);
        if (retval == -1) {
            debug(LOG_CRIT, "Failed to write client data to child: %s", strerror(errno));
            return 0;
        } else {
            written += retval;
        }
    }
    return 1;
}

static void
wdctl_status(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_status_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

/** A bit of an hack, self kills.... */
/* coverity[+kill] */
static void
wdctl_stop(int fd)
{
    pid_t pid;

    pid = getpid();
    kill(pid, SIGINT);
}

static void
wdctl_restart(int afd)
{
    int sock, fd;
    char *sock_name;
    s_config *conf = NULL;
    struct sockaddr_un sa_un;
    t_client *client;
    char *tempstring = NULL;
    pid_t pid;
    socklen_t len;

    conf = config_get_config();

    debug(LOG_NOTICE, "Will restart myself");

    /* First, prepare the internal socket */
    sock_name = conf->internal_sock;
    debug(LOG_DEBUG, "Socket name: %s", sock_name);

    debug(LOG_DEBUG, "Creating socket");
    sock = create_unix_socket(sock_name);
    if (-1 == sock) {
        return;
    }

    /*
     * The internal socket is ready, fork and exec ourselves
     */
    debug(LOG_DEBUG, "Forking in preparation for exec()...");
    pid = safe_fork();
    if (pid > 0) {
        /* Parent */

        /* Wait for the child to connect to our socket : */
        debug(LOG_DEBUG, "Waiting for child to connect on internal socket");
        len = sizeof(sa_un);
        if ((fd = accept(sock, (struct sockaddr *)&sa_un, &len)) == -1) {
            debug(LOG_ERR, "Accept failed on internal socket: %s", strerror(errno));
            close(sock);
            return;
        }

        close(sock);

        debug(LOG_DEBUG, "Received connection from child.  Sending them all existing clients");

        /* The child is connected. Send them over the socket the existing clients */
        LOCK_CLIENT_LIST();
        client = client_get_first_client();
        while (client) {
            /* Send this client */
            safe_asprintf(&tempstring,
                          "CLIENT|ip=%s|mac=%s|token=%s|fw_connection_state=%u|fd=%d|counters_incoming=%llu|counters_outgoing=%llu|counters_last_updated=%lu\n",
                          client->ip, client->mac, client->token, client->fw_connection_state, client->fd,
                          client->counters.incoming, client->counters.outgoing, client->counters.last_updated);
            debug(LOG_DEBUG, "Sending to child client data: %s", tempstring);
            write_to_socket(fd, tempstring, strlen(tempstring));        /* XXX Despicably not handling error. */
            free(tempstring);
            client = client->next;
        }
        UNLOCK_CLIENT_LIST();

        close(fd);

        debug(LOG_INFO, "Sent all existing clients to child.  Committing suicide!");

        shutdown(afd, 2);
        close(afd);

        /* Our job in life is done. Commit suicide! */
        wdctl_stop(afd);
    } else {
        /* Child */
        close(wdctl_socket_server);
        close(sock);
        close_icmp_socket();
        shutdown(afd, 2);
        close(afd);
        debug(LOG_NOTICE, "Re-executing myself (%s)", restartargv[0]);
        setsid();
        execvp(restartargv[0], restartargv);
        /* If we've reached here the exec() failed - die quickly and silently */
        debug(LOG_ERR, "I failed to re-execute myself: %s", strerror(errno));
        debug(LOG_ERR, "Exiting without cleanup");
        exit(1);
    }
}

static void
wdctl_reset(int fd, const char *arg)
{
    t_client *node;

    debug(LOG_DEBUG, "Entering wdctl_reset...");

    LOCK_CLIENT_LIST();
    debug(LOG_DEBUG, "Argument: %s (@%x)", arg, arg);

    /* We get the node or return... */
    if ((node = client_list_find_by_ip(arg)) != NULL) ;
    else if ((node = client_list_find_by_mac(arg)) != NULL) ;
    else {
        debug(LOG_DEBUG, "Client not found.");
        UNLOCK_CLIENT_LIST();
        write_to_socket(fd, "No", 2);   /* Error handling in fucntion sufficient. */

        return;
    }

    debug(LOG_DEBUG, "Got node %x.", node);

    /* deny.... */
    logout_client(node);

    UNLOCK_CLIENT_LIST();

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_reset...");
}

//>>> liudf added 20151225
static void
wdctl_add_trusted_iplist(int fd, const char *arg)
{
	debug(LOG_DEBUG, "Entering wdctl_add_trusted_iplist ...");
	
    debug(LOG_DEBUG, "Argument: %s ", arg);

    debug(LOG_DEBUG, "parse trusted ip list");
	add_trusted_ip_list(arg);

	fw_refresh_user_domains_trusted();	

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_add_trusted_domains...");

}

static void
wdctl_clear_trusted_iplist(int fd)
{
	debug(LOG_DEBUG, "Entering wdctl_clear_trusted_domains...");
	
	
	clear_trusted_ip_list();

	fw_refresh_user_domains_trusted();	

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_clear_trusted_domains...");
}

static void
wdctl_add_trusted_domains(int fd, const char *arg)
{
    debug(LOG_DEBUG, "Entering wdctl_add_trusted_domains...");
	

    debug(LOG_DEBUG, "Argument: %s ", arg);

    debug(LOG_DEBUG, "parse trusted domains");
	parse_user_trusted_domain_string(arg);
	
    debug(LOG_DEBUG, "parse trusted domains ip");
	parse_user_trusted_domain_list();

    write_to_socket(fd, "Yes", 3);

	fw_refresh_user_domains_trusted();	

    debug(LOG_DEBUG, "Exiting wdctl_add_trusted_domains...");
}

static void
wdctl_del_trusted_domains(int fd, const char *arg)
{
    debug(LOG_DEBUG, "Entering wdctl_del_trusted_domains...");
	

    debug(LOG_DEBUG, "Argument: %s ", arg);

    debug(LOG_DEBUG, "parse & del trusted domains");
	parse_del_trusted_domain_string(arg);
	
    write_to_socket(fd, "Yes", 3);

	fw_refresh_user_domains_trusted();	

    debug(LOG_DEBUG, "Exiting wdctl_del_trusted_domains...");
}

static void
wdctl_reparse_trusted_domains(int fd)
{
	debug(LOG_DEBUG, "Entering wdctl_reparse_trusted_domains...");
	
    debug(LOG_DEBUG, "parse trusted domains list");
	parse_user_trusted_domain_list();

	fw_refresh_user_domains_trusted();	

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_reparse_trusted_domains...");
}

static void
wdctl_clear_trusted_domains(int fd)
{
	debug(LOG_DEBUG, "Entering wdctl_clear_trusted_domains...");
	
	
	clear_trusted_domains();

	fw_refresh_user_domains_trusted();	

    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_clear_trusted_domains...");
}

static void
wdctl_show_trusted_domains(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_trusted_domains_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

static void
wdctl_add_domain_ip(int fd, const char *args)
{
	add_domain_ip_pair(args, USER_TRUSTED_DOMAIN);

	fw_refresh_user_domains_trusted();	

    write_to_socket(fd, "Yes", 3);
}

// roam maclist
static void
wdctl_add_roam_maclist(int fd, const char *args)
{
    debug(LOG_DEBUG, "Entering wdctl_add_roam_maclist...");
	
    debug(LOG_DEBUG, "Argument: %s ", args);
	
    debug(LOG_DEBUG, "parse roam maclist");
	LOCK_CONFIG();

	parse_roam_mac_list(args);	
	
	UNLOCK_CONFIG();
	
    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_add_roam_maclist...");
}

static void
wdctl_show_roam_maclist(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_roam_maclist_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

static void
wdctl_clear_roam_maclist(int fd)
{
	LOCK_CONFIG();
	__clear_roam_mac_list();	
	
	UNLOCK_CONFIG();	

	fw_clear_roam_maclist();

    write_to_socket(fd, "Yes", 3);
}


// trusted maclist
static void
wdctl_add_trusted_maclist(int fd, const char *args)
{
    debug(LOG_DEBUG, "Entering wdctl_add_trusted_maclist...");
	
    debug(LOG_DEBUG, "Argument: %s ", args);
	
    debug(LOG_DEBUG, "parse trusted maclist");

	parse_trusted_mac_list(args);	
	
	fw_set_trusted_maclist();	
	
    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_add_trusted_maclist...");
}

static void
wdctl_show_trusted_maclist(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_trusted_maclist_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

static void
wdctl_clear_trusted_maclist(int fd)
{
	clear_trusted_mac_list();	

	fw_clear_trusted_maclist();

    write_to_socket(fd, "Yes", 3);
}

// untrusted maclist
static void
wdctl_add_untrusted_maclist(int fd, const char *args)
{
    debug(LOG_DEBUG, "Entering wdctl_add_untrusted_maclist...");
	
    debug(LOG_DEBUG, "Argument: %s ", args);
	
    debug(LOG_DEBUG, "parse untrusted maclist");
	LOCK_CONFIG();

	parse_untrusted_mac_list(args);	
	
	UNLOCK_CONFIG();
	
	fw_clear_untrusted_maclist();	
	fw_set_untrusted_maclist();
	
    write_to_socket(fd, "Yes", 3);

    debug(LOG_DEBUG, "Exiting wdctl_add_untrusted_maclist...");
}

static void
wdctl_show_untrusted_maclist(int fd)
{
    char *status = NULL;
    size_t len = 0;

    status = get_untrusted_maclist_text();
    len = strlen(status);

    write_to_socket(fd, status, len);   /* XXX Not handling error because we'd just print the same log line. */

    free(status);
}

static void
wdctl_clear_untrusted_maclist(int fd)
{
	clear_untrusted_mac_list();	
	
	fw_clear_untrusted_maclist();
    write_to_socket(fd, "Yes", 3);
}


static void
wdctl_user_cfg_save(int fd)
{
	const char *trusted_maclist = NULL, 
			   *untrusted_maclist = NULL, 
			   *trusted_domains = NULL,
			   *trusted_iplist = NULL;
	char	szcmd[4096] = {0};
	
	iptables_fw_save_online_clients();
	

	trusted_maclist 	= get_serialize_maclist(TRUSTED_MAC);
	untrusted_maclist 	= get_serialize_maclist(UNTRUSTED_MAC);
	trusted_domains		= get_serialize_trusted_domains();
	trusted_iplist		= get_serialize_iplist();
	
	if(trusted_domains) {
		snprintf(szcmd, 4096, "uci set wifidog.@wifidog[0].trusted_domains='%s'", trusted_domains);
	} else {
		snprintf(szcmd, 4096, "uci delete wifidog.@wifidog[0].trusted_domains");
	}
	execute(szcmd, 1);
	
	memset(szcmd, 0, 4096);
	if(trusted_iplist) {
		snprintf(szcmd, 4096, "uci set wifidog.@wifidog[0].trusted_iplist='%s'", trusted_iplist);
	} else {
		snprintf(szcmd, 4096, "uci delete wifidog.@wifidog[0].trusted_iplist");
	}
	execute(szcmd, 1);

	memset(szcmd, 0, 4096);
	if(trusted_maclist) {
		snprintf(szcmd, 4096, "uci set wifidog.@wifidog[0].trusted_maclist='%s'", trusted_maclist);
	} else {
		snprintf(szcmd, 4096, "uci delete wifidog.@wifidog[0].trusted_maclist");
	}
	execute(szcmd, 1);

	memset(szcmd, 0, 4096);
	if(untrusted_maclist) {
		snprintf(szcmd, 4096, "uci set wifidog.@wifidog[0].untrusted_maclist='%s'", untrusted_maclist);
	} else {
		snprintf(szcmd, 4096, "uci delete wifidog.@wifidog[0].untrusted_maclist");
	}
	execute(szcmd, 1);

	memset(szcmd, 0, 4096);
	snprintf(szcmd, 4096, "uci commit wifidog");
	execute(szcmd, 1);

    write_to_socket(fd, "Yes", 3);
}

static void
wdctl_add_online_client(int fd, const char *args)
{
	int nret = 0;
    
	nret = add_online_client(args);
	
	if(nret == 0)
    	write_to_socket(fd, "Yes", 3);
	else
		write_to_socket(fd, "No", 2);
}

//>>> liudf added end
