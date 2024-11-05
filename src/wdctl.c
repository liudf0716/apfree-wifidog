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
/** @file wdctl.c
    @brief Monitoring and control of wifidog, client part
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
	@author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#define _GNU_SOURCE

#include "common.h"
#include "wdctl.h"
#include "util.h"

#define WDCTL_TIMEOUT   1000*2
#define WDCTL_MSG_LENG  1024*8

static char *sk_name = NULL;
char *progname = NULL;

static void show_command(const char *type);
static void add_command(const char *type, char *values);
static void clear_command(const char *type);
static void display_help();
static void stop_command();
static void reset_command(const char *value);
static void status_command(const char *type);
static void refresh_command();

static void send_request(int, const char *);
static void read_response(int);
static void wdctl_command_action(const char *, const char *);
static int connect_to_server(const char *);

static int
connect_to_server(const char *sock_name)
{
    struct sockaddr_un sa_un;
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stdout, "wdctl: could not get socket (Error: %s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    if (sock_name) {
        strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));
    } else {
        strncpy(sa_un.sun_path, DEFAULT_SOCK, (sizeof(sa_un.sun_path) - 1));
    
    }

    if (wd_connect(sock, (struct sockaddr *)&sa_un, strlen(sa_un.sun_path) + sizeof(sa_un.sun_family), 2)) {
        fprintf(stdout, "wdctl: wifidog probably not started (Error: %s)\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return sock;
}

static void 
send_request(int sock, const char *request)
{
    struct pollfd fds;	
    fds.fd      = sock;
    fds.events  = POLLOUT;

    if (poll(&fds, 1, WDCTL_TIMEOUT) > 0 && fds.revents == POLLOUT) {
        write(sock, request, strlen(request));
    } 
}

/**
 * @brief execute command sending from wdctl_thread after process wdctlx's command
 * usually it execute 'dnsmasq restart', this feature depends openwrt system 
 *      
 */ 
static void
execute_post_cmd(char *raw_cmd)
{
    size_t nlen = strlen(raw_cmd);
    if (nlen < 3) goto ERR;

    char *cmd = NULL;
    if (raw_cmd[0] == '[' && raw_cmd[nlen-1] == ']') {
        raw_cmd[nlen-1] = '\0';
        cmd = raw_cmd + 1;
        system(cmd);
        fprintf(stdout, "execut shell [%s] success", cmd);
        return;
    }

ERR:
    fprintf(stdout, "[%s] is illegal post command", raw_cmd);
}

/**
 * @brief read reponse from wdctl_thread
 * 
 */ 
static void
read_response(int sock)
{
    char buf[WDCTL_MSG_LENG+1] = {0};
    struct pollfd fds;	
    fds.fd      = sock;
    fds.events  = POLLIN;

    if (poll(&fds, 1, WDCTL_TIMEOUT) > 0 && fds.revents == POLLIN) {
        if (read(sock, buf, WDCTL_MSG_LENG) > 0) {
            if (!strncmp(buf, "CMD", 3)) {
                execute_post_cmd(buf+3);
            } else
                fprintf(stdout, "%s\n", buf);
        }
    } 
    close(sock);
}

static void
wdctl_command_action(const char *cmd, const char *param)
{
    char *request = NULL;	
    int sock = connect_to_server(sk_name);
	
	if(param)	
		asprintf(&request, "%s %s", cmd, param);
	else
		asprintf(&request, "%s", cmd);

    send_request(sock, request);
    free(request);

    read_response(sock);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        display_help();
        return 1;
    }

    char *command = argv[1];
    char *type = (argc > 2) ? argv[2] : NULL;
    char *values = (argc > 3) ? argv[3] : NULL;

    if (strcmp(command, "show") == 0) {
        if (!type) {
            printf("Error: Missing type argument\n");
            return 1;
        }
        show_command(type);
    } else if (strcmp(command, "add") == 0) {
        if (!type || !values) {
            printf("Error: Missing type or values argument\n");
            return 1;
        }
        add_command(type, values);
    } else if (strcmp(command, "clear") == 0) {
        if (!type) {
            printf("Error: Missing type argument\n");
            return 1;
        }
        clear_command(type);
    } else if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0) {
        display_help();
    } else if (strcmp(command, "stop") == 0) {
        stop_command();
    } else if (strcmp(command, "reset") == 0) {
        if (!values) {
            printf("Error: Missing reset argument\n");
            return 1;
        }
        reset_command(values);
    } else if (strcmp(command, "status") == 0) {
        if (type) {
            status_command(type);
        } else {
            status_command(NULL);
        }
    } else if (strcmp(command, "refresh") == 0) {
        refresh_command();
    } else {
        printf("Unknown command. Type 'wdctlx help' or 'wdctlx ?' for help.\n");
        return 1;
    }

    return 0;
}

static void 
show_command(const char *type) {
    printf("Showing %s\n", type);
    // Add the logic to show the domain|wildcard_domain|mac
    if (strcmp(type, "domain") == 0) {
        wdctl_command_action("show_trusted_domains", NULL);
    } else if (strcmp(type, "wildcard_domain") == 0) {
        wdctl_command_action("show_trusted_pdomains", NULL);
    } else if (strcmp(type, "mac") == 0) {
        wdctl_command_action("show_trusted_mac", NULL);
    } else {
        printf("Unknown type\n");
    }
}

static void 
add_command(const char *type, char *values) {
    printf("Adding %s values is %s\n", type, values);
    
    // Add the logic to add the values to domain|wildcard_domain|mac
    if (strcmp(type, "domain") == 0) {
        wdctl_command_action("add_trusted_domains", values);
    } else if (strcmp(type, "wildcard_domain") == 0) {
        wdctl_command_action("add_trusted_pdomains", values);
    } else if (strcmp(type, "mac") == 0) {
        wdctl_command_action("add_trusted_mac", values);
    } else {
        printf("Unknown type\n");
    }
}

static void 
clear_command(const char *type) {
    printf("Clearing %s\n", type);
    // Add the logic to clear the domain|wildcard_domain|mac
    if (strcmp(type, "domain") == 0) {
        wdctl_command_action("clear_trusted_domains", NULL);
    } else if (strcmp(type, "wildcard_domain") == 0) {
        wdctl_command_action("clear_trusted_pdomains", NULL);
    } else if (strcmp(type, "mac") == 0) {
        wdctl_command_action("clear_trusted_mac", NULL);
    } else {
        printf("Unknown type\n");
    }
}

static void 
display_help() {
    printf("Commands:\n");
    printf("wdctlx show domain|wildcard_domain|mac\n");
    printf("wdctlx add domain|wildcard_domain|mac value1,value2...\n");
    printf("wdctlx clear domain|wildcard_domain|mac\n");
    printf("wdctlx help|?\n");
    printf("wdctlx stop\n");
    printf("wdctlx reset\n");
    printf("wdctlx status\n");
    printf("wdctlx refresh [type]\n");
}

static void 
stop_command() {
    printf("Stopping wdctlx\n");
    // Add the logic to stop the process
    wdctl_command_action("stop", NULL);
}

static void 
reset_command(const char *value) {
    printf("Resetting wdctlx\n");
    // Add the logic to reset the process
    wdctl_command_action("reset", value);
}

static void 
status_command(const char *type) {
    if (type) {
        wdctl_command_action("status", type);
    } else {
        printf("Status: Running\n");
        // Add the logic to show the status
        wdctl_command_action("status", NULL);
    }
}

static void
refresh_command(const char *type)
{
    printf("Refreshing wdctlx\n");
    wdctl_command_action("refresh", NULL);
}
