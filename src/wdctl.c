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
	@author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#define _GNU_SOURCE

#include "common.h"
#include "wdctl.h"
#include "util.h"

#define WDCTL_TIMEOUT   1000*2
#define WDCTL_MSG_LENG  1024*8

static char *sk_name = NULL;

static void usage(void);
static void parse_commandline(int, char **);
static void send_request(int, const char *);
static void read_response(int);
static void wdctl_cmd_process(int , char **, int);
static void wdctl_command_action(const char *, const char *);
static int connect_to_server(const char *);


static struct wdctl_client_command {
    const char *command; // command name
    const char *cmd_args; // comand args demo
    const char *cmd_description; // help
} wdctl_clt_cmd [] = {
    {"status", NULL, "get apfree wifidog status"},
    {"clear_trusted_pdomains", NULL, "clear trusted pan-domain"},
    {"show_trusted_pdomains", NULL, "show trusted pan-domain"},
    {"clear_trusted_iplist", NULL, "clear trusted iplist"},
    {"reparse_trusted_domains", NULL, "reparse trusted domain's ip and add new parsed ip"},
    {"clear_trusted_domains", NULL, "clear trusted domain and it's ip"},
    {"show_trusted_domains", NULL, "show trusted domains and its ip"},
    {"show_trusted_mac", NULL, "show trusted mac list"},
    {"clear_trusted_mac", NULL, "clear trusted mac list"},
    {"add_trusted_pdomains", "pan-domain1,pan-domain2...", "add one or more trusted pan-domain like kunteng.org.cn,qq.com..."},
    {"del_trusted_pdomains", "pan-domain1,pan-domain2...", "del one or more trusted pan-domain list like kunteng.org.cn,qq.com..."},
    {"add_trusted_domains", "domain1,domain2...", "add trusted domain list like www.kunteng.org.cn,www.qq.com..."},
    {"del_trusted_domains", "domain1,domain2...", "del trusted domain list like www.kunteng.org.cn,www.qq.com...."},
    {"add_trusted_iplist", "ip1,ip2...", "add one or more trusted ip list like ip1,ip2..."},
    {"del_trusted_iplist", "ip1,ip2...", "del one or more trsuted ip list like ip1,ip2..."},
    {"add_trusted_mac", "mac1,mac2...", "add one or more trusted mac list like mac1,mac2..."},
    {"del_trusted_mac", "mac1,mac2...", "del one or more trusted mac list like mac1,mac2..."},
    {"add_online_client", "{\"ip\":\"ipaddress\", \"mac\":\"devMac\", \"name\":\"devName\"}", "add client to connected list "},
    {"user_cfg_save", NULL, "save all rule to config file"},
    {"reset", "ip|mac", "logout connected client by its ip or mac"},
    {"stop", NULL, "stop apfree wifidog"},
    {"help", NULL, "list all method"},
};

/** 
 * @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void
usage(void)
{
    fprintf(stdout, "Usage: wdctlx [options] command [arguments]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -s <path>         Path to the socket\n");
    fprintf(stdout, "  -h                Print usage\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "commands arg\t description:\n");
    for (int i = 0; i < ARRAYLEN(wdctl_clt_cmd); i++) {
        fprintf(stdout, " %s %s\t %s \n", wdctl_clt_cmd[i].command, 
            wdctl_clt_cmd[i].cmd_args?wdctl_clt_cmd[i].cmd_args:"", 
            wdctl_clt_cmd[i].cmd_description);
    }
}

static void
list_all_method()
{
#define COMMAND_EQUAL(CMD) !strcmp(cmd,CMD)
    char *cmd = NULL;
    for (int i = 0; i < ARRAYLEN(wdctl_clt_cmd); i++) {
        cmd = wdctl_clt_cmd[i].command;
        if (COMMAND_EQUAL("list"))
            continue;
        else if(COMMAND_EQUAL("add_online_client"))
            fprintf(stdout, "%s {\"ip\":\"192.168.1.211\", \"mac\":\"aa:bb:cc:dd:ee:ff\", \"name\":\"apfree\"}\n", cmd);
        else if (COMMAND_EQUAL("add_trusted_domains"))
            fpintf(stdout, "%s www.kunteng.org.cn,captive.apple.com,www.baidu.com,www.qq.com,www.alibaba.com,aaa,bbb", cmd);
        else if (COMMAND_EQUAL("add_trusted_pdomains"))
            fprintf(stdout, "%s kunteng.org.cn,apple.com,baidu.com,qq.com,aa,bb", cmd);
        else if (COMMAND_EQUAL("add_trusted_mac"))
            fprintf(stdout, "%s aa:bb:cc:11:22:33,11:22:33:aa:bb:cc:dd,22.22.22:aa:aa:aa", cmd);
        else if (COMMAND_EQUAL("add_trusted_iplist"))
            fprintf(stdout, "%s 192.168.1.2,192.168.1.3,192.168.1.4", cmd);
        else
            fprintf(stdout, "%s \n", cmd);
    }
#undef COMMAND_EQUAL
}

static void
wdctl_cmd_process(int argc, char **argv, int optind)
{
    if ((argc - optind) <= 0) {
        goto ERR;
    }

    for (int i = 0; i < ARRAYLEN(wdctl_clt_cmd); i++) {
        if (!strcmp(wdctl_clt_cmd[i].command, "help")) {
            list_all_method();
            return;
        }

        if (!strcmp(wdctl_clt_cmd[i].command, *(argv+optind))) {
            if ((argc - (optind + 1)) > 0) {
                if (wdctl_clt_cmd[i].cmd_args)
                    wdctl_command_action(wdctl_clt_cmd[i].command, *(argv + optind + 1));
                else
                    goto ERR;
            } else 
                wdctl_command_action(wdctl_clt_cmd[i].command, NULL);
            return;
        }
    }
ERR:
    fprintf(stderr, "wdctlx: Error: Invalid command \"%s\"\n", *(argv + optind));
    usage();
    exit(EXIT_FAILURE);
}

/** @internal
 *
 * Uses getopt() to parse the command line and set configuration values
 */
void
parse_commandline(int argc, char **argv)
{
    extern int optind;
    int c;

    while (-1 != (c = getopt(argc, argv, "s:h"))) {
        switch (c) {
        case 'h':
            usage();
            exit(1);
            break;

        case 's':
            if (optarg) {
                sk_name = strdup(optarg);
            }
            break;

        default:
            usage();
            exit(1);
            break;
        }
    }

    if (!sk_name) sk_name = strdup(DEFAULT_SOCK);

    wdctl_cmd_process(argc, argv, optind);

}

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
    strncpy(sa_un.sun_path, sock_name, (sizeof(sa_un.sun_path) - 1));

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

static void
read_response(int sock)
{
    char buf[WDCTL_MSG_LENG+1] = {0};
    struct pollfd fds;	
    fds.fd      = sock;
    fds.events  = POLLIN;

    if (poll(&fds, 1, WDCTL_TIMEOUT) > 0 && fds.revents == POLLIN) {
        if (read(sock, buf, WDCTL_MSG_LENG) > 0) {
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
    parse_commandline(argc, argv);
}