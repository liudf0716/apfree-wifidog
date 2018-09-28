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

#define WDCTL_MSG_LENG  1024*8

static void usage(void);
static void parse_commandline(int, char **);
static int connect_to_server(const char *);
static void send_request(int, const char *);
static void read_response(int sock);
static void wdctl_cmd_process(int argc, char **argv, int optind);

static struct wdctl_client_command {
    const char *command;
    int cmd_type;
} wdctl_clt_cmd [] = {
    {"status", WDCTL_STATUS},
    {"stop", WDCTL_STOP},
    {"clear_trusted_pdomains", WDCTL_CLEAR_TRUSTED_PAN_DOMAINS},
    {"show_trusted_pdomains", WDCTL_SHOW_TRUSTED_PAN_DOMAINS},
    {"clear_trusted_iplist", WDCTL_CLEAR_TRUSTED_IPLIST},
    {"reparse_trusted_domains", WDCTL_REPARSE_TRUSTED_DOMAINS},
    {"clear_trusted_domains", WDCTL_CLEAR_TRUSTED_DOMAINS},
    {"show_trusted_domains", WDCTL_SHOW_TRUSTED_DOMAINS},
    {"show_roam_maclist", WDCTL_SHOW_ROAM_MACLIST},
    {"clear_roam_maclist", WDCTL_CLEAR_ROAM_MACLIST},
    {"show_trusted_maclist", WDCTL_SHOW_TRUSTED_MACLIST},
    {"clear_trusted_maclist", WDCTL_CLEAR_TRUSTED_MACLIST},
    {"show_trusted_local_maclist", WDCTL_SHOW_TRUSTED_LOCAL_MACLIST},
    {"clear_trusted_local_maclist", WDCTL_CLEAR_TRUSTED_LOCAL_MACLIST},
    {"show_untrusted_maclist", WDCTL_SHOW_UNTRUSTED_MACLIST},
    {"clear_untrusted_maclist", WDCTL_CLEAR_UNTRUSTED_MACLIST},
    {"user_cfg_save", WDCTL_USER_CFG_SAVE},
    {"reset", WDCTL_KILL},
    {"add_trusted_pdomains", WDCTL_ADD_TRUSTED_PAN_DOMAINS},
    {"del_trusted_pdomains", WDCTL_DEL_TRUSTED_PAN_DOMAINS},
    {"add_trusted_domains", WDCTL_ADD_TRUSTED_DOMAINS},
    {"del_trusted_domains", WDCTL_DEL_TRUSTED_DOMAINS},
    {"add_trusted_iplist", WDCTL_ADD_TRUSTED_IPLIST},
    {"del_trusted_iplist", WDCTL_DEL_TRUSTED_IPLIST},
    {"add_domain_ip", WDCTL_ADD_DOMAIN_IP},
    {"add_roam_mac", WDCTL_ADD_ROAM_MACLIST},
    {"add_trusted_mac", WDCTL_ADD_TRUSTED_MACLIST},
    {"del_trusted_mac", WDCTL_DEL_TRUSTED_MACLIST},
    {"add_trusted_local_mac", WDCTL_ADD_TRUSTED_LOCAL_MACLIST},
    {"del_trusted_local_mac", WDCTL_DEL_TRUSTED_LOCAL_MACLIST},
    {"add_untrusted_mac", WDCTL_ADD_UNTRUSTED_MACLIST},
    {"del_untrusted_mac", WDCTL_DEL_UNTRUSTED_MACLIST},
    {"add_online_client", WDCTL_ADD_ONLINE_CLIENT}
};

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wdctl is run with -h or with an unknown option
 */
static void
usage(void)
{
    fprintf(stdout, "Usage: wdctl [options] command [arguments]\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -s <path>         Path to the socket\n");
    fprintf(stdout, "  -h                Print usage\n");
    fprintf(stdout, "\n");
    fprintf(stdout, "commands:\n");
    fprintf(stdout, "  reset [mac|ip]    Reset the specified mac or ip connection\n");
    fprintf(stdout, "  status            Obtain the status of wifidog\n");
    fprintf(stdout, "  stop              Stop the running wifidog\n");
    fprintf(stdout, "  add_trusted_pdomains [domain1,domain2...]	Add trusted pan-domains\n");
    fprintf(stdout, "  del_trusted_pdomains [domain1,domain2...]	Del trusted pan-domains\n");
    fprintf(stdout, "  clear_trusted_pdomains	Clear all trusted pan-domains\n");
    fprintf(stdout, "  add_trusted_domains [domain1,domain2...]	Add trusted domains\n");
    fprintf(stdout, "  del_trusted_domains [domain1,domain2...]		Del trusted domains\n");
    fprintf(stdout, "  clear_trusted_domains	Clear all trusted domains\n");
    fprintf(stdout, "  reparse_trusted_domains	Reparse trusted domains ip\n");
    fprintf(stdout, "  add_trusted_iplist [ip1,ip2...]		Add trusted ip list\n");
    //fprintf(stdout, "  del_trusted_iplist [ip1,ip2...]		Del trusted ip list\n");
    fprintf(stdout, "  clear_trusted_iplist		Clear trusted ip list\n");
    fprintf(stdout, "  show_trusted_domains 	Show all trusted domains and its ip\n");
    fprintf(stdout, "  add_domain_ip [domain:ip] 	Add domain and its ip\n");
    fprintf(stdout, "  add_trusted_mac [mac1,mac2...]			Add trusted mac list\n");
    fprintf(stdout, "  del_trusted_mac [mac1,mac2...]			Del trusted mac list\n");
    fprintf(stdout, "  clear_trusted_mac		Clear trusted mac list\n");
    fprintf(stdout, "  show_trusted_mac			Show trusted mac list\n");
	fprintf(stdout, "  add_trusted_local_mac [mac1,mac2...]			Add trusted local mac list\n");
    fprintf(stdout, "  del_trusted_local_mac [mac1,mac2...]			Del trusted local mac list\n");
    fprintf(stdout, "  clear_trusted_local_mac			Clear trusted local mac list\n");
    fprintf(stdout, "  show_trusted_local_mac			Show trusted local mac list\n");
    fprintf(stdout, "  add_untrusted_mac [mac1,mac2...]		Add untrusted mac list\n");
    fprintf(stdout, "  del_untrusted_mac [mac1,mac2...]		Del untrusted mac list\n");
	fprintf(stdout, "  clear_untrusted_mac		Clear untrusted mac list\n");
    fprintf(stdout, "  show_untrusted_mac		Show untrusted mac list\n");
    fprintf(stdout, "  user_cfg_save			User config save\n");
	fprintf(stdout, "  add_online_client 		Add online client\n");
    fprintf(stdout, "\n");
}

static void
wdctl_cmd_process(int argc, char **argv, int optind)
{
    for (int i = 0; i < ARRAYLEN(wdctl_clt_cmd); i++) {
        if (!strcmp(wdctl_clt_cmd[i].command, *(argv+optind)) {
            config.command = wdctl_clt_cmd[i].cmd_type;
            if ((argc - (optind + 1)) > 0) {
                wdctl_command_action(wdctl_clt_cmd[i].command, *(argv + optind + 1));
            } else 
                wdctl_command_action(wdctl_clt_cmd[i].command, NULL);
            return;
        }
    }

    fprintf(stderr, "wdctl: Error: Invalid command \"%s\"\n", *(argv + optind));
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
                free(config.socket);
                config.socket = strdup(optarg);
            }
            break;

        default:
            usage();
            exit(1);
            break;
        }
    }

    if ((argc - optind) <= 0) {
        usage();
        exit(1);
    }

    wdctl_cmd_parse(argc, argv, optind);

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
    fds.events   = POLLOUT;

    if (poll(&fds, 1, WDCTL_TIMEOUT) > 0 && fds.revents == POLLOUT) {
        write(sock, buf, len);
    } 
}

static void
wdctl_command_action(const char *cmd, const char *param)
{
    char request[WDCTL_MSG_LENG] = {0};	
    int sock = connect_to_server(config.socket);
	
	if(param)	
		snprintf(request, WDCTL_MSG_LENG, "%s %s\r\n\r\n", cmd, param);
	else
		snprintf(request, WDCTL_MSG_LENG, "%s \r\n\r\n", cmd);

    send_request(sock, request);
    read_response(sock);
}

int
main(int argc, char **argv)
{
    parse_commandline(argc, argv);
}