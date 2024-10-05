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

/** @file commandline.c
    @brief Command line argument handling
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include "common.h"
#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "commandline.h"
#include "version.h"


/*
 * Holds an argv that could be passed to exec*() if we restart ourselves
 */
char ** restartargv = NULL;
char *progname = NULL;

/**
 * A flag to denote whether we were restarted via a parent wifidog, or started normally
 * 0 means normally, otherwise it will be populated by the PID of the parent
 */
pid_t restart_orig_pid = 0;

static void usage(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wifidog is run with -h or with an unknown option
 */
static void
usage(void)
{
    fprintf(stdout, "Usage: %s [options]\n", progname);
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -c [filename] Use this config file\n");
    fprintf(stdout, "  -f            Run in foreground\n");
    fprintf(stdout, "  -d <level>    Debug level\n");
    fprintf(stdout, "  -s            Log to syslog\n");
    fprintf(stdout, "  -w <path>     Wdctlx socket path\n");
    fprintf(stdout, "  -h            Print usage\n");
    fprintf(stdout, "  -v            Print version information\n");
    fprintf(stdout,
            "  -x pid        Used internally by apfree wifidog when re-starting itself *DO NOT ISSUE THIS SWITCH MANUAlLY*\n");
    fprintf(stdout, "  -i <path>     Internal socket path used when re-starting self\n");
    fprintf(stdout, "  -a <path>     Path to /proc/net/arp replacement - mainly useful for debugging.\n");
    fprintf(stdout, "  -p <path>     Save pid to file\n");
    fprintf(stdout, "\n");
}

/** Uses getopt() to parse the command line and set configuration values
 * also populates restartargv
 */
void
parse_commandline(int argc, char **argv)
{
    int c;
    int skiponrestart;
    int i = 0;

    s_config *config = config_get_config();

    //MAGIC 3: Our own -x, the pid, and NULL :
    restartargv = safe_malloc((size_t) (argc + 3) * sizeof(char *));
    restartargv[i++] = safe_strdup(argv[0]);
    progname = restartargv[0];


    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vx:i:a:"))) {

        skiponrestart = 0;

        switch (c) {

        case 'h':
            usage();
            exit(1);
            break;

        case 'c':
            if (optarg) {
                free(config->configfile);
                config->configfile = safe_strdup(optarg);
            }
            break;

        case 'w':
            if (optarg) {
                free(config->wdctl_sock);
                config->wdctl_sock = safe_strdup(optarg);
            }
            break;

        case 'f':
            skiponrestart = 1;
            config->daemon = 0;
            debugconf.log_stderr = 1;
            break;

        case 'd':
            if (optarg) {
                debugconf.debuglevel = atoi(optarg);
            }
            break;

        case 's':
            debugconf.log_syslog = 1;
            break;

        case 'v':
            fprintf(stdout, "This is apfree wifidog version " VERSION "\n");
            exit(1);
            break;

        case 'x':
            skiponrestart = 1;
            if (optarg) {
                restart_orig_pid = atoi(optarg);
            } else {
                fprintf(stdout, "The expected PID to the -x switch was not supplied!");
                exit(1);
            }
            break;

        case 'i':
            if (optarg) {
                free(config->internal_sock);
                config->internal_sock = safe_strdup(optarg);
            }
            break;

        case 'a':
            if (optarg) {
                free(config->arp_table_path);
                config->arp_table_path = safe_strdup(optarg);
            } else {
                fprintf(stdout, "You must supply the path to the ARP table with -a!");
                exit(1);
            }
            break;
        case 'p':
            if (optarg) {
                free(config->pidfile);
                config->pidfile = safe_strdup(optarg);
            } else {
                fprintf(stdout, "The expected PID file path to the apfree wifidog was not supplied!\n");
                exit(1);
            }
            break;
        default:
            usage();
            exit(1);
            break;

        }

        if (!skiponrestart) {
            /* Add it to restartargv */
            safe_asprintf(&(restartargv[i++]), "-%c", c);
            if (optarg) {
                restartargv[i++] = safe_strdup(optarg);
            }
        }

    }

    /* Finally, we should add  the -x, pid and NULL to restartargv
     * HOWEVER we cannot do it here, since this is called before we fork to background
     * so we'll leave this job to gateway.c after forking is completed
     * so that the correct PID is assigned
     *
     * We add 3 nulls, and the first 2 will be overridden later
     */
    restartargv[i++] = NULL;
    restartargv[i++] = NULL;
    restartargv[i++] = NULL;
}
