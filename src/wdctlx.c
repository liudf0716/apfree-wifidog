// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include "common.h"
#include "wd_util.h"

#define DEFAULT_SOCK "/tmp/wdctlx.sock"

#define WDCTL_TIMEOUT 2000
#define WDCTL_MSG_LEN 8192

static struct event_base *base = NULL;
static char *sk_name = NULL;
char *program_argv0 = NULL;

static void display_help();

static void event_cb(struct bufferevent *bev, short events, void *ctx) {
    int *connection_success = (int *)ctx;
    if (events & BEV_EVENT_CONNECTED) {
        *connection_success = 1;
        event_base_loopexit(base, NULL);
    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        *connection_success = 0;
        event_base_loopexit(base, NULL);
    }
}

static struct bufferevent *connect_to_server(const char *sock_name) {
    struct sockaddr_un sa_un;
    int connection_success = 0;

    base = event_base_new();
    if (!base) {
        fprintf(stdout, "Could not create event base\n");
        exit(EXIT_FAILURE);
    }

    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, sock_name ? sock_name : DEFAULT_SOCK, sizeof(sa_un.sun_path) - 1);

    struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stdout, "Could not create bufferevent\n");
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    bufferevent_setcb(bev, NULL, NULL, event_cb, &connection_success);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    struct timeval tv = {2, 0};
    bufferevent_set_timeouts(bev, &tv, &tv);

    if (bufferevent_socket_connect(bev, (struct sockaddr *)&sa_un, sizeof(sa_un)) < 0) {
        fprintf(stdout, "Could not connect\n");
        bufferevent_free(bev);
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    event_base_dispatch(base);

    if (!connection_success) {
        fprintf(stdout, "wdctlx: apfree-wifidog probably not started\n");
        bufferevent_free(bev);
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    event_base_free(base);
    return bev;
}

static void send_request(struct bufferevent *bev, const char *request) {
    bufferevent_write(bev, request, strlen(request));
}

static void execute_post_cmd(char *raw_cmd) {
    size_t nlen = strlen(raw_cmd);
    if (nlen < 3) return;

    if (raw_cmd[0] == '[' && raw_cmd[nlen - 1] == ']') {
        raw_cmd[nlen - 1] = '\0';
        char *cmd = raw_cmd + 1;
        system(cmd);
        fprintf(stdout, "Executed shell command: [%s]\n", cmd);
    } else {
        fprintf(stdout, "[%s] is an illegal post command\n", raw_cmd);
    }
}

static void read_response(struct bufferevent *bev) {
    char buf[WDCTL_MSG_LEN + 1] = {0};
    int n = bufferevent_read(bev, buf, WDCTL_MSG_LEN);
    if (n > 0) {
        buf[n] = '\0';
        if (!strncmp(buf, "CMD", 3)) {
            execute_post_cmd(buf + 3);
        } else {
            fprintf(stdout, "%s\n", buf);
        }
    }
}

static void wdctl_command_action(const char *cmd, const char *param) {
    struct bufferevent *bev = connect_to_server(sk_name);
    char *request = NULL;

    if (param)
        asprintf(&request, "%s %s", cmd, param);
    else
        asprintf(&request, "%s", cmd);

    send_request(bev, request);
    free(request);

    read_response(bev);
    bufferevent_free(bev);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        display_help();
        return 1;
    }

    program_argv0 = argv[0];
    char *command = argv[1];
    char *type = (argc > 2) ? argv[2] : NULL;
    char *values = (argc > 3) ? argv[3] : NULL;

    if (strcmp(command, "show") == 0) {
        if (!type) {
            printf("Error: Missing type argument\n");
            return 1;
        }
        if (strcmp(type, "domain") == 0) {
            wdctl_command_action("show_trusted_domains", NULL);
        } else if (strcmp(type, "wildcard_domain") == 0) {
            wdctl_command_action("show_trusted_pdomains", NULL);
        } else if (strcmp(type, "mac") == 0) {
            wdctl_command_action("show_trusted_mac", NULL);
        } else {
            printf("Unknown type\n");
        }
    } else if (strcmp(command, "add") == 0) {
        if (!type || !values) {
            printf("Error: Missing type or values argument\n");
            return 1;
        }
        if (strcmp(type, "domain") == 0) {
            wdctl_command_action("add_trusted_domains", values);
        } else if (strcmp(type, "wildcard_domain") == 0) {
            wdctl_command_action("add_trusted_pdomains", values);
        } else if (strcmp(type, "mac") == 0) {
            wdctl_command_action("add_trusted_mac", values);
        } else {
            printf("Unknown type\n");
        }
    } else if (strcmp(command, "clear") == 0) {
        if (!type) {
            printf("Error: Missing type argument\n");
            return 1;
        }
        if (strcmp(type, "domain") == 0) {
            wdctl_command_action("clear_trusted_domains", NULL);
        } else if (strcmp(type, "wildcard_domain") == 0) {
            wdctl_command_action("clear_trusted_pdomains", NULL);
        } else if (strcmp(type, "mac") == 0) {
            wdctl_command_action("clear_trusted_mac", NULL);
        } else {
            printf("Unknown type\n");
        }
    } else if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0) {
        display_help();
    } else if (strcmp(command, "stop") == 0) {
        wdctl_command_action("stop", NULL);
    } else if (strcmp(command, "reset") == 0) {
        if (!values) {
            printf("Error: Missing reset argument\n");
            return 1;
        }
        wdctl_command_action("reset", values);
    } else if (strcmp(command, "status") == 0) {
        wdctl_command_action("status", type);
    } else if (strcmp(command, "refresh") == 0) {
        wdctl_command_action("refresh", NULL);
    } else {
        printf("Unknown command. Type 'wdctlx help' or 'wdctlx ?' for help.\n");
        return 1;
    }

    return 0;
}

static void display_help() {
    printf("Commands:\n");
    printf("wdctlx show domain|wildcard_domain|mac\n");
    printf("wdctlx add domain|wildcard_domain|mac value1,value2...\n");
    printf("wdctlx clear domain|wildcard_domain|mac\n");
    printf("wdctlx help|?\n");
    printf("wdctlx stop\n");
    printf("wdctlx reset value\n");
    printf("wdctlx status [type]\n");
    printf("wdctlx refresh\n");
}
