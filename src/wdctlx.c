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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>

#define DEFAULT_SOCK "/tmp/wdctlx.sock"
#define WDCTL_TIMEOUT 2000
#define WDCTL_MSG_LEN 8192

static struct event_base *base = NULL;
static char *sk_name = NULL;
char *program_argv0 = NULL;

static void display_help();
static struct bufferevent *connect_to_server(const char *sock_name);
static void send_request(struct bufferevent *bev, const char *request);
static void read_response(struct bufferevent *bev);
static void execute_post_cmd(char *raw_cmd);
static void handle_command(const char *cmd, const char *param);

/**
 * Event callback for handling connection events.
 */
static void event_cb(struct bufferevent *bev, short events, void *ctx) {
    int *connection_success = (int *)ctx;
    if (events & BEV_EVENT_CONNECTED) {
        *connection_success = 1;
    } else if (events & (BEV_EVENT_ERROR | BEV_EVENT_TIMEOUT)) {
        *connection_success = 0;
    }
    event_base_loopexit(base, NULL);
}

/**
 * Connects to the server using a UNIX domain socket.
 */
static struct bufferevent *connect_to_server(const char *sock_name) {
    struct sockaddr_un sa_un;
    int connection_success = 0;

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Error: Could not create event base\n");
        exit(EXIT_FAILURE);
    }

    memset(&sa_un, 0, sizeof(sa_un));
    sa_un.sun_family = AF_UNIX;
    strncpy(sa_un.sun_path, sock_name ? sock_name : DEFAULT_SOCK, sizeof(sa_un.sun_path) - 1);

    struct bufferevent *bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        fprintf(stderr, "Error: Could not create bufferevent\n");
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    bufferevent_setcb(bev, NULL, NULL, event_cb, &connection_success);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    struct timeval tv = {WDCTL_TIMEOUT / 1000, 0};
    bufferevent_set_timeouts(bev, &tv, &tv);

    if (bufferevent_socket_connect(bev, (struct sockaddr *)&sa_un, sizeof(sa_un)) < 0) {
        fprintf(stderr, "Error: Could not connect to server\n");
        bufferevent_free(bev);
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    event_base_dispatch(base);

    if (!connection_success) {
        fprintf(stderr, "Error: Connection failed. Is apfree-wifidog running?\n");
        bufferevent_free(bev);
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    event_base_free(base);
    return bev;
}

/**
 * Sends a request to the server.
 */
static void send_request(struct bufferevent *bev, const char *request) {
    bufferevent_write(bev, request, strlen(request));
}

/**
 * Executes shell commands specified in the server response.
 */
static void execute_post_cmd(char *raw_cmd) {
    size_t nlen = strlen(raw_cmd);
    if (nlen < 3) return;

    if (raw_cmd[0] == '[' && raw_cmd[nlen - 1] == ']') {
        raw_cmd[nlen - 1] = '\0';
        char *cmd = raw_cmd + 1;
        system(cmd);
        fprintf(stdout, "Executed shell command: [%s]\n", cmd);
    } else {
        fprintf(stderr, "Error: [%s] is an illegal post command\n", raw_cmd);
    }
}

/**
 * Reads and processes the server's response.
 */
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

/**
 * Handles the main command logic.
 */
static void handle_command(const char *cmd, const char *param) {
    struct bufferevent *bev = connect_to_server(sk_name);
    char *request = NULL;

    if (param)
        asprintf(&request, "%s %s", cmd, param);
    else
        asprintf(&request, "%s", cmd);

    if (!request) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    send_request(bev, request);
    free(request);

    read_response(bev);
    bufferevent_free(bev);
}

/**
 * Displays usage help for the program.
 */
static void display_help() {
    printf("Commands:\n");
    printf("  wdctlx show domain|wildcard_domain|mac\n");
    printf("  wdctlx add domain|wildcard_domain|mac value1,value2...\n");
    printf("  wdctlx clear domain|wildcard_domain|mac\n");
    printf("  wdctlx help|?\n");
    printf("  wdctlx stop\n");
    printf("  wdctlx reset value\n");
    printf("  wdctlx status [type]\n");
    printf("  wdctlx refresh\n");
}

typedef struct {
    const char *command;
    const char *server_cmd;
    bool requires_type;
    bool requires_values;
} CommandMapping;

static const CommandMapping COMMAND_MAP[] = {
    {"show", "show_trusted_", true, false},
    {"add", "add_trusted_", true, true},
    {"clear", "clear_trusted_", true, false},
    {"stop", "stop", false, false},
    {"reset", "reset", false, true},
    {"status", "status", false, false},
    {"refresh", "refresh", false, false},
    {NULL, NULL, false, false}
};

static const char *TYPE_MAP[] = {
    "domain",
    "wildcard_domain",
    "mac",
    NULL
};

static const char *get_server_command(const char *cmd_type, const char *type) {
    static char server_cmd[64];
    if (strcmp(cmd_type, "show") == 0 || strcmp(cmd_type, "add") == 0 || strcmp(cmd_type, "clear") == 0) {
        const char *type_suffix = strcmp(type, "wildcard_domain") == 0 ? "pdomains" : 
                                strcmp(type, "domain") == 0 ? "domains" : "mac";
        snprintf(server_cmd, sizeof(server_cmd), "%s%s", strcmp(cmd_type, "show") == 0 ? "show_trusted_" :
                                                        strcmp(cmd_type, "add") == 0 ? "add_trusted_" : 
                                                        "clear_trusted_", type_suffix);
        return server_cmd;
    }
    return cmd_type;
}

static bool is_valid_type(const char *type) {
    for (const char **t = TYPE_MAP; *t; t++) {
        if (strcmp(*t, type) == 0) return true;
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        display_help();
        return 1;
    }

    program_argv0 = argv[0];
    const char *command = argv[1];
    const char *type = (argc > 2) ? argv[2] : NULL;
    const char *values = (argc > 3) ? argv[3] : NULL;

    if (strcmp(command, "help") == 0 || strcmp(command, "?") == 0) {
        display_help();
        return 0;
    }

    for (const CommandMapping *cmd = COMMAND_MAP; cmd->command; cmd++) {
        if (strcmp(command, cmd->command) == 0) {
            if (cmd->requires_type && (!type || !is_valid_type(type))) {
                fprintf(stderr, "Error: Invalid or missing type argument\n");
                return 1;
            }
            if (cmd->requires_values && !values) {
                fprintf(stderr, "Error: Missing values argument\n");
                return 1;
            }

            const char *server_cmd = get_server_command(command, type);
            handle_command(server_cmd, strcmp(command, "status") == 0 ? type : values);
            return 0;
        }
    }

    fprintf(stderr, "Error: Unknown command\n");
    display_help();
    return 1;
}
