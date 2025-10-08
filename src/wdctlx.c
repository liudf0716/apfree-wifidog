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
#define WDCTL_TIMEOUT 5

static struct event_base *base = NULL;
static char *sk_name = NULL;
char *program_argv0 = NULL;

static void display_help();
static struct bufferevent *connect_to_server(const char *sock_name, void *data);
static void send_request(struct bufferevent *bev, const char *request);
static void read_response(struct bufferevent *bev);
static void execute_post_cmd(char *raw_cmd);
static void handle_command(const char *cmd, const char *param);

/**
 * Event callback for handling connection events.
 */
static void 
event_cb(struct bufferevent *bev, short events, void *ctx) {
    char *request = (char *)ctx;
    if (events & BEV_EVENT_CONNECTED) {
        send_request(bev, request);
        free(request);
    }
}

static void
read_cb(struct bufferevent *bev, void *ctx) {
    read_response(bev);
    event_base_loopexit(bufferevent_get_base(bev), NULL);
}

/**
 * Connects to the server using a UNIX domain socket.
 */
static struct bufferevent *
connect_to_server(const char *sock_name, void *data) 
{
    struct sockaddr_un sa_un;

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

    bufferevent_setcb(bev, read_cb, NULL, event_cb, data);
    bufferevent_enable(bev, EV_READ | EV_WRITE);

    struct timeval tv = {WDCTL_TIMEOUT, 0};
    bufferevent_set_timeouts(bev, &tv, &tv);

    if (bufferevent_socket_connect(bev, (struct sockaddr *)&sa_un, sizeof(sa_un)) < 0) {
        fprintf(stderr, "Error: Could not connect to server\n");
        bufferevent_free(bev);
        event_base_free(base);
        exit(EXIT_FAILURE);
    }

    event_base_dispatch(base);

    bufferevent_free(bev);
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
static void 
execute_post_cmd(char *raw_cmd) {
    size_t nlen = strlen(raw_cmd);
    if (nlen < 3) return;

    if (raw_cmd[0] == '[' && raw_cmd[nlen - 1] == ']') {
        raw_cmd[nlen - 1] = '\0';
        char *cmd = raw_cmd + 1;
        // Validate command before execution to prevent command injection
        if (strchr(cmd, ';') || strchr(cmd, '|') || strchr(cmd, '&') || 
            strstr(cmd, "$(") || strstr(cmd, "`")) {
            fprintf(stderr, "Error: Potentially dangerous command rejected: [%s]\n", cmd);
            return;
        }
        int ret = system(cmd);
        if (ret == -1) {
            fprintf(stderr, "Error: Failed to execute command: [%s]\n", cmd);
            return;
        }
        fprintf(stdout, "Executed shell command: [%s]\n", cmd);
    } else {
        fprintf(stderr, "Error: [%s] is an illegal post command\n", raw_cmd);
    }
}

/**
 * Reads and processes the server's response.
 */
static void 
read_response(struct bufferevent *bev) {
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);
    
    if (len > 0) {
        char *buf = malloc(len + 1);
        if (!buf) {
            fprintf(stderr, "Error: Memory allocation failed\n");
            return;
        }
        
        if (evbuffer_remove(input, buf, len) > 0) {
            buf[len] = '\0';
            if (len >= 3 && !strncmp(buf, "CMD", 3)) {
                execute_post_cmd(buf + 3);
            } else {
                fprintf(stdout, "%s\n", buf);
            }
        }
        
        free(buf);
    }
}

/**
 * Handles the main command logic.
 */
static void 
handle_command(const char *cmd, const char *param) 
{
    char *request = NULL;
    int ret;
    
    if (param) {
        ret = asprintf(&request, "%s %s", cmd, param);
    } else {
        ret = asprintf(&request, "%s", cmd);
    }

    if (ret == -1 || !request) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    connect_to_server(sk_name, request);
}

/**
 * Displays usage help for the program.
 */
static void display_help() {
    printf("Commands:\n");
    printf("  wdctlx show <domain|wildcard_domain|mac>\n");
    printf("  wdctlx add <domain|wildcard_domain|mac> <value1,value2...>\n");
    printf("  wdctlx del <mac> <value1,value2...>\n");
    printf("  wdctlx clear <domain|wildcard_domain|mac>\n");
    printf("  wdctlx help|?\n");
    printf("  wdctlx stop\n");
    printf("  wdctlx reset <value>\n");
    printf("  wdctlx status [client|auth|wifidogx]\n");
    printf("  wdctlx refresh\n");
    printf("  wdctlx apfree <user_list|user_info|user_auth|save_user|restore_user>\n");
    printf("  wdctlx hotplugin <json_value>\n");
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
    {"del", "del_trusted_", true, true},
    {"clear", "clear_trusted_", true, false},
    {"stop", "stop", false, false},
    {"reset", "reset", false, true},
    {"status", "status", false, false},
    {"refresh", "refresh", false, false},
    {"apfree", "user_list", true, false},
    {"apfree", "user_info", true, true},
    {"apfree", "user_auth", true, true},
    {"apfree", "save_user", true, false},
    {"apfree", "restore_user", true, false},
    {"hotplugin", "hotplugin", false, false},
    {NULL, NULL, false, false}
};

static const char *TYPE_MAP[] = {
    "domain",
    "wildcard_domain",
    "mac",
    "user_list",
    "user_info",
    "user_auth",
    "save_user",
    "restore_user",
    NULL
};

static const char *
get_server_command(const char *cmd_type, const char *type) {
    static char server_cmd[64];
    if (strcmp(cmd_type, "show") == 0 || 
        strcmp(cmd_type, "add") == 0 || 
        strcmp(cmd_type, "clear") == 0 || 
        strcmp(cmd_type, "del") == 0) {
        const char *type_suffix = strcmp(type, "wildcard_domain") == 0 ? "pdomains" : 
                                strcmp(type, "domain") == 0 ? "domains" : "mac";
        snprintf(server_cmd, sizeof(server_cmd), "%s%s", strcmp(cmd_type, "show") == 0 ? "show_trusted_" :
                                                        strcmp(cmd_type, "add") == 0 ? "add_trusted_" : 
                                                        strcmp(cmd_type, "del") == 0 ? "del_trusted_" :
                                                        "clear_trusted_", type_suffix);
        return server_cmd;
    } else if (strcmp(cmd_type, "apfree") == 0) {
        return type;
    } 
    return cmd_type;
}

static bool 
is_valid_type(const char *type) {
    for (const char **t = TYPE_MAP; *t; t++) {
        if (strcmp(*t, type) == 0) return true;
    }
    return false;
}

int 
main(int argc, char **argv) {
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
            if (!strcmp(command, "status") || !strcmp(command, "hotplugin")) {
                // type as input values
                handle_command(server_cmd, type);
            } else {
                handle_command(server_cmd, values);
            }
            return 0;
        }
    }

    fprintf(stderr, "Error: Unknown command\n");
    display_help();
    return 1;
}
