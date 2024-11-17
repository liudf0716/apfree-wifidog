
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <event2/event.h>
#include <pthread.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include "dns_forward.h"
#include "debug.h"
#include "conf.h"

struct dns_query {
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    char buffer[512];
    int buffer_len;
    struct event *dns_event;
};


static int parse_dns_header(unsigned char *response, int response_len, struct dns_header **header);
static int parse_dns_question(unsigned char **ptr, char *query_name, int qdcount);
static int is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain);
static int process_dns_answers(unsigned char **ptr, int ancount, t_domain_trusted *trusted_domain);
static int add_trusted_ip(t_domain_trusted *trusted_domain, uint16_t type, unsigned char *addr_ptr);

static char *
safe_strrstr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    char *result = NULL;
    size_t needle_len = strlen(needle);
    size_t haystack_len = strlen(haystack);

    if (needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    for (const char *p = haystack + haystack_len - needle_len; p >= haystack; p--) {
        if (strncmp(p, needle, needle_len) == 0) {
            result = (char *)p;
            break;
        }
    }
    return result;
}

static unsigned char *
parse_dns_query_name(unsigned char *query, char *name) {
    unsigned char *ptr = query;
    char *name_ptr = name;
    int len = 0;

    while ((len = *ptr++)) {
        if (len & 0xC0) {
            // Compression not handled
            return NULL;
        }
        memcpy(name_ptr, ptr, len);
        name_ptr += len;
        ptr += len;
        *name_ptr++ = '.';
    }
    *--name_ptr = '\0'; // Remove the last dot
    return ptr;
}

static int 
process_dns_response(unsigned char *response, int response_len) {
    struct dns_header *header = NULL;
    unsigned char *ptr = response + sizeof(struct dns_header);
    char query_name[MAX_DNS_NAME] = {0};
    t_domain_trusted *trusted_domain = NULL;
    int qdcount, ancount;

    if (parse_dns_header(response, response_len, &header) != 0)
        return -1;

    qdcount = ntohs(header->qdcount);
    ancount = ntohs(header->ancount);

    if (parse_dns_question(&ptr, query_name, qdcount) != 0)
        return -1;

    if (!is_trusted_domain(query_name, &trusted_domain))
        return 0; // Not a trusted domain

    if (process_dns_answers(&ptr, ancount, trusted_domain) != 0)
        return -1;

    return 0;
}

static int 
parse_dns_header(unsigned char *response, int response_len, struct dns_header **header) {
    if (response_len <= sizeof(struct dns_header)) {
        debug(LOG_WARNING, "Invalid DNS response, response_len=%d", response_len);
        return -1;
    }
    *header = (struct dns_header *)response;
    if ((*header)->qr != 1 || (*header)->opcode != 0 || (*header)->rcode != 0) {
        debug(LOG_WARNING, "Invalid DNS response, qr=%d, opcode=%d, rcode=%d",
              (*header)->qr, (*header)->opcode, (*header)->rcode);
        return -1;
    }
    return 0;
}

static int 
parse_dns_question(unsigned char **ptr, char *query_name, int qdcount) {
    if (qdcount != 1) {
        debug(LOG_WARNING, "Unsupported qdcount=%d", qdcount);
        return -1;
    }
    for (int i = 0; i < qdcount; i++) {
        *ptr = parse_dns_query_name(*ptr, query_name);
        if (!*ptr) {
            debug(LOG_WARNING, "Failed to parse DNS query name");
            return -1;
        }
        *ptr += 4; // Skip QTYPE and QCLASS
    }
    return 0;
}

static int 
is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain) {
    s_config *config = config_get_config();
    t_domain_trusted *p = config->pan_domains_trusted;
    while (p) {
        if (safe_strrstr(query_name, p->domain)) {
            debug(LOG_DEBUG, "Found trusted wildcard domain: %s", p->domain);
            *trusted_domain = p;
            return 1;
        }
        p = p->next;
    }
    return 0;
}

static int 
process_dns_answers(unsigned char **ptr, int ancount, t_domain_trusted *trusted_domain) {
    for (int i = 0; i < ancount; i++) {
        // Skip the name
        if ((**ptr & 0xC0) == 0xC0) {
            *ptr += 2; // Compressed name pointer
        } else {
            while (**ptr) {
                *ptr += (**ptr) + 1;
            }
            (*ptr)++;
        }

        // Read TYPE and CLASS
        uint16_t type = ntohs(*(uint16_t *)(*ptr));
        *ptr += 2;
        *ptr += 2; // Skip CLASS
        *ptr += 4; // Skip TTL
        uint16_t data_len = ntohs(*(uint16_t *)(*ptr));
        *ptr += 2;

        if ((type == 1 && data_len == 4) || (type == 28 && data_len == 16)) {
            // A or AAAA record
            unsigned char *addr_ptr = *ptr;
            *ptr += data_len;

            if (add_trusted_ip(trusted_domain, type, addr_ptr) != 0)
                return -1;
        } else {
            // Skip data
            *ptr += data_len;
        }
    }
    return 0;
}

static int 
add_trusted_ip(t_domain_trusted *trusted_domain, uint16_t type, unsigned char *addr_ptr) {
    t_ip_trusted *ip_trusted = trusted_domain->ips_trusted;
    int found = 0;
    while (ip_trusted) {
        if (ip_trusted->ip_type == (type == 1 ? IP_TYPE_IPV4 : IP_TYPE_IPV6)) {
            if ((type == 1 && ip_trusted->uip.ipv4.s_addr == *(uint32_t *)addr_ptr) ||
                (type == 28 && memcmp(&ip_trusted->uip.ipv6, addr_ptr, 16) == 0)) {
                found = 1;
                break;
            }
        }
        ip_trusted = ip_trusted->next;
    }

    if (!found) {
        char ip_str[INET6_ADDRSTRLEN] = {0};
        if (type == 1) {
            inet_ntop(AF_INET, addr_ptr, ip_str, sizeof(ip_str));
        } else {
            inet_ntop(AF_INET6, addr_ptr, ip_str, sizeof(ip_str));
        }
        debug(LOG_DEBUG, "Trusted domain: %s -> %s", trusted_domain->domain, ip_str);

        t_ip_trusted *new_ip_trusted = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
        if (!new_ip_trusted) {
            debug(LOG_ERR, "Memory allocation failed");
            return -1;
        }
        if (type == 1) {
            new_ip_trusted->ip_type = IP_TYPE_IPV4;
            memcpy(&new_ip_trusted->uip.ipv4, addr_ptr, 4);
        } else {
            new_ip_trusted->ip_type = IP_TYPE_IPV6;
            memcpy(&new_ip_trusted->uip.ipv6, addr_ptr, 16);
        }
        new_ip_trusted->next = trusted_domain->ips_trusted;
        trusted_domain->ips_trusted = new_ip_trusted;

        // Add to nftables
        char cmd[256] = {0};
        if (type == 1) {
            snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_inner_trust_domains { %s }", ip_str);
        } else {
            snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_inner_trust_domains_v6 { %s }", ip_str);
        }
        system(cmd);
    }
    return 0;
}

static void 
dns_read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct dns_query *query = (struct dns_query *)arg;
    unsigned char response[512] = {0};
    int response_len = recv(fd, response, sizeof(response), 0);

    if (response_len > 0) {
        process_dns_response(response, response_len);
        sendto(query->client_fd, response, response_len, 0, (struct sockaddr *)&query->client_addr, query->client_len);
    } else {
        debug(LOG_ERR, "DNS response recv failed: %s", strerror(errno));
    }

    // Clean up
    event_free(query->dns_event);
    close(fd);
    free(query);
}

static void 
read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct event_base *base = (struct event_base *)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[512] = {0};

    int recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
    if (recv_len > 0) {
        // Forward DNS query to dns server
        int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dns_sock < 0) {
            debug(LOG_ERR, "socket: %s", strerror(errno));
            return;
        }

        struct sockaddr_in dns_addr;
        memset(&dns_addr, 0, sizeof(dns_addr));
        dns_addr.sin_family = AF_INET;
        dns_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        dns_addr.sin_port = htons(LOCAL_DNS_PORT);

        if (sendto(dns_sock, buffer, recv_len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
            debug(LOG_ERR, "sendto: %s", strerror(errno));
            close(dns_sock);
            return;
        }

        // Create a new dns_query structure
        struct dns_query *query = (struct dns_query *)malloc(sizeof(struct dns_query));
        if (!query) {
            debug(LOG_ERR, "malloc: %s", strerror(errno));
            close(dns_sock);
            return;
        }
        query->client_fd = fd;
        query->client_addr = client_addr;
        query->client_len = client_len;
        memcpy(query->buffer, buffer, recv_len);
        query->buffer_len = recv_len;

        // Set up an event to listen for dns server's response
        query->dns_event = event_new(base, dns_sock, EV_READ | EV_PERSIST, dns_read_cb, query);
        if (!query->dns_event) {
            debug(LOG_ERR, "event_new: %s", strerror(errno));
            free(query);
            close(dns_sock);
            return;
        }

        if (event_add(query->dns_event, NULL) < 0) {
            debug(LOG_ERR, "event_add: %s", strerror(errno));
            event_free(query->dns_event);
            free(query);
            close(dns_sock);
            return;
        }
    }
}

void *
dns_forward_thread(void *arg) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug(LOG_ERR, "Failed to create socket");
        return NULL;
    }

    // Bind to port 5353
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_FORWARD_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        debug(LOG_ERR, "Failed to bind to port %d", DNS_FORWARD_PORT);
        close(sockfd);
        return NULL;
    }

    // Initialize libevent
    struct event_base *base = event_base_new();
    if (!base) {
        debug(LOG_ERR, "event_base_new: %s", strerror(errno));
        close(sockfd);
        return NULL;
    }

    // Create an event to listen for incoming DNS requests
    struct event *dns_event = event_new(base, sockfd, EV_READ | EV_PERSIST, read_cb, base);
    if (!dns_event) {
        debug(LOG_ERR, "event_new: %s", strerror(errno));
        event_base_free(base);
        close(sockfd);
        return NULL;
    }

    // Add the event to the event base
    if (event_add(dns_event, NULL) < 0) {
        debug(LOG_ERR, "event_add: %s", strerror(errno));
        event_free(dns_event);
        event_base_free(base);
        close(sockfd);
        return NULL;
    }

    debug(LOG_INFO, "DNS forwarder started on port %d", DNS_FORWARD_PORT);

    // Dispatch events
    event_base_dispatch(base);

    // Clean up
    event_free(dns_event);
    event_base_free(base);
    close(sockfd);

    return NULL;
}


