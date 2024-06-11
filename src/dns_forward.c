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
    struct event *dnsmasq_event;
};

static char *
strrstr(const char *haystack, const char *needle) 
{
    // Find the last occurrence of the substring needle in the string haystack
    char *result = NULL;
    size_t needle_len = strlen(needle);
    size_t haystack_len = strlen(haystack);
    if (needle_len > haystack_len) {
        return NULL;
    }

    for (size_t i = haystack_len - needle_len; i >= 0; i--) {
        if (strncmp(haystack + i, needle, needle_len) == 0) {
            result = (char *)(haystack + i);
            break;
        }
    }

    return result;
};

static void 
process_dns_response(char *response, int response_len) 
{
    ns_msg handle;
    s_config *config = config_get_config();


    if (ns_initparse((const uint8_t *)response, response_len, &handle) < 0) {
        debug(LOG_WARNING, "ns_initparse: %s", strerror(errno));
        return;
    }

    int msg_count = ns_msg_count(handle, ns_s_an);
    for (int i = 0; i < msg_count; i++) {
        ns_rr rr;
        if (ns_parserr(&handle, ns_s_an, i, &rr) < 0) {
            debug(LOG_WARNING, "ns_parserr: %s", strerror(errno));
            continue;
        }

        if (ns_rr_type(rr) == ns_t_a) {
            t_domain_trusted *p = NULL;
            char domain[NS_MAXDNAME] = {0};
            ns_name_uncompress(ns_msg_base(handle), ns_msg_end(handle), ns_rr_name(rr), domain, sizeof(domain));
            debug(LOG_DEBUG, "Get dns response domain: %s", domain);
            for (p = config->pan_domains_trusted; p; p = p->next) {
                // reverse match the domain, check if the domain include p->domain
                if (strrstr(domain, p->domain) != NULL) {
                    struct in_addr addr;
                    char cmd[128] = {0};
                    memcpy(&addr, ns_rr_rdata(rr), sizeof(addr));
                    debug(LOG_DEBUG, "Trusted domain: %s -> %s", domain, inet_ntoa(addr));
                    snprintf(cmd, sizeof(cmd), "nft add element set wifidogx_inner_trust_domains %s", inet_ntoa(addr));
                    system(cmd);
                    break;
                }
            }
        }
    }
}

static void 
dnsmasq_read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct dns_query *query = (struct dns_query *)arg;
    char response[512];
    int response_len = recv(fd, response, sizeof(response), 0);

    if (response_len > 0) {
        debug(LOG_DEBUG, "Received DNS response from dnsmasq");

        // Process DNS response for trusted domains
        process_dns_response(response, response_len);

        // Send the DNS response back to the client
        sendto(query->client_fd, response, response_len, 0, (struct sockaddr *)&query->client_addr, query->client_len);
        debug(LOG_DEBUG, "Sent DNS response to client");
    } else {
        perror("recv");
    }

    // Clean up
    event_free(query->dnsmasq_event);
    close(fd);
    free(query);
}

static void 
read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct event_base *base = (struct event_base *)arg;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[512];

    int recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);
    if (recv_len > 0) {
        debug(LOG_DEBUG, "Received DNS request");

        // Forward DNS query to dnsmasq
        int dnsmasq_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dnsmasq_sock < 0) {
            debug(LOG_ERR, "socket: %s", strerror(errno));
            return;
        }

        struct sockaddr_in dnsmasq_addr;
        memset(&dnsmasq_addr, 0, sizeof(dnsmasq_addr));
        dnsmasq_addr.sin_family = AF_INET;
        dnsmasq_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        dnsmasq_addr.sin_port = htons(LOCAL_DNS_PORT);

        if (sendto(dnsmasq_sock, buffer, recv_len, 0, (struct sockaddr *)&dnsmasq_addr, sizeof(dnsmasq_addr)) < 0) {
            debug(LOG_ERR, "sendto: %s", strerror(errno));
            close(dnsmasq_sock);
            return;
        }

        // Create a new dns_query structure
        struct dns_query *query = (struct dns_query *)malloc(sizeof(struct dns_query));
        if (!query) {
            debug(LOG_ERR, "malloc: %s", strerror(errno));
            close(dnsmasq_sock);
            return;
        }
        query->client_fd = fd;
        query->client_addr = client_addr;
        query->client_len = client_len;
        memcpy(query->buffer, buffer, recv_len);
        query->buffer_len = recv_len;

        // Set up an event to listen for dnsmasq's response
        query->dnsmasq_event = event_new(base, dnsmasq_sock, EV_READ | EV_PERSIST, dnsmasq_read_cb, query);
        if (!query->dnsmasq_event) {
            debug(LOG_ERR, "event_new: %s", strerror(errno));
            free(query);
            close(dnsmasq_sock);
            return;
        }

        if (event_add(query->dnsmasq_event, NULL) < 0) {
            debug(LOG_ERR, "event_add: %s", strerror(errno));
            event_free(query->dnsmasq_event);
            free(query);
            close(dnsmasq_sock);
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


