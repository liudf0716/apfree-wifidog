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

    for (size_t i = haystack_len - needle_len; i > 0; i--) {
        if (strncmp(haystack + i, needle, needle_len) == 0) {
            result = (char *)(haystack + i);
            break;
        }
    }

    return result;
};

static unsigned char *
parse_dns_query_name(unsigned char *query, char *name) {
    unsigned char *ptr = query;
    char *name_ptr = name;

    while (*ptr != 0) {
        // Get the length of the next label
        int len = *ptr++;

        // Copy the label to the name
        for (int i = 0; i < len; i++) {
            *name_ptr++ = *ptr++;
        }

        // Add a dot between labels
        *name_ptr++ = '.';
    }

    // Replace the last dot with a null terminator
    *--name_ptr = '\0';

    // Return the pointer to the end of the query
    return ptr + 1;
}

static int 
process_dns_response(unsigned char *response, int response_len) {
    s_config *config = config_get_config();
    
    if (response_len <= sizeof(struct dns_header)) {
        debug(LOG_WARNING, "Invalid DNS response");
        return -1;
    }
    struct dns_header *header = (struct dns_header *)response;
    if (header->qr != 1 || header->opcode != 0 || header->rcode != 0) {
        debug(LOG_WARNING, "Invalid DNS response");
        return -1;
    }

    char query_name[MAX_DNS_NAME] = {0};
    int qdcount = ntohs(header->qdcount);
    int ancount = ntohs(header->ancount);
    unsigned char *ptr = response + sizeof(struct dns_header); // Skip the DNS header
    debug(LOG_DEBUG, "DNS response: qdcount=%d, ancount=%d", qdcount, ancount);

    // Skip the question section
    assert(qdcount == 1); // Only handle one question (A record)
    for (int i = 0; i < qdcount; i++) {
        ptr = parse_dns_query_name(ptr, query_name);
        ptr += 4; // Skip QTYPE and QCLASS
    }
    debug(LOG_DEBUG, "DNS query: %s %x %x", query_name, *ptr, *(ptr + 1));
    // find the trusted domain in the query_name
    t_domain_trusted *p = config->pan_domains_trusted;
    while (p) {
        if (strrstr(query_name, p->domain)) {
            debug(LOG_DEBUG, "Find trusted wildcard domain: %s", p->domain);
            break;
        }
        p = p->next;
    }

    if (!p) {
        debug(LOG_DEBUG, "No trusted wildcard domain found in the query");
        return 0;
    }

    // Parse the answer section
    for (int i = 0; i < ancount; i++) {
        ptr += 2; // Skip the name
        // get the type and data length
        unsigned short type = ntohs(*(unsigned short *)ptr);
        ptr += 8; // Skip class, TTL, and data length
        unsigned short data_len = ntohs(*(unsigned short *)ptr);
        ptr += 2;

        debug(LOG_DEBUG, "Type: %d, Data length: %d", type, data_len);
        if (type == 1 && data_len == 4) { // Type A record
            t_ip_trusted *ip_trusted = p->ips_trusted;
            while(ip_trusted) {
                if (ip_trusted->uip == *(unsigned int *)ptr) {
                    break;
                }
                ip_trusted = ip_trusted->next;
            }
            if (!ip_trusted) {
                char ip[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, ptr, ip, sizeof(ip));
                debug(LOG_DEBUG, "Trusted domain: %s -> %s", query_name, ip);
                t_ip_trusted *new_ip_trusted = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
                new_ip_trusted->uip = *(unsigned int *)ptr;
                new_ip_trusted->next = p->ips_trusted;
                p->ips_trusted = new_ip_trusted;
                char cmd[128] = {0};
                snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_inner_trust_domains { %s }", ip);
                system(cmd);
            }
        }
        ptr += data_len;
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
        debug(LOG_DEBUG, "Received DNS response from local dns server");

        // Process DNS response for trusted domains
        process_dns_response(response, response_len);

        // Send the DNS response back to the client
        sendto(query->client_fd, response, response_len, 0, (struct sockaddr *)&query->client_addr, query->client_len);
        debug(LOG_DEBUG, "Sent DNS response to client");
    } else {
        perror("recv");
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
        debug(LOG_DEBUG, "Received DNS request");

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


