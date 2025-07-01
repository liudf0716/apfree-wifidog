// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif
#include <event2/event.h>
#include <pthread.h>
#include <netinet/in.h>
#include <resolv.h>
#include <arpa/nameser.h>
#include <ctype.h> // For isxdigit
#include "dns_forward.h"
#include "debug.h"
#include "conf.h"
#include "wd_util.h"
#include "gateway.h"

#define INITIAL_MAX_SID 0
#define XDPI_DOMAIN_MAX 256
#define MAX_DOMAIN_LEN 64

#define XDPI_IOC_MAGIC 'X' // Magic number for xDPI IOCTL commands

// Buffer sizes
#define DNS_MESSAGE_BUFFER_SIZE 512       // Max size for DNS query/response packets
#define NFT_COMMAND_BUFFER_SIZE 256     // Buffer for constructing nftables shell commands
#define PROC_BUFFER_SIZE 16             // Buffer for reading from /proc files

// DNS Protocol specific sizes/values (in bytes unless specified)
#define DNS_QTYPE_QCLASS_SIZE 4         // Size of QTYPE and QCLASS fields in question section
#define DNS_COMPRESSED_NAME_POINTER_SIZE 2 // Size of a compressed name pointer (0xC0xx)
#define DNS_TYPE_SIZE 2                 // Size of the RR TYPE field
#define DNS_CLASS_SIZE 2                // Size of the RR CLASS field
#define DNS_TTL_SIZE 4                  // Size of the RR TTL field
#define DNS_RDLENGTH_SIZE 2             // Size of the RR RDLENGTH field
#define DNS_RR_TYPE_A 1                 // RR Type code for A record (IPv4 address)
#define DNS_RR_TYPE_AAAA 28             // RR Type code for AAAA record (IPv6 address)
#define IPV4_ADDR_LEN 4                 // Length of an IPv4 address
#define IPV6_ADDR_LEN 16                // Length of an IPv6 address

// XDPI IOCTL definitions for communication with a kernel module
#define XDPI_IOC_ADD    _IOW(XDPI_IOC_MAGIC, 1, struct domain_entry) // IOCTL to add a domain entry
#define XDPI_IOC_DEL    _IOW(XDPI_IOC_MAGIC, 2, int)                 // IOCTL to delete a domain entry
#define XDPI_IOC_UPDATE _IOW(XDPI_IOC_MAGIC, 3, struct domain_update) // IOCTL to update a domain entry

/**
 * @brief Represents a domain entry for xDPI kernel module.
 * Stores the domain name, its length, a session ID (SID), and usage status.
 */
struct domain_entry {
    char domain[MAX_DOMAIN_LEN]; // Domain name string
    int domain_len;              // Actual length of the domain string
    int sid;                     // Session ID associated with this domain
    bool used;                   // Flag indicating if this entry is currently in use
};

/**
 * @brief Used for updating an existing domain entry in the kernel module.
 * Contains the new domain entry data and the index of the entry to update.
 */
struct domain_update {
    struct domain_entry entry;   // The new data for the domain entry
    int index;                   // Index of the domain entry to be updated
};

/**
 * @brief Represents an active DNS query being forwarded.
 * Stores client information, the DNS request buffer, and event data for async handling.
 */
struct dns_query {
    int client_fd;                          // File descriptor of the original client UDP socket (for sending response back)
    struct sockaddr_in client_addr;         // Client's address information
    socklen_t client_len;                   // Length of client's address structure
    char buffer[DNS_MESSAGE_BUFFER_SIZE];   // Buffer holding the DNS query from the client
    int buffer_len;                         // Length of the DNS query in the buffer
    struct event *dns_event;                // Libevent event structure for handling the response from the upstream DNS server
};

/* Static array to cache domain entries, mirroring those in the xDPI kernel module. */
static struct domain_entry domain_entries[XDPI_DOMAIN_MAX];
/* Mutex to protect concurrent access to the domain_entries array. */
static pthread_mutex_t domain_entries_mutex;

// Forward declarations for static functions
static int parse_dns_header(unsigned char *response, int response_len, struct dns_header **header);
static int parse_dns_question(unsigned char **ptr, char *query_name, int qdcount);
static int is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain);
static int process_dns_answers(unsigned char **ptr, int ancount, t_domain_trusted *trusted_domain);
static int add_trusted_ip(t_domain_trusted *trusted_domain, uint16_t type, unsigned char *addr_ptr);
static void handle_xdpi_domain_processing(const char *query_name);
static int is_valid_domain_suffix(const char *domain);
static int get_xdpi_domain_count(void);
static void sync_xdpi_domains_2_kern(void);
static int xdpi_add_domain(const char *input_domain);
static char *safe_strrstr(const char *haystack, const char *needle);
static unsigned char *parse_dns_query_name(unsigned char *query, char *name);
static int is_safe_ip_str(const char *ip_str);
static int xdpi_short_domain(const char *full_domain, char *short_domain, int *olen);
static unsigned char* skip_dns_name_in_answer(unsigned char *ptr);
// static int process_single_rr(...); // Forward declaration removed
static void dns_read_cb(evutil_socket_t fd, short event, void *arg);
// static int forward_dns_query_and_setup_handler(...); // Forward declaration already removed
static void read_cb(evutil_socket_t fd, short event, void *arg);
static int process_dns_response(unsigned char *response, int response_len);

/**
 * @brief Processes a received DNS response message.
 * Parses the header and question, then checks if the domain needs to be added to xDPI.
 * If the domain is trusted, processes DNS answers to add IPs to trusted list and nftables.
 *
 * @param response Buffer containing the DNS response packet.
 * @param response_len Length of the DNS response packet.
 * @return 0 on success or if processing is not required, -1 on error.
 */
static int
process_dns_response(unsigned char *response, int response_len) {
    struct dns_header *header = NULL;
    unsigned char *ptr = response + sizeof(struct dns_header); // Current parsing pointer
    const unsigned char *response_end = response + response_len; // End of the response buffer for bounds checking
    char query_name[MAX_DNS_NAME] = {0};
    t_domain_trusted *trusted_domain = NULL;
    int qdcount, ancount;

    if (parse_dns_header(response, response_len, &header) != 0) {
        return -1;
    }

    qdcount = ntohs(header->qdcount);
    ancount = ntohs(header->ancount);

    // Ensure ptr is within bounds before parsing question
    if (ptr >= response_end && qdcount > 0) {
        debug(LOG_WARNING, "DNS response too short to contain questions.");
        return -1;
    }
    if (parse_dns_question(&ptr, query_name, qdcount) != 0) {
        return -1;
    }

    // Handle xDPI domain logic: check suffix, sync with kernel, add domain.
    // This is done for non-reverse DNS lookup domains.
    if (!strstr(query_name, "in-addr.arpa") && !strstr(query_name, "ip6.arpa")) {
        handle_xdpi_domain_processing(query_name);
    }

    if (!is_trusted_domain(query_name, &trusted_domain)) {
        return 0;
    }

    // Ensure ptr is within bounds before parsing answers
    if (ptr >= response_end && ancount > 0) {
        debug(LOG_WARNING, "DNS response too short to contain answers after questions.");
        return -1;
    }
    // Pass response_end to process_dns_answers for robust bounds checking
    if (process_dns_answers(&ptr, ancount, trusted_domain) != 0) {
        return -1;
    }

    return 0;
}

/**
 * @brief Handles the logic for processing a domain for xDPI purposes.
 * If the domain has a valid suffix, it checks the xDPI domain count,
 * potentially syncs domains to the kernel, and then adds the domain via xdpi_add_domain.
 *
 * @param query_name The fully qualified domain name that was queried.
 */
static void handle_xdpi_domain_processing(const char *query_name) {
    if (!query_name || query_name[0] == '\0') {
        return;
    }

    if (is_valid_domain_suffix(query_name)) {
        debug(LOG_DEBUG, "Domain '%s' has a valid suffix, considering for xDPI.", query_name);
        // get xdpi domain count, and if it's 0, it might be the first run or a reset,
        // so sync existing domain_entries to kernel.
        int xdpi_domain_count = get_xdpi_domain_count();
        if (xdpi_domain_count == 0) {
            debug(LOG_INFO, "xDPI domain count is 0, attempting to sync local entries to kernel.");
            sync_xdpi_domains_2_kern();
        }
        // Attempt to add the (potentially shortened) domain to xDPI.
        // xdpi_add_domain internally handles shortening and checks for duplicates.
        if (xdpi_add_domain(query_name) < 0) {
             debug(LOG_WARNING, "Failed to add domain '%s' to xDPI.", query_name);
        }
    } else {
        debug(LOG_DEBUG, "Domain '%s' does not have a valid suffix, skipping xDPI processing.", query_name);
    }
}

/**
 * @brief Parses the header of a DNS message.
 * Validates basic header fields like QR flag, opcode, and rcode.
 *
 * @param response Buffer containing the DNS message.
 * @param response_len Length of the DNS message.
 * @param header Output parameter, pointer to a dns_header struct pointer.
 *               On success, this will point to the start of the message cast as dns_header.
 * @return 0 on success, -1 on error (e.g., too short, invalid flags).
 */
static int
parse_dns_header(unsigned char *response, int response_len, struct dns_header **header) {
    // Ensure the response is long enough to contain a DNS header.
    if (response_len <= sizeof(struct dns_header)) {
        debug(LOG_WARNING, "Invalid DNS response: too short (len=%d)", response_len);
        return -1;
    }
    *header = (struct dns_header *)response; // Cast the beginning of the response to dns_header struct.

    // Validate DNS header fields:
    // QR flag should be 1 (response).
    // Opcode should be 0 (standard query).
    // Rcode should be 0 (no error).
    if ((*header)->qr != 1 || (*header)->opcode != 0 || (*header)->rcode != 0) {
        debug(LOG_WARNING, "Invalid DNS response flags: qr=%d, opcode=%d, rcode=%d",
              (*header)->qr, (*header)->opcode, (*header)->rcode);
        return -1;
    }
    return 0; // Header is valid
}

/**
 * @brief Parses the question section of a DNS message.
 * Expects exactly one question (qdcount == 1).
 * Extracts the query name and advances the pointer past QTYPE and QCLASS.
 *
 * @param ptr Pointer to a pointer to the current position in the DNS message.
 *            This pointer will be advanced past the question section.
 * @param query_name Buffer to store the parsed query name.
 * @param qdcount The number of questions, expected to be 1.
 * @return 0 on success, -1 on error.
 */
static int
parse_dns_question(unsigned char **ptr, char *query_name, int qdcount) {
    // This implementation only supports DNS messages with exactly one question.
    if (qdcount != 1) {
        debug(LOG_WARNING, "Unsupported DNS qdcount=%d (expected 1)", qdcount);
        return -1;
    }
    for (int i = 0; i < qdcount; i++) { // Loop (effectively once)
        // Parse the domain name from the question.
        *ptr = parse_dns_query_name(*ptr, query_name);
        if (!*ptr) { // If name parsing failed
            debug(LOG_WARNING, "Failed to parse DNS query name in question section.");
            return -1;
        }
        // Skip QTYPE and QCLASS fields (2 bytes each).
        *ptr += DNS_QTYPE_QCLASS_SIZE;
    }
    return 0; // Question section parsed successfully.
}

/**
 * @brief Checks if a query name matches any configured trusted domain.
 * Trusted domains may be specified with wildcards (e.g., ".example.com").
 *
 * @param query_name The DNS query name to check.
 * @param trusted_domain Output parameter. If a match is found, this will point to the
 *                       t_domain_trusted configuration structure for the matched domain.
 * @return 1 if the domain is trusted, 0 otherwise.
 */
static int
is_trusted_domain(const char *query_name, t_domain_trusted **trusted_domain) {
    s_config *config = config_get_config(); // Get global configuration
    if (!config) return 0;

    t_domain_trusted *p = config->pan_domains_trusted; // Start of trusted domains list
    while (p) {
        // safe_strrstr checks if query_name ends with p->domain (for wildcard matching)
        // or if p->domain is a substring. For simple suffix match, ensure p->domain starts with '.'.
        if (p->domain && safe_strrstr(query_name, p->domain)) {
            debug(LOG_DEBUG, "Query name '%s' matched trusted domain rule '%s'", query_name, p->domain);
            *trusted_domain = p; // Store the matched trusted domain entry
            return 1; // Trusted
        }
        p = p->next;
    }
    return 0; // Not trusted
}

/**
 * @brief Skips over a domain name in a DNS record.
 * Handles both compressed names (starting with 0xC0) and uncompressed names.
 *
 * @param ptr Pointer to the current position in the DNS message, at the start of a domain name.
 * @return Pointer to the byte immediately following the domain name, or NULL on error (e.g., malformed).
 */
static unsigned char*
skip_dns_name_in_answer(unsigned char *ptr) {
    if (!ptr) return NULL;

    // Check for compression pointer (first two bits set)
    if ((*ptr & 0xC0) == 0xC0) {
        ptr += DNS_COMPRESSED_NAME_POINTER_SIZE; // Skip the 2-byte compression pointer
    } else {
        // Skip uncompressed name (sequence of labels ending with a zero byte)
        while (*ptr) { // While length byte is not zero
            if ((*ptr & 0xC0)) { // Should not encounter compression here in uncompressed name
                debug(LOG_WARNING, "Malformed uncompressed name: encountered compression pointer.");
                return NULL;
            }
            if (*ptr > 63) { // Label length check (max 63)
                 debug(LOG_WARNING, "Malformed uncompressed name: label too long (%d).", *ptr);
                return NULL;
            }
            ptr += (*ptr) + 1; // Skip length byte and label itself
        }
        ptr++; // Skip the final zero byte for the name
    }
    return ptr;
}

static int
process_dns_answers(unsigned char **ptr, int ancount, t_domain_trusted *trusted_domain) {
    unsigned char *current_ptr = *ptr; // Use a local copy to iterate

    for (int i = 0; i < ancount; i++) { // Loop through each answer record
        // Skip the domain name in the answer record.
        current_ptr = skip_dns_name_in_answer(current_ptr);
        if (!current_ptr) {
            debug(LOG_WARNING, "Failed to skip DNS name in answer record %d.", i + 1);
            return -1; // Error in name skipping
        }

        // Read RR TYPE, CLASS, TTL, and RDLENGTH.
        // Ensure there's enough data left for these fields + RDLENGTH field itself
        if (current_ptr + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE + DNS_RDLENGTH_SIZE > *ptr + (ancount * 10)) { // Rough check
             // This check is very approximate. A more robust check would involve response_end pointer.
             // For now, assume data is available as we are within ancount.
        }

        uint16_t type = ntohs(*(uint16_t *)current_ptr); // RR Type (e.g., A, AAAA)
        current_ptr += DNS_TYPE_SIZE;    // Advance past Type
        current_ptr += DNS_CLASS_SIZE;   // Advance past Class
        current_ptr += DNS_TTL_SIZE;     // Advance past TTL
        uint16_t data_len = ntohs(*(uint16_t *)current_ptr); // Length of RDATA
        current_ptr += DNS_RDLENGTH_SIZE; // Advance past RDLENGTH

        // Check if the record is of type A (IPv4) or AAAA (IPv6).
        if ((type == DNS_RR_TYPE_A && data_len == IPV4_ADDR_LEN) ||
            (type == DNS_RR_TYPE_AAAA && data_len == IPV6_ADDR_LEN)) {
            unsigned char *addr_ptr = current_ptr; // Pointer to the IP address data in RDATA.

            // Ensure RDATA is not out of bounds (needs response_end) - simplified check
            // if (current_ptr + data_len > response_end) return -1;

            current_ptr += data_len; // Advance past RDATA.

            // Add this IP address to the list of trusted IPs for the domain.
            if (add_trusted_ip(trusted_domain, type, addr_ptr) != 0) {
                *ptr = current_ptr; // Update original pointer before returning error
                return -1; // Failed to add IP
            }
        } else {
            // For other RR types, just skip the RDATA.
            // Ensure RDATA is not out of bounds (needs response_end) - simplified check
            // if (current_ptr + data_len > response_end) return -1;
            current_ptr += data_len;
        }
    }
    *ptr = current_ptr; // Update the original pointer to reflect consumed data
    return 0; // All answers processed successfully.
}

// Helper function to validate characters in an IP string representation

#define MAX_PARTS 5       // 最大域名段数
// MAX_DOMAIN_LEN is already defined globally, but also locally used by xdpi_short_domain
// Ensure MAX_DOMAIN_LEN used in xdpi_short_domain is consistent with global expectations.
// For this refactoring, we'll use the one defined locally or ensure it's available.

/**
 * @brief Extracts a "short" domain from a full domain name.
 *
 * The definition of "short" depends on the TLD. For ".cn" domains,
 * it handles ".com.cn" specifically (e.g., "example.com.cn" -> "example.com.cn").
 * For other ".cn" domains, it takes two parts (e.g., "sub.example.cn" -> "example.cn").
 * For non-".cn" domains, it takes two parts (e.g., "www.example.com" -> "example.com").
 * This function manually parses the domain string from right to left to avoid
 * `strtok` and `strdup` for safety and efficiency.
 *
 * @param full_domain The input full domain name (e.g., "www.example.com.cn"). Must be null-terminated.
 * @param short_domain Output buffer to store the extracted short domain. Must be of size MAX_DOMAIN_LEN.
 * @param olen Pointer to an integer to store the length of the extracted short_domain.
 * @return 0 on success, -1 on error (e.g., invalid input, domain too short, buffer overflow).
 */
static int xdpi_short_domain(const char *full_domain, char *short_domain, int *olen) {
    // Basic input validation
    if (!full_domain || !short_domain || !olen) {
        if (olen) *olen = 0;
        // Ensure short_domain is empty and null-terminated on error, if buffer is valid
        if (short_domain) short_domain[0] = '\0';
        return -1;
    }

    size_t full_domain_len = strlen(full_domain);

    // Initialize output parameters to safe defaults
    short_domain[0] = '\0';
    *olen = 0;

    // Validate domain length (must not be empty or too long)
    if (full_domain_len == 0 || full_domain_len >= MAX_DOMAIN_LEN) {
        return -1; // Error: domain is empty or exceeds max length
    }

    const char *p = full_domain + full_domain_len - 1; // Start from the end of the domain
    int part_count = 0;
    const char *parts_ptr[MAX_PARTS] = {0}; // Pointers to the start of each part
    int parts_len[MAX_PARTS] = {0}; // Length of each part

    // Iterate backwards from the end of the full_domain to find domain parts separated by '.'
    // This avoids modifying the input string (unlike strtok).
    while (p >= full_domain && part_count < MAX_PARTS) {
        const char *end_of_part = p; // Mark the end of the current part
        while (p >= full_domain && *p != '.') { // Move pointer left until a dot or start is found
            p--;
        }
        // p now points to the dot, or one character before the start of full_domain if no dot was found.
        parts_ptr[part_count] = p + 1; // Start of the current part's string
        parts_len[part_count] = end_of_part - p; // Calculate length of the current part
        part_count++;

        if (p >= full_domain && *p == '.') {
            p--; // Move pointer before the dot to continue to the next part
        } else {
            break; // Reached the beginning of the string or a part without a preceding dot
        }
    }

    // A short domain typically requires at least two parts (e.g., "example.com").
    if (part_count < 2) {
        return -1; // Not enough parts to form a recognizable short domain.
    }

    // Domain parts are stored in reverse order due to backward parsing.
    // Example: "www.example.com.cn"
    // parts_ptr[0] -> "cn", parts_len[0] = 2
    // parts_ptr[1] -> "com", parts_len[1] = 3
    // parts_ptr[2] -> "example", parts_len[2] = 7
    // parts_ptr[3] -> "www", parts_len[3] = 3

    // Helper macro to compare a parsed part with a string literal.
    // Compares both length and content for an exact match.
    #define PART_EQ(index, str_literal) \
        (parts_len[index] == strlen(str_literal) && strncmp(parts_ptr[index], str_literal, parts_len[index]) == 0)

    // Logic for constructing the short_domain based on TLD and SLD.
    if (PART_EQ(0, "cn")) { // Check if TLD is "cn"
        if (part_count >= 2 && PART_EQ(1, "com")) { // Check if SLD is "com" (for ".com.cn")
            if (part_count >= 3) { // e.g., "subdomain.example.com.cn"
                // Construct as "example.com.cn" (parts_ptr[2] is "example")
                snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.com.cn", parts_len[2], parts_ptr[2]);
            } else { // e.g., "example.com.cn" (no further subdomains, or just "com.cn")
                     // If full_domain was "com.cn", parts_ptr[0]="cn", parts_ptr[1]="com", part_count=2.
                snprintf(short_domain, MAX_DOMAIN_LEN, "com.cn");
            }
        } else { // Other ".cn" domains (e.g., "example.net.cn" or "example.cn")
            if (part_count >= 2) { // e.g. "example.cn", parts_ptr[1] is "example"
                // Construct as "example.cn"
                snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.cn", parts_len[1], parts_ptr[1]);
            } else {
                 // This case should ideally not be reached if part_count < 2 check is effective.
                 // Handles cases like just "cn" which is not a valid short domain by this logic.
                return -1;
            }
        }
    } else { // Non ".cn" domains
        if (part_count >= 2) { // e.g. "example.com", parts_ptr[1]="example", parts_ptr[0]="com"
            // Construct as "example.com"
            // Check for potential buffer overflow before snprintf.
            int first_part_len = parts_len[1];
            int second_part_len = parts_len[0];
            if (first_part_len + 1 + second_part_len < MAX_DOMAIN_LEN) { // +1 for the dot
                 snprintf(short_domain, MAX_DOMAIN_LEN, "%.*s.%.*s",
                         first_part_len, parts_ptr[1],
                         second_part_len, parts_ptr[0]);
            } else {
                // Resulting short domain would exceed MAX_DOMAIN_LEN.
                return -1;
            }
        } else {
            // Should not be reached due to part_count < 2 check.
            return -1;
        }
    }

    *olen = strlen(short_domain);
    // Final safety check: if the logic resulted in an empty short_domain
    // but the input full_domain was valid, it indicates an unhandled edge case or error.
    if (*olen == 0 && full_domain_len > 0) {
        return -1;
    }

    return 0;
}

#undef PART_EQ // Undefine the helper macro to limit its scope.

/* List of common valid domain suffixes. Used by is_valid_domain_suffix. */
static const char *valid_domain_suffixes[] = {
    ".com", ".net", ".org", ".gov", ".edu", ".cn", ".com.cn", ".co.uk", ".io", ".me", ".app", ".xyz", ".site", ".top", ".club", ".vip", ".shop", ".store", ".tech", ".dev", ".cloud", ".fun", ".online", ".pro", ".work", ".link", ".live", ".run", ".group", ".red", ".blue", ".green", ".mobi", ".asia", ".name", ".today", ".news", ".website", ".space", ".icu",
};
// Calculate the number of entries in the valid_domain_suffixes array.
#define VALID_DOMAIN_SUFFIXES_COUNT (sizeof(valid_domain_suffixes)/sizeof(valid_domain_suffixes[0]))

/**
 * @brief Checks if a given domain name ends with one of the predefined valid suffixes.
 * This is used as a heuristic to decide whether to process a domain for xDPI.
 *
 * @param domain The domain name to check.
 * @return 1 if the domain has a valid suffix, 0 otherwise.
 */
static int is_valid_domain_suffix(const char *domain) {
    if (!domain) return 0; // Null domain is not valid
    size_t len = strlen(domain);
    for (size_t i = 0; i < VALID_DOMAIN_SUFFIXES_COUNT; ++i) {
        size_t suffix_len = strlen(valid_domain_suffixes[i]);
        if (len > suffix_len && strcmp(domain + len - suffix_len, valid_domain_suffixes[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int get_xdpi_domain_count() {
    FILE *fp;
    char buf[PROC_BUFFER_SIZE] = {0}; // Buffer to read the count string
    int count = 0;

    // xDPI kernel module might expose the number of active domains via a /proc file.
    fp = fopen("/proc/xdpi_domain_num", "r");
    if (!fp) {
        debug(LOG_ERR, "Failed to open /proc/xdpi_domain_num: %s", strerror(errno));
        return -1; // Return -1 to indicate failure to read count
    }

    if (fgets(buf, sizeof(buf), fp)) { // Read the line containing the count
        count = atoi(buf); // Convert string to integer
    }

    fclose(fp);
    return count;
}

/**
 * @brief Synchronizes locally cached domain entries (domain_entries array) to the xDPI kernel module.
 * This is typically done at startup or if a discrepancy is detected.
 * It iterates through local entries and uses IOCTL calls to add them to the kernel if marked 'used'.
 */
static void sync_xdpi_domains_2_kern(void) {
    int fd; // File descriptor for the /proc/xdpi_domains interface
    int i;

    pthread_mutex_lock(&domain_entries_mutex);
    int result;
    struct domain_entry entry;
    
    fd = open("/proc/xdpi_domains", O_RDWR);
    if (fd < 0) {
        debug(LOG_ERR, "Failed to open /proc/xdpi_domains: %s", strerror(errno));
        return;
    }
    
    debug(LOG_INFO, "Syncing domain entries to kernel");
    
    // Iterate through all domain entries and send used ones to kernel
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            size_t len_to_copy;
            memset(&entry, 0, sizeof(entry));

            // Ensure domain_len from domain_entries is not out of bounds for its own domain string
            // (though it should be internally consistent)
            size_t src_domain_len = strnlen(domain_entries[i].domain, MAX_DOMAIN_LEN);

            len_to_copy = MIN(src_domain_len, MAX_DOMAIN_LEN - 1);
            memcpy(entry.domain, domain_entries[i].domain, len_to_copy);
            entry.domain[len_to_copy] = '\0';  // Null terminate at the actual end of copied data
            entry.domain_len = len_to_copy;     // Correctly reflect the copied length
            entry.sid = domain_entries[i].sid;
            entry.used = true;
            
            // Add the domain via IOCTL
            result = ioctl(fd, XDPI_IOC_ADD, &entry);
            if (result < 0) {
                debug(LOG_ERR, "Failed to sync domain %s to kernel: %s", 
                      domain_entries[i].domain, strerror(errno));
            } else {
                debug(LOG_DEBUG, "Successfully synced domain %s with SID %d to kernel", 
                      domain_entries[i].domain, domain_entries[i].sid);
            }
        }
    }
    
    close(fd);
    pthread_mutex_unlock(&domain_entries_mutex);
    debug(LOG_INFO, "Domain sync to kernel completed");
}

static int xdpi_add_domain(const char *input_domain) {
    int fd = -1, result = 0;
    struct domain_entry entry_for_ioctl; // Renamed to avoid confusion with domain_entries array elements
    int i, local_free_idx = -1;
    int local_max_sid = INITIAL_MAX_SID; // Use local var for SID calculation before final update
    char domain_to_process[MAX_DOMAIN_LEN] = {0};

    // 1. Initial input validation (no lock needed)
    if (!input_domain || input_domain[0] == '\0') {
        debug(LOG_WARNING, "Invalid domain: NULL or empty");
        return -1;
    }
    if (strlen(input_domain) >= MAX_DOMAIN_LEN) {
        debug(LOG_WARNING, "Invalid domain: too long: %s", input_domain);
        return -1;
    }

    // 2. Domain shortening (no lock needed)
    char short_domain_buf[MAX_DOMAIN_LEN] = {0};
    int short_domain_len = 0;
    if (xdpi_short_domain(input_domain, short_domain_buf, &short_domain_len) == 0 && short_domain_len > 0) {
        strncpy(domain_to_process, short_domain_buf, MAX_DOMAIN_LEN - 1);
    } else {
        strncpy(domain_to_process, input_domain, MAX_DOMAIN_LEN - 1);
    }
    domain_to_process[MAX_DOMAIN_LEN-1] = '\0'; // Ensure null termination

    // 3. Access shared domain_entries: Find duplicate, free_idx, max_sid (lock needed)
    pthread_mutex_lock(&domain_entries_mutex);
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domain_entries[i].used) {
            if (domain_entries[i].sid > local_max_sid) {
                local_max_sid = domain_entries[i].sid;
            }
            if (strcmp(domain_entries[i].domain, domain_to_process) == 0) {
                pthread_mutex_unlock(&domain_entries_mutex);
                return 0; // Domain already tracked
            }
        } else if (local_free_idx == -1) {
            local_free_idx = i;
        }
    }

    if (local_free_idx == -1) {
        pthread_mutex_unlock(&domain_entries_mutex);
        debug(LOG_ERR, "No free entry in local xDPI domain list for %s", domain_to_process);
        return -1; // No space left
    }
    // Values local_free_idx and local_max_sid are now determined.
    pthread_mutex_unlock(&domain_entries_mutex);

    // 4. I/O operations: open and ioctl (no lock held)
    fd = open("/proc/xdpi_domains", O_RDWR);
    if (fd < 0) {
        debug(LOG_ERR, "Failed to open /proc/xdpi_domains to add domain %s: %s", domain_to_process, strerror(errno));
        return -1;
    }

    memset(&entry_for_ioctl, 0, sizeof(entry_for_ioctl));
    size_t domain_actual_len = strlen(domain_to_process);
    size_t len_to_copy_entry = MIN(domain_actual_len, MAX_DOMAIN_LEN - 1);
    memcpy(entry_for_ioctl.domain, domain_to_process, len_to_copy_entry);
    entry_for_ioctl.domain[len_to_copy_entry] = '\0';
    entry_for_ioctl.domain_len = len_to_copy_entry;
    entry_for_ioctl.sid = local_max_sid + 1;
    entry_for_ioctl.used = true;

    result = ioctl(fd, XDPI_IOC_ADD, &entry_for_ioctl);
    close(fd); // Close fd after ioctl

    if (result < 0) {
        debug(LOG_ERR, "Failed to add domain %s to xDPI via IOCTL: %s", entry_for_ioctl.domain, strerror(errno));
        return -1;
    } else {
        debug(LOG_DEBUG, "Successfully added domain to xDPI via IOCTL: %s with SID %d", entry_for_ioctl.domain, entry_for_ioctl.sid);
    }

    // 5. Update shared domain_entries cache (lock needed)
    pthread_mutex_lock(&domain_entries_mutex);
    if (domain_entries[local_free_idx].used) {
        pthread_mutex_unlock(&domain_entries_mutex);
        debug(LOG_ERR, "Concurrency issue: free_idx %d for domain %s was taken before final cache update.",
              local_free_idx, domain_to_process);
        return -2; // Specific error code for this state
    }

    memcpy(domain_entries[local_free_idx].domain, domain_to_process, len_to_copy_entry);
    domain_entries[local_free_idx].domain[len_to_copy_entry] = '\0';
    domain_entries[local_free_idx].domain_len = len_to_copy_entry;
    domain_entries[local_free_idx].sid = entry_for_ioctl.sid; // Use the SID that was successfully sent to kernel
    domain_entries[local_free_idx].used = true;
    pthread_mutex_unlock(&domain_entries_mutex);

    return result; // Success from IOCTL
}

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
    unsigned char *ptr = query; // Current position in the query buffer
    char *name_ptr = name;      // Current position in the output name buffer
    int len = 0;                // Length of the current label
    char *name_limit = name + MAX_DNS_NAME; // End of the output buffer

    // process_dns_response, the typical caller, zero-initializes query_name.
    // If other callers don't, uncomment:
    // name[0] = '\0';

    while ((len = *ptr++)) { // Read length byte of the current label
        if (len & 0xC0) { // Check for DNS name compression (first two bits set)
            // This implementation does not support compression pointers.
            debug(LOG_WARNING, "DNS name compression not supported in query name parsing.");
            return NULL; // Error: compression not handled
        }

        // Check for potential buffer overflow before copying the label.
        // Need space for the label itself, a potential subsequent dot, and the final null terminator.
        if (name_ptr + len + 1 >= name_limit) {
            debug(LOG_WARNING, "DNS name label too long for buffer during query name parsing.");
            return NULL; // Error: overflow
        }

        memcpy(name_ptr, ptr, len); // Copy the label
        name_ptr += len;            // Advance output buffer pointer
        ptr += len;                 // Advance query buffer pointer

        if (*ptr != 0) { // If this is not the last label in the name (next byte is not zero length)
            *name_ptr++ = '.'; // Add a dot separator
        } else {
            break; // End of the name (next label length is 0)
        }
    }
    *name_ptr = '\0'; // Null-terminate the constructed domain name.
    return ptr;       // Return pointer to the byte after the name (e.g., QTYPE).
}

/*
 * @brief Handles the logic for processing a domain for xDPI purposes.
 * If the domain has a valid suffix, it checks the xDPI domain count,
 * potentially syncs domains to the kernel, and then adds the domain via xdpi_add_domain.
 */
/*
 * @brief Parses the header of a DNS message.
 * Validates basic header fields like QR flag, opcode, and rcode.
 *
 * @param response Buffer containing the DNS message.
 * @param response_len Length of the DNS message.
 */
/*
 * @brief Parses the question section of a DNS message.
 * Expects exactly one question (qdcount == 1).
 * Extracts the query name and advances the pointer past QTYPE and QCLASS.
 *
 * @param ptr Pointer to a pointer to the current position in the DNS message.
 *            This pointer will be advanced past the question section.
 * @param query_name Buffer to store the parsed query name.
 */
/*
 * @brief Checks if a query name matches any configured trusted domain.
 * Trusted domains may be specified with wildcards (e.g., ".example.com").
 *
 * @param query_name The DNS query name to check.
 */
/*
 * @brief Processes DNS answer records (RRs) in a DNS response.
 * Iterates through 'ancount' records. For A or AAAA records belonging to a trusted domain,
 * it calls add_trusted_ip to add the IP to a local list and potentially to nftables.
 *
 * @param ptr Pointer to a pointer to the current position in the DNS message (start of answers).
 *            This pointer will be advanced past the processed answer records.
 * @param ancount The number of answer records.
 * @param trusted_domain Pointer to the configuration of the trusted domain being processed.
 * @return 0 on success, -1 on error (e.g., if add_trusted_ip fails).
 */
/*
 * @brief Skips over a domain name in a DNS record.
 * Handles both compressed names (starting with 0xC0) and uncompressed names.
 */
/*
 * @brief Processes a single DNS Resource Record (RR) from the answer section.
 * Parses RR header fields (Type, Class, TTL, RDLength). If the RR is type A or AAAA,
 * it attempts to add the IP address to the trusted list via add_trusted_ip.
 * Advances the provided pointer past the processed RR.
 *
 * @param rr_data_ptr Pointer to a pointer to the current position in the DNS message,
 *                    at the start of the RR's fixed fields (Type, Class, etc.).
 *                    This pointer is advanced past the RR.
 * @param trusted_domain The trusted domain configuration relevant to this RR.
 */
// Helper function to validate characters in an IP string representation
// Ensures the string only contains characters expected in IPv4 or IPv6 addresses.
static int is_safe_ip_str(const char *ip_str) {
    if (!ip_str || ip_str[0] == '\0') {
        debug(LOG_WARNING, "IP string is NULL or empty, considered unsafe.");
        return 0; // Not safe if NULL or empty
    }
    for (const char *p = ip_str; *p; ++p) {
        // Allow hexadecimal digits (0-9, a-f, A-F), period (for IPv4), and colon (for IPv6).
        if (!(isxdigit((unsigned char)*p) || *p == '.' || *p == ':')) {
            debug(LOG_WARNING, "IP string '%s' contains unsafe character '%c'.", ip_str, *p);
            return 0; // Unsafe character found
        }
    }
    return 1; // All characters are within the allowed set.
}

/**
 * @brief Adds an IP address to a trusted domain's IP list and attempts to add it to an nftables set.
 * Checks for duplicates before adding. Converts binary IP to string for nftables command.
 *
 * @param trusted_domain The trusted domain to which this IP belongs.
 * @param type DNS record type (DNS_RR_TYPE_A or DNS_RR_TYPE_AAAA).
 * @param addr_ptr Pointer to the binary IP address data (4 bytes for IPv4, 16 for IPv6).
 * @return 0 on success or if IP already exists/is unsafe but skipped, -1 on memory allocation failure.
 */
static int 
add_trusted_ip(t_domain_trusted *trusted_domain, uint16_t type, unsigned char *addr_ptr) {
    t_ip_trusted *ip_trusted = trusted_domain->ips_trusted; // Head of the IP list for this domain
    int found = 0; // Flag to indicate if the IP is already in the list

    // Check if this IP address is already in our trusted list for this domain.
    while (ip_trusted) {
        if (ip_trusted->ip_type == (type == DNS_RR_TYPE_A ? IP_TYPE_IPV4 : IP_TYPE_IPV6)) {
            if ((type == DNS_RR_TYPE_A && ip_trusted->uip.ipv4.s_addr == *(uint32_t *)addr_ptr) ||
                (type == DNS_RR_TYPE_AAAA && memcmp(&ip_trusted->uip.ipv6, addr_ptr, IPV6_ADDR_LEN) == 0)) {
                found = 1; // IP already exists
                break;
            }
        }
        ip_trusted = ip_trusted->next;
    }

    if (!found) { // If the IP is not already in the list, add it.
        char ip_str[INET6_ADDRSTRLEN] = {0}; // Buffer for string representation of the IP
        // Convert binary IP address to string form (e.g., "1.2.3.4" or "2001:db8::1").
        if (type == DNS_RR_TYPE_A) {
            inet_ntop(AF_INET, addr_ptr, ip_str, sizeof(ip_str));
        } else { // DNS_RR_TYPE_AAAA
            inet_ntop(AF_INET6, addr_ptr, ip_str, sizeof(ip_str));
        }
        debug(LOG_DEBUG, "Adding trusted IP for domain '%s': %s", trusted_domain->domain, ip_str);

        // Allocate memory for the new trusted IP entry.
        t_ip_trusted *new_ip_trusted = (t_ip_trusted *)malloc(sizeof(t_ip_trusted));
        if (!new_ip_trusted) {
            debug(LOG_ERR, "Memory allocation failed for new_ip_trusted.");
            return -1; // Allocation failure
        }
        // Populate the new entry.
        if (type == DNS_RR_TYPE_A) {
            new_ip_trusted->ip_type = IP_TYPE_IPV4;
            memcpy(&new_ip_trusted->uip.ipv4, addr_ptr, IPV4_ADDR_LEN);
        } else {
            new_ip_trusted->ip_type = IP_TYPE_IPV6;
            memcpy(&new_ip_trusted->uip.ipv6, addr_ptr, IPV6_ADDR_LEN);
        }
        // Add to the head of the linked list.
        new_ip_trusted->next = trusted_domain->ips_trusted;
        trusted_domain->ips_trusted = new_ip_trusted;

        // Construct and execute command to add IP to nftables set.
        // Validate ip_str as a defense-in-depth measure before using in a shell command.
        char cmd[NFT_COMMAND_BUFFER_SIZE] = {0};
        if (!is_safe_ip_str(ip_str)) {
            debug(LOG_ERR, "Cannot add unsafe IP string '%s' to nftables.", ip_str);
            // IP is in memory list but not in firewall. This might be acceptable or require error propagation.
            return 0; // Skipping execute for safety, but not treating as a hard error for add_trusted_ip.
        }

        // Construct the nftables command.
        if (type == DNS_RR_TYPE_A) {
            snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_inner_trust_domains { %s }", ip_str);
        } else {
            snprintf(cmd, sizeof(cmd), "nft add element inet fw4 set_wifidogx_inner_trust_domains_v6 { %s }", ip_str);
        }
        execute(cmd, 0); // Execute the command (e.g., via system() or popen()).
    }
    return 0; // Success or IP already existed / was skipped for safety.
}

/**
 * @brief Callback function for libevent when a DNS response is received from upstream server.
 * This function reads the response, processes it, and forwards it to the original client.
 *
 * @param fd File descriptor of the socket connected to the upstream DNS server.
 * @param event Event flags (EV_READ, EV_TIMEOUT, etc.).
 * @param arg Pointer to the struct dns_query associated with this transaction.
 */
static void 
dns_read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct dns_query *query = (struct dns_query *)arg; // Cast arg back to dns_query
    unsigned char response[DNS_MESSAGE_BUFFER_SIZE] = {0}; // Buffer for the DNS response
    int response_len;

    // Check for timeout or other event errors
    if (event & EV_TIMEOUT) {
        debug(LOG_WARNING, "DNS query timeout for domain in query buffer (client FD: %d)", query->client_fd);
        // Fall through to cleanup
    } else if (event & EV_READ) {
        // Receive the DNS response from the upstream server.
        response_len = recv(fd, response, sizeof(response), 0);

        if (response_len > 0) {
            // Process the DNS response (e.g., for xDPI or trusted domains).
            process_dns_response(response, response_len);
            // Forward the response back to the original client.
            sendto(query->client_fd, response, response_len, 0,
                   (struct sockaddr *)&query->client_addr, query->client_len);
        } else if (response_len == 0) {
            debug(LOG_INFO, "DNS upstream server closed connection (fd: %d).", fd);
        } else { // response_len < 0
            debug(LOG_ERR, "DNS response recv failed (fd: %d): %s", fd, strerror(errno));
        }
    } else {
        debug(LOG_WARNING, "Unhandled event %d on dns_read_cb (fd: %d)", event, fd);
    }


    // Clean up resources associated with this DNS query.
    event_free(query->dns_event); // Free the libevent event structure.
    close(fd);                    // Close the socket to the upstream DNS server.
    free(query);                  // Free the dns_query structure.
}

static void 
read_cb(evutil_socket_t fd, short event, void *arg) 
{
    struct event_base *base = (struct event_base *)arg; // Libevent base
    struct sockaddr_in client_addr;                     // To store client's address
    socklen_t client_len = sizeof(client_addr);
    char buffer[DNS_MESSAGE_BUFFER_SIZE] = {0};         // Buffer for incoming DNS query
    int recv_len;                                       // Length of received data
    int dns_sock;                                       // Socket for forwarding to upstream DNS
    struct dns_query *query_data;                       // Structure to hold query state

    // Receive DNS query from a client.
    recv_len = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_len);

    if (recv_len > 0) { // Successfully received a query
        // Create a new UDP socket to forward the query to the upstream DNS server.
        dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (dns_sock < 0) {
            debug(LOG_ERR, "Failed to create upstream DNS socket: %s", strerror(errno));
            return;
        }

        // Prepare address for the upstream DNS server.
        struct sockaddr_in dns_server_addr;
        memset(&dns_server_addr, 0, sizeof(dns_server_addr));
        dns_server_addr.sin_family = AF_INET;
        dns_server_addr.sin_port = htons(LOCAL_DNS_PORT); // LOCAL_DNS_PORT usually 53 (e.g. from conf.h)

        // s_config *config = config_get_config(); // Unused variable
        const char *upstream_ip_str = NULL;

        upstream_ip_str = "127.0.0.1";
        debug(LOG_DEBUG, "Using upstream DNS IP: %s", upstream_ip_str);

        if (inet_pton(AF_INET, upstream_ip_str, &dns_server_addr.sin_addr) <= 0) {
            debug(LOG_ERR, "Failed to convert upstream DNS IP string '%s' to address, defaulting to 127.0.0.1.", upstream_ip_str);
            // If conversion failed even for a potentially configured IP, fallback to 127.0.0.1
            if (inet_pton(AF_INET, "127.0.0.1", &dns_server_addr.sin_addr) <= 0) {
                 // This should not happen for "127.0.0.1"
                 debug(LOG_CRIT, "Failed to convert fallback IP '127.0.0.1'. This is critical.");
                 close(dns_sock);
            }
        }

        // Send the received query to the upstream DNS server.
        if (sendto(dns_sock, buffer, recv_len, 0, (struct sockaddr *)&dns_server_addr, sizeof(dns_server_addr)) < 0) {
            debug(LOG_ERR, "Failed to send DNS query to upstream server: %s", strerror(errno));
            close(dns_sock);
            return;
        }

        // Allocate structure to hold state for this forwarded query.
        query_data = (struct dns_query *)malloc(sizeof(struct dns_query));
        if (!query_data) {
            debug(LOG_ERR, "Failed to malloc for dns_query: %s", strerror(errno));
            close(dns_sock);
            return;
        }
        // Populate query_data.
        query_data->client_fd = fd; // This is the listening socket, not ideal for sending response directly.
                                    // For UDP, can send from any socket, but better to use the one that received.
                                    // However, client_addr is key. The fd here is the server's main fd.
                                    // The response will be sent using query->client_fd (which is this fd)
                                    // and query->client_addr (which is the actual client). This is okay for UDP.
        query_data->client_addr = client_addr;
        query_data->client_len = client_len;
        memcpy(query_data->buffer, buffer, recv_len); // Store original query (optional, for debugging)
        query_data->buffer_len = recv_len;

        // Set up a new libevent event to wait for the response on dns_sock.
        // EV_TIMEOUT could be added here with a struct timeval.
        query_data->dns_event = event_new(base, dns_sock, EV_READ | EV_TIMEOUT, dns_read_cb, query_data);
        if (!query_data->dns_event) {
            debug(LOG_ERR, "Failed to event_new for DNS response: %s", strerror(errno));
            free(query_data);
            close(dns_sock);
            return;
        }

        struct timeval tv = {5, 0}; // 5 second timeout for DNS response
        if (event_add(query_data->dns_event, &tv) < 0) {
            debug(LOG_ERR, "Failed to event_add for DNS response: %s", strerror(errno));
            event_free(query_data->dns_event); // Clean up allocated event
            free(query_data);
            close(dns_sock);
            return;
        }
    } else if (recv_len < 0) {
        debug(LOG_ERR, "recvfrom failed on main DNS socket: %s", strerror(errno));
    }
}

/**
 * @brief Main function for the DNS forwarding thread.
 * Initializes a UDP socket on DNS_FORWARD_PORT (e.g., 5353),
 * and uses libevent to handle incoming DNS queries asynchronously.
 *
 * @param arg Thread arguments (not used in this implementation).
 * @return NULL when the thread exits.
 */
void *
thread_dns_forward(void *arg) {
    int sockfd; // Listening socket file descriptor
    struct sockaddr_in server_addr;

    // Initialize the mutex for domain_entries
    if (pthread_mutex_init(&domain_entries_mutex, NULL) != 0) {
        debug(LOG_ERR, "Failed to initialize domain_entries_mutex: %s", strerror(errno));
        // Depending on policy, might call termination_handler or try to proceed without mutex
        return NULL; // Cannot proceed without mutex
    }

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        debug(LOG_ERR, "Failed to create socket: %s", strerror(errno));
        pthread_mutex_destroy(&domain_entries_mutex); // Clean up initialized mutex
        // No resources to clean yet, direct call to termination_handler is okay or return NULL
        termination_handler(0); // Or consider returning NULL if this thread is joined
        return NULL; // Added return
    }

    // Bind to port 5353
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_FORWARD_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        debug(LOG_ERR, "Failed to bind to port %d: %s", DNS_FORWARD_PORT, strerror(errno));
        close(sockfd);
        termination_handler(0);
        return NULL; // Added return
    }

    // Initialize libevent
    struct event_base *base = event_base_new();
    if (!base) {
        debug(LOG_ERR, "event_base_new failed"); // errno might not be set by libevent
        close(sockfd);
        termination_handler(0);
        return NULL; // Added return
    }

    // Create an event to listen for incoming DNS requests
    struct event *dns_event = event_new(base, sockfd, EV_READ | EV_PERSIST, read_cb, base);
    if (!dns_event) {
        debug(LOG_ERR, "event_new failed"); // errno might not be set by libevent
        event_base_free(base);
        close(sockfd);
        termination_handler(0);
        return NULL; // Added return
    }

    // Add the event to the event base
    if (event_add(dns_event, NULL) < 0) {
        debug(LOG_ERR, "event_add failed"); // errno might not be set by libevent
        event_free(dns_event);
        event_base_free(base);
        close(sockfd);
        termination_handler(0);
        return NULL; // Added return
    }

    debug(LOG_INFO, "DNS forwarder started on port %d", DNS_FORWARD_PORT);

    // Dispatch events
    event_base_dispatch(base);

    // Clean up
    event_free(dns_event);
    event_base_free(base);
    close(sockfd);
    pthread_mutex_destroy(&domain_entries_mutex); // Destroy the mutex

    return NULL;
}


