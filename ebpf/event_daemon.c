#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/types.h>
#include <sys/stat.h> // Added for S_IRUSR, S_IWUSR etc. and umask
#include <fcntl.h>   // Added for O_RDWR, O_CREAT etc.
#include <errno.h>   // Added for errno and EINTR
#include <string.h>  // Added for string operations
#include <ifaddrs.h> // Added for getifaddrs
#include <net/if.h>  // Added for interface operations
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <time.h>    // Added for time operations
#include <uci.h>     // Added for UCI operations
#include "aw-bpf.h" // Include aw-bpf.h for session_data_t definition

static volatile sig_atomic_t exiting = 0;
static char location_id[15] = "UNKNOWN"; // Global variable to store location_id (14 bytes + null terminator)
static char ap_device_id[32] = "UNKNOWN"; // Global variable to store ap_device_id
static char ap_mac_address[18] = "UNKNOWN"; // Global variable to store ap_mac_address
static char ap_longitude[16] = "0.000000"; // Global variable to store ap_longitude
static char ap_latitude[16] = "0.000000"; // Global variable to store ap_latitude

/**
 * @brief Get current timestamp (seconds since 1970-01-01 00:00:00 UTC, adjusted by system timezone)
 * @return Current timestamp in seconds
 */
static time_t get_current_timestamp(void) {
    // time(NULL) returns the current time as seconds since 1970-01-01 00:00:00 UTC
    // If system timezone is set to Beijing time (UTC+8), this will be Beijing time
    return time(NULL);
}

/**
 * @brief Normalize MAC address by removing separators and converting to lowercase
 * @param mac_with_separators MAC address with separators (e.g., "AA-BB-CC-11-22-33")
 * @param normalized_mac Output buffer for normalized MAC (must be at least 13 bytes)
 * @return 0 on success, -1 on failure
 */
static int normalize_mac(const char *mac_with_separators, char *normalized_mac) {
    int i, j = 0;
    
    if (strcmp(mac_with_separators, "UNKNOWN") == 0) {
        strcpy(normalized_mac, "unknown");
        return 0;
    }
    
    for (i = 0; mac_with_separators[i] != '\0' && j < 12; i++) {
        if (mac_with_separators[i] != '-' && mac_with_separators[i] != ':') {
            // Convert to lowercase
            if (mac_with_separators[i] >= 'A' && mac_with_separators[i] <= 'F') {
                normalized_mac[j] = mac_with_separators[i] - 'A' + 'a';
            } else {
                normalized_mac[j] = mac_with_separators[i];
            }
            j++;
        }
    }
    
    if (j == 12) {
        normalized_mac[12] = '\0';
        return 0;
    }
    
    return -1;
}

/**
 * @brief Parse configuration from wifidogx config file using UCI
 * @return 0 on success, -1 on failure
 */
static int parse_wifidogx_config(void) {
    struct uci_context *ctx;
    struct uci_package *pkg;
    struct uci_element *e;
    struct uci_section *s;
    struct uci_option *o;
    const char *value;
    int ret = -1;

    ctx = uci_alloc_context();
    if (!ctx) {
        syslog(LOG_ERR, "Failed to allocate UCI context");
        return -1;
    }

    if (uci_load(ctx, "wifidogx", &pkg) != UCI_OK) {
        syslog(LOG_ERR, "Failed to load wifidogx config");
        goto cleanup;
    }

    // Find the 'common' section
    uci_foreach_element(&pkg->sections, e) {
        s = uci_to_section(e);
        if (strcmp(s->type, "wifidogx") == 0 && strcmp(s->e.name, "common") == 0) {
            
            // Parse location_id
            o = uci_lookup_option(ctx, s, "location_id");
            if (o && o->type == UCI_TYPE_STRING) {
                value = o->v.string;
                if (value && strlen(value) < sizeof(location_id)) {
                    strncpy(location_id, value, sizeof(location_id) - 1);
                    location_id[sizeof(location_id) - 1] = '\0';
                    syslog(LOG_DEBUG, "Parsed location_id: %s", location_id);
                }
            }

            // Parse ap_device_id
            o = uci_lookup_option(ctx, s, "ap_device_id");
            if (o && o->type == UCI_TYPE_STRING) {
                value = o->v.string;
                if (value && strlen(value) < sizeof(ap_device_id)) {
                    strncpy(ap_device_id, value, sizeof(ap_device_id) - 1);
                    ap_device_id[sizeof(ap_device_id) - 1] = '\0';
                    syslog(LOG_DEBUG, "Parsed ap_device_id: %s", ap_device_id);
                }
            }

            // Parse ap_mac_address
            o = uci_lookup_option(ctx, s, "ap_mac_address");
            if (o && o->type == UCI_TYPE_STRING) {
                value = o->v.string;
                if (value && strlen(value) < sizeof(ap_mac_address)) {
                    strncpy(ap_mac_address, value, sizeof(ap_mac_address) - 1);
                    ap_mac_address[sizeof(ap_mac_address) - 1] = '\0';
                    syslog(LOG_DEBUG, "Parsed ap_mac_address: %s", ap_mac_address);
                }
            }

            // Parse ap_longitude
            o = uci_lookup_option(ctx, s, "ap_longitude");
            if (o && o->type == UCI_TYPE_STRING) {
                value = o->v.string;
                if (value && strlen(value) < sizeof(ap_longitude)) {
                    strncpy(ap_longitude, value, sizeof(ap_longitude) - 1);
                    ap_longitude[sizeof(ap_longitude) - 1] = '\0';
                    syslog(LOG_DEBUG, "Parsed ap_longitude: %s", ap_longitude);
                }
            }

            // Parse ap_latitude
            o = uci_lookup_option(ctx, s, "ap_latitude");
            if (o && o->type == UCI_TYPE_STRING) {
                value = o->v.string;
                if (value && strlen(value) < sizeof(ap_latitude)) {
                    strncpy(ap_latitude, value, sizeof(ap_latitude) - 1);
                    ap_latitude[sizeof(ap_latitude) - 1] = '\0';
                    syslog(LOG_DEBUG, "Parsed ap_latitude: %s", ap_latitude);
                }
            }

            ret = 0;
            break;
        }
    }

    if (ret != 0) {
        syslog(LOG_WARNING, "wifidogx 'common' section not found in config");
    }

cleanup:
    uci_unload(ctx, pkg);
    uci_free_context(ctx);
    return ret;
}

/**
 * @brief Get MAC address for given IP address from ARP table
 * @param ip_addr IPv4 address in network byte order
 * @param mac_str Output buffer for MAC address string (must be at least 18 bytes)
 * @return 0 on success, -1 on failure
 */
static int get_mac_from_arp(uint32_t ip_addr, char *mac_str) {
    FILE *arp_file;
    char line[256];
    char ip_str[16];
    char hw_addr[18];
    char flags[16];
    char hw_type[16];
    char mask[16];
    char device[16];
    uint32_t parsed_ip;
    
    // Convert IP to string for comparison
    struct in_addr addr;
    addr.s_addr = htonl(ip_addr);
    if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str)) == NULL) {
        return -1;
    }
    
    arp_file = fopen("/proc/net/arp", "r");
    if (arp_file == NULL) {
        return -1;
    }
    
    // Skip header line
    if (fgets(line, sizeof(line), arp_file) == NULL) {
        fclose(arp_file);
        return -1;
    }
    
    // Parse ARP entries
    while (fgets(line, sizeof(line), arp_file) != NULL) {
        if (sscanf(line, "%s %s %s %s %s %s", 
                   ip_str, hw_type, flags, hw_addr, mask, device) == 6) {
            
            if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                parsed_ip = ntohl(addr.s_addr);
                if (parsed_ip == ip_addr && strcmp(hw_addr, "00:00:00:00:00:00") != 0) {
                    // Convert MAC format from aa:bb:cc:dd:ee:ff to AA-BB-CC-DD-EE-FF
                    int i, j;
                    for (i = 0, j = 0; i < 17 && j < 17; i++, j++) {
                        if (hw_addr[i] == ':') {
                            mac_str[j] = '-';
                        } else if (hw_addr[i] >= 'a' && hw_addr[i] <= 'f') {
                            mac_str[j] = hw_addr[i] - 'a' + 'A';
                        } else {
                            mac_str[j] = hw_addr[i];
                        }
                    }
                    mac_str[17] = '\0';
                    fclose(arp_file);
                    return 0;
                }
            }
        }
    }
    
    fclose(arp_file);
    return -1;
}

static int handle_event(void *ctx, void *data, size_t len) {
    struct session_data_t *e = data;

    // Validate data length
    if (len < sizeof(struct session_data_t)) {
        return -1;
    }

    const char *proto_str = (e->proto == IPPROTO_TCP) ? "TCP" : 
                           (e->proto == IPPROTO_UDP) ? "UDP" : "UNKNOWN";
    
    // Get current timestamp (system timezone dependent)
    time_t current_timestamp = get_current_timestamp();
    
    if (e->ip_version == 4) {
        // Handle IPv4 - use raw uint32 values
        uint32_t src_ip = ntohl(e->addrs.v4.saddr_v4);
        uint32_t dst_ip = ntohl(e->addrs.v4.daddr_v4);
        
        // Get MAC address for source IP
        char src_mac[18] = "00-00-00-00-00-00"; // Default value
        if (get_mac_from_arp(src_ip, src_mac) != 0) {
            strcpy(src_mac, "UNKNOWN");
        }
        
        // Skip logging if MAC address is unknown
        if (strcmp(src_mac, "UNKNOWN") == 0) {
            return 0;
        }
        
        // Generate session ID: location_id + normalized_mac + timestamp
        char normalized_mac[13];
        char session_id[64]; // location_id(14) + normalized_mac(12) + timestamp(10) + null
        if (normalize_mac(src_mac, normalized_mac) == 0) {
            snprintf(session_id, sizeof(session_id), "%s%s%ld", location_id, normalized_mac, current_timestamp);
        } else {
            // This should not happen since we already checked for UNKNOWN above
            return 0;
        }
        
        syslog(LOG_INFO, "{\"location_id\":\"%s\",\"timestamp\":%ld,\"session_id\":\"%s\",\"sid\":%u,\"protocol\":\"%s\",\"ip_version\":4,\"src_ip\":%u,\"src_port\":%d,\"dst_ip\":%u,\"dst_port\":%d,\"clt_mac\":\"%s\",\"ap_device_id\":\"%s\",\"ap_mac_address\":\"%s\",\"ap_longitude\":\"%s\",\"ap_latitude\":\"%s\"}",
               location_id, current_timestamp, session_id, e->sid, proto_str, src_ip, ntohs(e->sport), dst_ip, ntohs(e->dport), src_mac, ap_device_id, ap_mac_address, ap_longitude, ap_latitude);
    } else if (e->ip_version == 6) {
        // Handle IPv6 - skip logging since MAC is always unknown for IPv6
        return 0;
    } else {
        return -1;
    }

    return 0;
}

static void sigint_handler(int sig) {
    exiting = 1;
}

#define PID_FILE "/var/run/event_daemon.pid"

/**
 * @brief Check if another instance of event_daemon is already running using pid file
 * @return 1 if another instance is running, 0 if not, -1 on error
 */
static int check_existing_process(void) {
    FILE *pid_file;
    pid_t existing_pid;
    char proc_path[64];
    
    // Try to open existing pid file
    pid_file = fopen(PID_FILE, "r");
    if (pid_file == NULL) {
        // No pid file exists, so no instance is running
        return 0;
    }
    
    // Read the PID from the file
    if (fscanf(pid_file, "%d", &existing_pid) != 1) {
        fclose(pid_file);
        // Invalid pid file, remove it
        unlink(PID_FILE);
        return 0;
    }
    fclose(pid_file);
    
    // Check if the process with this PID actually exists
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", existing_pid);
    if (access(proc_path, F_OK) == 0) {
        // Process exists
        fprintf(stderr, "Another event_daemon process (PID: %d) is already running\n", existing_pid);
        return 1;
    } else {
        // Process doesn't exist, remove stale pid file
        unlink(PID_FILE);
        return 0;
    }
}

/**
 * @brief Create pid file for current process
 * @return 0 on success, -1 on error
 */
static int create_pid_file(void) {
    FILE *pid_file;
    
    pid_file = fopen(PID_FILE, "w");
    if (pid_file == NULL) {
        fprintf(stderr, "Failed to create pid file %s: %s\n", PID_FILE, strerror(errno));
        return -1;
    }
    
    fprintf(pid_file, "%d\n", getpid());
    fclose(pid_file);
    
    return 0;
}

/**
 * @brief Remove pid file
 */
static void remove_pid_file(void) {
    unlink(PID_FILE);
}

int main() {
    struct ring_buffer *rb = NULL;
    int map_fd;
    
    // Check if another instance is already running
    int check_result = check_existing_process();
    if (check_result == 1) {
        fprintf(stderr, "Exiting: Another event_daemon instance is already running\n");
        exit(EXIT_FAILURE);
    } else if (check_result == -1) {
        fprintf(stderr, "Warning: Failed to check for existing processes\n");
    }

    // Create pid file
    if (create_pid_file() != 0) {
        fprintf(stderr, "Failed to create pid file, continuing anyway...\n");
    }

    // Initialize logging (no longer daemonized, so we can use both stderr and syslog)
    openlog("event-daemon", LOG_PID | LOG_CONS | LOG_PERROR, LOG_DAEMON);
    
    printf("Starting event_daemon (PID: %d)\n", getpid());
    syslog(LOG_INFO, "Starting event_daemon (PID: %d)", getpid());


    // Signal handling
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    // Parse configuration from UCI
    if (parse_wifidogx_config() != 0) {
        fprintf(stderr, "Warning: Failed to parse wifidogx config, using defaults\n");
        syslog(LOG_WARNING, "Failed to parse wifidogx config, using defaults");
    }

    // Try to find the pinned ring buffer map from already loaded aw-bpf program
    // The map should be pinned at /sys/fs/bpf/session_events_map if aw-bpf is loaded
    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/session_events_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to get BPF map: %s\n", strerror(errno));
        syslog(LOG_ERR, "Failed to get BPF map: %s", strerror(errno));
        goto cleanup_syslog;
    }

    // Create ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        syslog(LOG_ERR, "Failed to create ring buffer");
        close(map_fd);
        goto cleanup_syslog;
    }

    printf("Event daemon started successfully, monitoring events...\n");
    syslog(LOG_INFO, "Event daemon started successfully, monitoring events");

    while (!exiting) {
        // Poll with a timeout. ring_buffer__poll returns number of records consumed or negative on error.
        int ret = ring_buffer__poll(rb, 100); // 100 ms timeout
        if (ret < 0) {
            if (ret == -EINTR) {
                // Interrupted by signal, this is expected
                continue;
            } else {
                fprintf(stderr, "Error polling ring buffer: %d\n", ret);
                syslog(LOG_ERR, "Error polling ring buffer: %d", ret);
                break;
            }
        }
        // ret == 0 means timeout, no events, continue polling
        // ret > 0 means successfully processed events
    }

    printf("Event daemon shutting down...\n");
    syslog(LOG_INFO, "Event daemon shutting down");

    ring_buffer__free(rb);
    if (map_fd >= 0) {
        close(map_fd);
    }
    
    // Clean up pid file
    remove_pid_file();
    
cleanup_syslog:
    closelog();
    return 0;
}
