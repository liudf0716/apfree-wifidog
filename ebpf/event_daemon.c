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
#include "aw-bpf.h" // Include aw-bpf.h for session_data_t definition

static volatile sig_atomic_t exiting = 0;

static int handle_event(void *ctx, void *data, size_t len) {
    struct session_data_t *e = data;

    // Validate data length
    if (len < sizeof(struct session_data_t)) {
        syslog(LOG_WARNING, "Received incomplete session data: expected %zu bytes, got %zu bytes", 
               sizeof(struct session_data_t), len);
        return -1;
    }

    char s_ip[INET6_ADDRSTRLEN], d_ip[INET6_ADDRSTRLEN];
    
    if (e->ip_version == 4) {
        // Handle IPv4
        if (inet_ntop(AF_INET, &e->addrs.v4.saddr_v4, s_ip, sizeof(s_ip)) == NULL ||
            inet_ntop(AF_INET, &e->addrs.v4.daddr_v4, d_ip, sizeof(d_ip)) == NULL) {
            syslog(LOG_WARNING, "Failed to convert IPv4 addresses to string");
            return -1;
        }
        syslog(LOG_INFO, "New session [SID:%u] IPv4: %s:%d -> %s:%d",
               e->sid, s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));
    } else if (e->ip_version == 6) {
        // Handle IPv6
        if (inet_ntop(AF_INET6, e->addrs.v6.saddr_v6, s_ip, sizeof(s_ip)) == NULL ||
            inet_ntop(AF_INET6, e->addrs.v6.daddr_v6, d_ip, sizeof(d_ip)) == NULL) {
            syslog(LOG_WARNING, "Failed to convert IPv6 addresses to string");
            return -1;
        }
        syslog(LOG_INFO, "New session [SID:%u] IPv6: %s:%d -> %s:%d",
               e->sid, s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));
    } else {
        syslog(LOG_WARNING, "Unknown IP version: %d for session SID:%u", e->ip_version, e->sid);
        return -1;
    }

    return 0;
}

static void sigint_handler(int sig) {
    exiting = 1;
}

int main() {
    struct ring_buffer *rb = NULL;
    int map_fd;
    pid_t pid;

    // Open syslog before forking to catch early errors, or after fork in child for correct PID.
    // For now, keeping it here. The PID logged will be the parent's if it's here.
    // Alternatively, move openlog() after the fork in the child process.
    openlog("event-daemon", LOG_PID | LOG_CONS, LOG_DAEMON); // Changed ident slightly

    // Fork off the parent process
    pid = fork();
    if (pid < 0) {
        syslog(LOG_ERR, "Failed to fork: %m"); // %m adds strerror(errno)
        exit(EXIT_FAILURE);
    }
    // If we got a good PID, then we can exit the parent process.
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    // Change the file mode mask
    umask(0); // Clear file mode creation mask

    // Create a new SID for the child process
    if (setsid() < 0) {
        syslog(LOG_ERR, "Failed to create new session: %m");
        exit(EXIT_FAILURE);
    }

    // Change the current working directory
    if ((chdir("/")) < 0) {
        syslog(LOG_ERR, "Failed to change directory to /: %m");
        exit(EXIT_FAILURE);
    }

    // Close out the standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Redirect standard file descriptors to /dev/null
    // Note: Some daemons open them to /dev/null explicitly.
    // Here, we are just closing them. For robust redirection:
    int fd0 = open("/dev/null", O_RDWR); // stdin
    int fd1 = open("/dev/null", O_RDWR); // stdout
    int fd2 = open("/dev/null", O_RDWR); // stderr
    if (fd0 == -1 || fd1 == -1 || fd2 == -1) {
         syslog(LOG_ERR, "Failed to open /dev/null for standard FDs: %m");
         // Not exiting here, as syslog might still work if it was opened before redirection.
    }


    // Signal handling
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    syslog(LOG_INFO, "Daemon started. PID: %d", getpid());

    // Try to find the pinned ring buffer map from already loaded aw-bpf program
    // The map should be pinned at /sys/fs/bpf/session_events_map if aw-bpf is loaded
    map_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/session_events_map");
    if (map_fd < 0) {
        syslog(LOG_ERR, "Failed to find pinned session_events_map. Is aw-bpf program loaded? Error: %s", strerror(errno));
        syslog(LOG_ERR, "Please load aw-bpf.o first using tc command:");
        syslog(LOG_ERR, "  tc qdisc add dev <interface> clsact");
        syslog(LOG_ERR, "  tc filter add dev <interface> ingress bpf da obj aw-bpf.o sec tc/ingress");
        syslog(LOG_ERR, "  tc filter add dev <interface> egress bpf da obj aw-bpf.o sec tc/egress");
        goto cleanup_syslog;
    }

    // Create ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        syslog(LOG_ERR, "Failed to create ring buffer: %s", strerror(errno)); // strerror for libbpf_get_error is not direct
        close(map_fd);
        goto cleanup_syslog;
    }

    syslog(LOG_INFO, "Listening for new session events from aw-bpf.o...");
    syslog(LOG_INFO, "Note: You need to manually attach the TC program using tc command");
    syslog(LOG_INFO, "Example: tc qdisc add dev eth0 clsact");
    syslog(LOG_INFO, "         tc filter add dev eth0 ingress bpf da obj ../ebpf/aw-bpf.o sec tc/ingress");
    syslog(LOG_INFO, "         tc filter add dev eth0 egress bpf da obj ../ebpf/aw-bpf.o sec tc/egress");

    while (!exiting) {
        // Poll with a timeout. ring_buffer__poll returns number of records consumed or negative on error.
        int ret = ring_buffer__poll(rb, 100); // 100 ms timeout
        if (ret < 0) {
            if (ret == -EINTR) {
                // Interrupted by signal, this is expected
                syslog(LOG_DEBUG, "Ring buffer polling interrupted by signal");
                continue;
            } else {
                syslog(LOG_ERR, "Error polling ring buffer: %s", strerror(-ret));
                // Depending on the error, you might want to break or continue
                break;
            }
        } else if (ret > 0) {
            // Successfully processed events
            syslog(LOG_DEBUG, "Processed %d events from ring buffer", ret);
        }
        // ret == 0 means timeout, no events, continue polling
    }

    ring_buffer__free(rb);
    if (map_fd >= 0) {
        close(map_fd);
    }
cleanup_syslog: // New label for cleanup before closelog
    syslog(LOG_INFO, "Exiting daemon. PID: %d", getpid());
    closelog();
    return 0; // Should be EXIT_SUCCESS or EXIT_FAILURE based on outcome
}
