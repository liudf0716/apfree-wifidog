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

static volatile sig_atomic_t exiting = 0;

struct conn_event_t {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
};

static int handle_event(void *ctx, void *data, size_t len) {
    struct conn_event_t *e = data;

    char s_ip[INET_ADDRSTRLEN], d_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->saddr, s_ip, sizeof(s_ip));
    inet_ntop(AF_INET, &e->daddr, d_ip, sizeof(d_ip));

    syslog(LOG_INFO, "New TCP connection: %s:%d -> %s:%d",
           s_ip, ntohs(e->sport), d_ip, ntohs(e->dport));

    return 0;
}

static void sigint_handler(int sig) {
    exiting = 1;
}

int main() {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, map_fd;
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


    // Load BPF object from file
    obj = bpf_object__open("aw-bpf.o");
    if (libbpf_get_error(obj)) {
        syslog(LOG_ERR, "Failed to open BPF object aw-bpf.o: %s", strerror(errno)); // strerror for libbpf_get_error is not direct
        goto cleanup_syslog; // Changed goto to ensure closelog is called
    }

    // Load BPF object into kernel
    if (bpf_object__load(obj)) {
        syslog(LOG_ERR, "Failed to load BPF object: %s", strerror(errno)); // strerror for libbpf_get_error is not direct
        goto cleanup_obj;
    }

    // Find the BPF program
    prog = bpf_object__find_program_by_name(obj, "handle_tc");
    if (!prog) {
        syslog(LOG_ERR, "Failed to find BPF program 'handle_tc'");
        goto cleanup_obj;
    }

    prog_fd = bpf_program__fd(prog);

    // Find the ring buffer map
    map = bpf_object__find_map_by_name(obj, "conn_events");
    if (!map) {
        syslog(LOG_ERR, "Failed to find BPF map 'conn_events'");
        goto cleanup_obj;
    }

    map_fd = bpf_map__fd(map);

    // Create ring buffer
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        syslog(LOG_ERR, "Failed to create ring buffer: %s", strerror(errno)); // strerror for libbpf_get_error is not direct
        goto cleanup_obj;
    }

    syslog(LOG_INFO, "Listening for new connections from aw-bpf.o...");
    syslog(LOG_INFO, "Note: You need to manually attach the TC program using tc command");
    syslog(LOG_INFO, "Example: tc qdisc add dev eth0 clsact && tc filter add dev eth0 ingress bpf da obj aw-bpf.o sec tc");

    while (!exiting) {
        // Poll with a timeout. ring_buffer__poll returns number of records consumed or negative on error.
        int ret = ring_buffer__poll(rb, 100); // 100 ms timeout
        if (ret < 0 && ret != -EINTR) { // EINTR is expected on signal
            syslog(LOG_ERR, "Error polling ring buffer: %s", strerror(-ret));
            // Depending on the error, you might want to break or continue
        }
    }

cleanup_obj:
    ring_buffer__free(rb);
    bpf_object__close(obj);
cleanup_syslog: // New label for cleanup before closelog
    syslog(LOG_INFO, "Exiting daemon. PID: %d", getpid());
    closelog();
    return 0; // Should be EXIT_SUCCESS or EXIT_FAILURE based on outcome
}
