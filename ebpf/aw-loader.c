#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    int err;

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load the BPF object file
    obj = bpf_object__open_file("aw-bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object file\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "tc_ingress");
    if (!prog) {
        fprintf(stderr, "Error finding BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

    // Load the BPF program into the kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF program loaded successfully\n");

    // Keep the program running until signal is received
    while (running) {
        sleep(1);
    }

    // Cleanup
    bpf_object__close(obj);
    return 0;
}