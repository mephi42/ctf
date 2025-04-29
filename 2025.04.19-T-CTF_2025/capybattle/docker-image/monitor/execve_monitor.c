#include <bpf/libbpf.h>           // for bpf_map__fd, ring_buffer__new, ring...
#include <errno.h>                // for EINTR
#include <signal.h>               // for signal, SIGINT, SIGTERM, size_t
#include <stdbool.h>              // for bool, false, true
#include <stdio.h>                // for fprintf, stderr, NULL
#include <stdlib.h>               // for exit, EXIT_FAILURE
#include <string.h>               // for memcpy
#include "execve_monitor.skel.h"  // for execve_monitor_bpf__attach, execve_...

static volatile bool running = true;

#define MAX_ENV_VARS 128
#define MAX_STRINGS_SIZE (1 << 13)

struct event {
    int env_offsets[MAX_ENV_VARS];
    char strings[MAX_STRINGS_SIZE];
};

static int handle_event(void *ctx __attribute__((unused)),
                        void *data, size_t data_sz)
{
    struct event e;
    int i;

    // Cast ring buffer data to struct event
    memcpy(&e, data, data_sz);
    
    // Path is always at offset 0
    fprintf(stderr, "=== Blocked suspicious execve(%s) attempt ===\n", e.strings);
    for (i = 0; e.env_offsets[i] != 0; i++) {
        fprintf(stderr, "%s\n", &e.strings[e.env_offsets[i]]);
    }
    fprintf(stderr, "===\n");
    
    return 0;
}

static void sig_handler(int sig)
{
    fprintf(stderr, "Received signal %d, exiting...\n", sig);
    running = false;
}

int main(void)
{
    struct execve_monitor_bpf *skel;
    struct ring_buffer *rb;
    int err;

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Open and load BPF program
    skel = execve_monitor_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        exit(EXIT_FAILURE);
    }

    // Attach BPF program
    err = execve_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        exit(EXIT_FAILURE);
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Successfully started! Please run commands to see execve() calls.\n");

    // Main loop
    while (running) {
        err = ring_buffer__poll(rb, -1);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
}