// file: main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include "main.skel.h"
#include "main.h"

int handle_event(void *ctx, void *data, size_t len)  {
    struct data_t *event = (struct data_t*) data;

    if (event->op_code == 3) {
        printf("Event Received:\n");
        printf("\t newname: %s\n", event->newpath);
        printf("\t oldname: %s\n", event->oldpath);
    }

    
}

void handle_sigint(int sig) {
    printf("Terminating\n");
    exit(0);
}

static int libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
        return 0;
    return vfprintf(stderr, format, args);
}


int main(int argc, char *argv[]) {
    struct main_bpf *skel;
    struct perf_buffer_opts pb_opts = {0};
    int err;

    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    // Initialize libbpf
    libbpf_set_print(libbpf_print);

    // Load and verify BPF application
    skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // Attach kprobe
    err = main_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(skel->obj, "ringbuf");
    if (!map) {
        fprintf(stderr, "Failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    printf("Successfully started! Please Ctrl+C to stop.\n");

    // Poll the ring buffer
    while (1) {
        if (ring_buffer__poll(rb, 100 /* timeout, ms */) < 0) {
            fprintf(stderr, "Error polling ring buffer\n");
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    main_bpf__destroy(skel);
    return 0;
}
