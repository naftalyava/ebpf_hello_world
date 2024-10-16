#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");



SEC("kprobe/execve")
int probe_execve(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.op_code = 4;

    char *path = (char *)PT_REGS_PARM1(ctx);


    bpf_probe_read(&data.oldpath, sizeof(data.oldpath), path);

    bpf_ringbuf_output(&ringbuf, &data, sizeof(data), BPF_RB_FORCE_WAKEUP);

    return 0;
}



char LICENSE[] SEC("license") = "Dual BSD/GPL";
