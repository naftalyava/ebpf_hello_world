//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct alloc_info_t {
    u64 size;
    u64 stack_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);           // Address of allocation
    __type(value, struct alloc_info_t);
} allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 127 * sizeof(u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

// Temporary storage for size argument to malloc
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);           // TID
    __type(value, u64);         // Size
} sizes SEC(".maps");

// uprobe for malloc entry
SEC("uprobe/malloc_enter")
int malloc_enter(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 size = PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&sizes, &tid, &size, BPF_ANY);
    return 0;
}

// uretprobe for malloc exit
SEC("uretprobe/malloc_exit")
int malloc_exit(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u64 addr = PT_REGS_RC(ctx);
    u64 *sizep = bpf_map_lookup_elem(&sizes, &tid);
    if (sizep) {
        struct alloc_info_t info = {};
        info.size = *sizep;
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);
        bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);
        bpf_map_delete_elem(&sizes, &tid);
    }
    return 0;
}

// uprobe for free
SEC("uprobe/free_enter")
int free_enter(struct pt_regs *ctx) {
    u64 addr = PT_REGS_PARM1(ctx);
    bpf_map_delete_elem(&allocs, &addr);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";