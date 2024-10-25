//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_STACK_DEPTH 64

struct alloc_info_t {
    u64 size;
    s32 stack_id;
    u32 padding; // Added padding to align to 16 bytes
};

// Map to store allocation info with the allocation address as the key
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct alloc_info_t);
} allocs SEC(".maps");

// Stack trace map
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10240);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} stack_traces SEC(".maps");

// Helper to get user-space stack trace
static __always_inline int get_user_stackid(struct pt_regs *ctx) {
    int stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    if (stack_id < 0) {
        // Handle errors or return 0 if necessary
        return -1;
    }
    return stack_id;
}

SEC("uprobe/malloc_enter")
int malloc_enter(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Store the size argument
    u64 size = PT_REGS_PARM1(ctx);

    // Save the size in a map indexed by the PID
    bpf_map_update_elem(&allocs, &pid_tgid, &size, BPF_ANY);
    return 0;
}

SEC("uretprobe/malloc_exit")
int malloc_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Retrieve the size from the map
    u64 *size_ptr = bpf_map_lookup_elem(&allocs, &pid_tgid);
    if (!size_ptr) {
        return 0;
    }
    u64 size = *size_ptr;

    // Get the return value (allocated address)
    u64 addr = PT_REGS_RC(ctx);
    if (addr == 0) {
        // Allocation failed
        bpf_map_delete_elem(&allocs, &pid_tgid);
        return 0;
    }

    // Get user stack trace
    int stack_id = get_user_stackid(ctx);

    // Prepare allocation info
    struct alloc_info_t info = {};
    info.size = size;
    info.stack_id = stack_id;

    // Store the allocation info in the allocs map with the address as the key
    bpf_map_update_elem(&allocs, &addr, &info, BPF_ANY);

    // Clean up
    bpf_map_delete_elem(&allocs, &pid_tgid);

    return 0;
}

SEC("uprobe/free_enter")
int free_enter(struct pt_regs *ctx) {
    u64 addr = PT_REGS_PARM1(ctx);

    // Remove the allocation info from the map
    bpf_map_delete_elem(&allocs, &addr);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
