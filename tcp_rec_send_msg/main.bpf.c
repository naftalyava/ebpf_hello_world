//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define MAX_PAYLOAD_LENGTH 9000
#define MAX_LOOP_ITERATIONS 12
#define CHUNK_SIZE 64
#define ITER_IOVEC 2
#define ITER_KVEC 1

struct ip_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 payload_length;
    char payload[MAX_PAYLOAD_LENGTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ip_event_t);
} ip_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ip_event_t);
} ip_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} allowed_pids SEC(".maps");

// Helper function to extract the payload from the msghdr
static inline int extract_payload(struct msghdr *msg, struct ip_event_t *event) {
    if (!msg) {
        bpf_printk("naftaly: msg is NULL");
        return -1;
    }

    bpf_printk("naftaly: msg address: %llx", (unsigned long long)msg);

    // Read the iov_iter structure from the msg
    struct iov_iter iter;
    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) < 0) {
        bpf_printk("naftaly: Failed to read iov_iter structure");
        return -1;
    }

    // Read iter_type
    u8 iter_type = BPF_CORE_READ(&iter, iter_type);
    bpf_printk("naftaly: iter_type: %d", iter_type);

    // Read count (length)
    size_t count = BPF_CORE_READ(&iter, count);
    bpf_printk("naftaly: iov_iter count: %lu", count);

    const void *base = NULL;
    size_t len = 0;

    if (iter_type == ITER_IOVEC) {
        // Handle ITER_IOVEC as before
        // Implement code to handle ITER_IOVEC if necessary
        bpf_printk("naftaly: ITER_IOVEC not handled in this example");
        return -1;
    } else if (iter_type == ITER_UBUF) {
        // Handle ITER_UBUF
        const void *ubuf = NULL;
        if (BPF_CORE_READ_INTO(&ubuf, &iter, ubuf) < 0) {
            bpf_printk("naftaly: Failed to read ubuf pointer");
            return -1;
        }
        bpf_printk("naftaly: ubuf pointer: %llx", (unsigned long long)ubuf);

        if (ubuf && count > 0) {
            base = ubuf;
            len = count;
        } else {
            bpf_printk("naftaly: ubuf is NULL or count is 0");
            return -1;
        }
    } else {
        bpf_printk("naftaly: Unsupported iter_type: %d", iter_type);
        return -1;
    }

    if (len > 0 && base != NULL) {
        // Adjust the read length if necessary
        size_t read_len = len < MAX_PAYLOAD_LENGTH ? len : MAX_PAYLOAD_LENGTH;

        int read_result = bpf_probe_read_user(event->payload, read_len, base);

        if (read_result < 0) {
            bpf_printk("naftaly: Failed to read payload, error: %d", read_result);
            return -1;
        }

        event->payload_length = read_len;

        // Optional: print the first few bytes of the payload
        size_t print_len = read_len < 16 ? read_len : 16;
        for (int i = 0; i < print_len; i++) {
            bpf_printk("naftaly: Payload byte %d: %02x", i + 1, event->payload[i]);
        }
    } else {
        bpf_printk("naftaly: Invalid length or base");
    }

    return 0;
}



static inline int extract_ip(struct sock *sk, struct ip_event_t *event, struct msghdr *msg) {
    event->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->src_port = bpf_ntohs(event->src_port);

    if (msg) {
        extract_payload(msg, event);
    }

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int bpf_prog_tcp_sendmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    if (!allowed) {
        return 0;
    }

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk || !msg) {
        return 0;
    }

    __u32 key = 0;
    struct ip_event_t *event = bpf_map_lookup_elem(&ip_event_map, &key);
    if (!event) {
        return 0;
    }

    extract_ip(sk, event, msg);

    key = bpf_get_prandom_u32();
    bpf_map_update_elem(&ip_events, &key, event, BPF_ANY);

    return 0;
}

SEC("kprobe/tcp_recvmsg")
int bpf_prog_tcp_recvmsg(struct pt_regs *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *allowed = bpf_map_lookup_elem(&allowed_pids, &pid);
    if (!allowed) {
        return 0;
    }

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

    if (!sk || !msg) {
        return 0;
    }

    __u32 key = 0;
    struct ip_event_t *event = bpf_map_lookup_elem(&ip_event_map, &key);
    if (!event) {
        return 0;
    }

    extract_ip(sk, event, msg);

    key = bpf_get_prandom_u32();
    bpf_map_update_elem(&ip_events, &key, event, BPF_ANY);

    return 0;
}

char _license[] SEC("license") = "GPL";