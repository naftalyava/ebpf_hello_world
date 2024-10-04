//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

struct ip_event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct ip_event_t);
} ip_events SEC(".maps");

static inline int extract_ip(struct sock *sk, struct ip_event_t *event) {
    event->src_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    event->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    event->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    event->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    event->src_port = bpf_ntohs(event->src_port);

    return 0;
}

SEC("kprobe/tcp_sendmsg")
int bpf_prog_tcp_sendmsg(struct pt_regs *ctx) {
    bpf_printk("tcp_sendmsg called\n");
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        bpf_printk("tcp_sendmsg: sk is NULL\n");
        return 0;
    }
    
    struct ip_event_t event = {};
    extract_ip(sk, &event);
    
    __u32 key = bpf_get_prandom_u32();
    int ret = bpf_map_update_elem(&ip_events, &key, &event, BPF_ANY);
    if (ret < 0) {
        bpf_printk("Failed to update map: %d\n", ret);
    } else {
        bpf_printk("Event added to map\n");
    }

    return 0;
}

SEC("kprobe/tcp_recvmsg")
int bpf_prog_tcp_recvmsg(struct pt_regs *ctx) {
    bpf_printk("tcp_recvmsg called\n");
    
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) {
        bpf_printk("tcp_recvmsg: sk is NULL\n");
        return 0;
    }
    
    struct ip_event_t event = {};
    extract_ip(sk, &event);
    
    __u32 key = bpf_get_prandom_u32();
    int ret = bpf_map_update_elem(&ip_events, &key, &event, BPF_ANY);
    if (ret < 0) {
        bpf_printk("Failed to update map: %d\n", ret);
    } else {
        bpf_printk("Event added to map\n");
    }

    return 0;
}

SEC("kprobe/do_renameat2")
int probe_renameat2(struct pt_regs *ctx)
{
    bpf_printk("renameat2 called\n");
    return 0;
}

char _license[] SEC("license") = "GPL";