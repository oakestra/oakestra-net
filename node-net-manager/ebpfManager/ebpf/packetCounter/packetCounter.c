//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 2);
} pkt_count SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    __u32 key    = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return TC_ACT_PIPE;
}

SEC("tc")
int handle_egress(struct __sk_buff *skb)
{
    __u32 key    = 1;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
    return TC_ACT_PIPE;
}

char _license[] SEC("license") = "GPL";