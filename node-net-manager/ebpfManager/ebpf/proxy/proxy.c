//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>

struct bpf_map_def SEC("maps") lookup_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
};

SEC("classifier")
int handle_ingress(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";