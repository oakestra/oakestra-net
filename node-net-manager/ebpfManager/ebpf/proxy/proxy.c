//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>
#include "masking.h"

struct bpf_map_def SEC("maps") lookup_table = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
};

void print(char * msg) {
    bpf_trace_printk(msg, sizeof(msg));
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb)
{
    struct ethhdr eth;
    struct iphdr ipv4;
    struct ipv6hdr ipv6;
    bool isInSubNet = false;

    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto == bpf_htons(ETH_P_IP)) {
        //print("IPv4");
        // IPv4 packet
        if (bpf_skb_load_bytes(skb, sizeof(eth), &ipv4, sizeof(ipv4)) < 0)
            return TC_ACT_SHOT;

        isInSubNet = is_ipv4_in_network(ipv4.daddr);
    } else if (eth.h_proto == bpf_htons(ETH_P_IPV6)) {
        //print("IPv6");
        // IPv6 packet
        if (bpf_skb_load_bytes(skb, sizeof(eth), &ipv6, sizeof(ipv6)) < 0)
            return TC_ACT_SHOT;
        isInSubNet = is_ipv4_in_network(ipv4.daddr);
    }

    // if not in the relevant subnetworks -> pass the packet
    if (!isInSubNet)
        return TC_ACT_UNSPEC;

    return TC_ACT_UNSPEC;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";