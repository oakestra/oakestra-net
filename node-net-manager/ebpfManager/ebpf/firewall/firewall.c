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

struct fw_rule
{
    __u32 src_ip;
    __u32 dst_ip;
    __u8 proto;
    __u8 p1;
    __u8 p2;
    __u8 p3;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fw_rule);
    __type(value, __u8);
    __uint(max_entries, 1024);
} fw_rules SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    // Access the packet data using bpf_skb_load_bytes
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_PIPE;

    struct iphdr ip;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip));

    // Initialize rule keys for lookup
    struct fw_rule key = {
        .src_ip = ip.saddr,
        .dst_ip = ip.daddr,
        .proto = ip.protocol,
        .p1 = 0,
        .p2 = 0,
        .p3 = 0,
        .src_port = 0,
        .dst_port = 0,
    };

    if (ip.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &udp, sizeof(udp));
        key.src_port = udp.source;
        key.dst_port = udp.dest;
    }
    else if (ip.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcp, sizeof(tcp));
        key.src_port = tcp.source;
        key.dst_port = tcp.dest;
    }
    else if (ip.protocol == IPPROTO_ICMP)
    {
        struct icmphdr icmp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &icmp, sizeof(icmp));
        key.src_port = 0;
        key.dst_port = 0;
    }
    else
    {
        // Allow non-UDP/non-TCP/non-ICMP traffic to pass
        return TC_ACT_PIPE;
    }

    key.src_port = bpf_htons(key.src_port);
    key.dst_port = bpf_htons(key.dst_port);
    // Lookup the rule in the map
    __u8 *value = bpf_map_lookup_elem(&fw_rules, &key);
    if (value)
    {
        return TC_ACT_PIPE; // Rule found, pass the packet
    }

    return TC_ACT_SHOT; // Default action is to drop
}

SEC("tc")
int handle_egress(struct __sk_buff *skb)
{
    // Access the packet data using bpf_skb_load_bytes
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_PIPE;

    struct iphdr ip;
    bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip));

    // Initialize rule keys for lookup
    struct fw_rule key = {
        .src_ip = ip.saddr,
        .dst_ip = ip.daddr,
        .proto = ip.protocol,
        .p1 = 0,
        .p2 = 0,
        .p3 = 0,
        .src_port = 0,
        .dst_port = 0,
    };

    if (ip.protocol == IPPROTO_UDP)
    {
        struct udphdr udp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &udp, sizeof(udp));
        key.src_port = udp.source;
        key.dst_port = udp.dest;
    }
    else if (ip.protocol == IPPROTO_TCP)
    {
        struct tcphdr tcp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcp, sizeof(tcp));
        key.src_port = tcp.source;
        key.dst_port = tcp.dest;
    }
    else if (ip.protocol == IPPROTO_ICMP)
    {
        struct icmphdr icmp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &icmp, sizeof(icmp));
        key.src_port = 0;
        key.dst_port = 0;
    }
    else
    {
        // Allow non-UDP/non-TCP/non-ICMP traffic to pass
        return TC_ACT_PIPE;
    }

    key.src_port = bpf_htons(key.src_port);
    key.dst_port = bpf_htons(key.dst_port);
    // Lookup the rule in the map
    __u8 *value = bpf_map_lookup_elem(&fw_rules, &key);
    if (value)
    {
        return TC_ACT_PIPE; // Rule found, pass the packet
    }

    return TC_ACT_SHOT; // Default action is to drop
}

char _license[] SEC("license") = "GPL";
