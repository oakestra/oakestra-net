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
    __u8 proto; //TODO ben can weird padding be ommited somehow?
    __u8 p1;
    __u8 p2;
    __u8 p3;
    __u16 src_port;
    __u16 dst_port;
};

struct bpf_map_def SEC("maps") fw_rules = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct fw_rule),
    .value_size = sizeof(__u8),
    .max_entries = 1024,
};

SEC("classifier")
int handle_ingress(struct __sk_buff *skb)
{
    // Access the packet data using bpf_skb_load_bytes
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Pass the packet if it is not IPv4 for now TODO ben!

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
        // TODO ben currently doing nothing!
        struct icmphdr icmp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &icmp, sizeof(icmp));
        key.src_port = 0;
        key.dst_port = 0;
    }
    else
    {
        // Allow non-UDP/non-TCP/non-ICMP traffic to pass
        return TC_ACT_OK;
    }

    key.src_port = bpf_htons(key.src_port);
    key.dst_port = bpf_htons(key.dst_port);
    // Lookup the rule in the map
    __u8 *value = bpf_map_lookup_elem(&fw_rules, &key);
    if (value)
    {
        return TC_ACT_OK; // Rule found, pass the packet
    }

    return TC_ACT_SHOT; // Default action is to drop
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    // Access the packet data using bpf_skb_load_bytes
    struct ethhdr eth;
    bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth));

    if (eth.h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK; // Pass the packet if it is not IPv4 for now TODO ben!

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
        // TODO ben currently doing nothing!
        struct icmphdr icmp;
        bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &icmp, sizeof(icmp));
        key.src_port = 0;
        key.dst_port = 0;
    }
    else
    {
        // Allow non-UDP/non-TCP/non-ICMP traffic to pass
        return TC_ACT_OK;
    }

    key.src_port = bpf_htons(key.src_port);
    key.dst_port = bpf_htons(key.dst_port);
    // Lookup the rule in the map
    __u8 *value = bpf_map_lookup_elem(&fw_rules, &key);
    if (value)
    {
        return TC_ACT_OK; // Rule found, pass the packet
    }

    return TC_ACT_SHOT; // Default action is to drop
}

//
// SEC("xdp_prog")
// int firewall(struct xdp_md *ctx)
//{
//    // Access the data and data_end from the packet context
//    void *data = (void *)(long)ctx->data;
//    void *data_end = (void *)(long)ctx->data_end;
//
//    // Check that the packet contains enough data to validate the Ethernet header
//    struct ethhdr *eth = data;
//    if ((void *)eth + sizeof(*eth) > data_end)
//        return XDP_DROP;
//
//    // Filter only IPv4 packets, Ethertype 0x0800
//    if (eth->h_proto != bpf_htons(ETH_P_IP))
//        return XDP_PASS;
//
//    // Offset to the IP header
//    struct iphdr *ip = data + sizeof(struct ethhdr);
//    if ((void *)ip + sizeof(*ip) > data_end)
//        return XDP_DROP;
//
//    unsigned int dest_ip = ip->daddr;
//    int ifindex = ctx->ingress_ifindex;
//    const char msg[] = "XDP received packet with destination IP: %x on interface: %d\n"; // TODO ben remove just here for debugging
//    bpf_trace_printk(msg, sizeof(msg), dest_ip, ifindex);
//
//    struct fw_rule key = {
//        .src_ip = ip->saddr,
//        .dst_ip = ip->daddr,
//        .src_port = 0,
//        .dst_port = 0,
//    };
//
//    if (ip->protocol == IPPROTO_UDP)
//    {
//        struct udphdr *udp = (void *)ip + sizeof(*ip);
//        if ((void *)(udp + 1) > data_end)
//            return XDP_DROP;
//        key.src_port = udp->source;
//        key.dst_port = udp->dest;
//    }
//    else if (ip->protocol == IPPROTO_TCP)
//    {
//        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
//        if ((void *)(tcp + 1) > data_end)
//            return XDP_DROP;
//        key.src_port = tcp->source;
//        key.dst_port = tcp->dest;
//    }
//    else
//    {
//        // TODO ben let all traffic that is not UDP or TCP pass for now.
//        return XDP_PASS;
//    }
//
//    // Lookup the rule in the map
//    __u8 *value = bpf_map_lookup_elem(&fw_rules, &key);
//    if (value)
//    {
//        return XDP_PASS; // Rule found, pass the packet
//    }
//
//    const char drp[] = "Packet was dropped\n"; // TODO ben remove just here for debugging
//    bpf_trace_printk(drp, sizeof(drp));
//    return XDP_DROP; // Default action is to drop
//}

char _license[] SEC("license") = "GPL";