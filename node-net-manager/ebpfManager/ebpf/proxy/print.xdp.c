#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_prog")
int printer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // Check that packet is long enough to contain Ethernet header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    // Check if the packet is an IPv4 packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Move the pointer to the IP header
    ip = data + sizeof(*eth);

    const char msg[] = "XDP: %x\n";
    bpf_trace_printk(msg, sizeof(msg), ip->daddr);


    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";