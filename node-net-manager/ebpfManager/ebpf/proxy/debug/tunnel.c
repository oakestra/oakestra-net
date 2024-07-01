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
#include <stddef.h>
#include "../masking.h"

#define IP_UDP 17

struct bpf_map_def SEC(

"maps")
lookup_table = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u8),
        .value_size = sizeof(__u8),
        .max_entries = 1024,
};

int proxy(struct __sk_buff *skb){
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;

    struct ethhdr ethHdr;
    struct iphdr ipHdr;

    int iphdr_len;

    bool isInSubNet = false;

    // check if enough size for ethernet header
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_UNSPEC;
    }

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        const char msg[] = "Ingress IPv4\n";
        bpf_trace_printk(msg, sizeof(msg));

        ip = (struct iphdr *) (eth + 1);
        if ((void *) (ip + 1) > data_end) {
            return TC_ACT_UNSPEC;
        }

        iphdr_len = ip->ihl * 4;
        if (iphdr_len < sizeof(*ip))
            return TC_ACT_SHOT;

        // Check if there's enough room for UDP header
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
            return TC_ACT_SHOT;

        int totalLength = bpf_ntohs(ip->tot_len);
        int ihl = ip->ihl * 8;
        int s = sizeof(struct iphdr);

        // Adjust the skb to make room for new IP and UDP headers
        if (bpf_skb_adjust_room(skb, sizeof(struct iphdr) + sizeof(struct udphdr), BPF_ADJ_ROOM_NET, 0))
            return TC_ACT_SHOT;

        // Update pointers after adjusting room
        data = (void *) (long) skb->data;
        data_end = (void *) (long) skb->data_end;
        eth = data;
        ip = (struct iphdr *) (eth + 1);
        udp = (struct udphdr *) ((void *) ip + sizeof(struct iphdr));

        if ((void *) (ip + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        const char msg2[] = "ihl: %d, tol: %d, s: %d\n";
        bpf_trace_printk(msg2, sizeof(msg2), ihl, totalLength, s);

        // Set the new IP header
        ip->version = 4;
        ip->ihl = sizeof(struct iphdr) / 4;
        ip->tos = 0;
        ip->tot_len = __bpf_htons(skb->len - sizeof(struct ethhdr));
        ip->id = 0;
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IP_UDP;
        ip->check = 0;
        ip->saddr = __bpf_htonl(0x0a1e0001);
        ip->daddr = __bpf_htonl(0x0a1e0002);
        ip->check = 0;
        ip->check = bpf_htons(0x665a); // set correct checksum statically foe debugging
        // TODO ben to size should be ip.idh * 4. Now set to 20 for debugging purposes. most IPH are 20B long
        //ip->check = bpf_csum_diff(0, 0, (__be32 *) ip, 20, 0);

        if ((void *) (udp + 1) > data_end) {
            return TC_ACT_SHOT;
        }

        // Set the new UDP header
        udp->source = __bpf_htons(12345);
        udp->dest = __bpf_htons(54321);
        udp->len = __bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
        udp->check = 0; // TODO ben Hint: In IPv6 UDP packets need a checksum! rfc768

        //bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),0, ip->saddr, 2);

        return TC_ACT_OK;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 packet
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_OK;
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    return proxy(skb);
}

char _license[]
SEC("license") = "GPL";