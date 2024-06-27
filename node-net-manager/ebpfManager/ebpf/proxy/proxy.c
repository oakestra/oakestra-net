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

#define MAX_IPS 32 // implies that no more than 32 replicas of one service can exist

struct session_key {
    __be32 src_ip;
    __be32 dst_service_ip;
    __be16 src_port;
    __be16 dst_port;
};

struct ip_list {
    int length;
    __be32 ips[MAX_IPS];
};

struct bpf_map_def SEC(

"maps/service_to_instance")
service_to_instance = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__be32),
        .value_size = sizeof(struct ip_list),
        .max_entries = 128,
};

struct bpf_map_def SEC(

"maps/open_sessions")
open_sessions = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct session_key),
        .value_size = sizeof(__be32),
        .max_entries = 1024,
};

// TODO BEN just for debugging
struct event_t {
    __u64 timestamp;
    __u32 len;
    char data[64];
};

struct bpf_map_def SEC(

"maps")
events = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 128,
};

int outgoing_proxy(struct __sk_buff *skb) {
    const char msg0[] = "Hello from egress\n";
    bpf_trace_printk(msg0, sizeof(msg0)); // TODO ben remove

    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;

    struct session_key key = {};
    __u32 new_daddr;

    // check if enough size for ethernet header
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // check if IPv4. Ebpf proxy only supports IPv4 for now.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    ip = (struct iphdr *) (eth + 1);
    if ((void *) (ip + 1) > data_end)
        return TC_ACT_OK;

    key.src_ip = ip->saddr;
    key.dst_service_ip = ip->daddr;

    int iphdr_len = ip->ihl * 4;
    if (iphdr_len < sizeof(*ip))
        // TODO ben, this more or less disables the use of IPv4 options
        //  but we need some kind of a bound for IHL for the ebpf verifier
        return TC_ACT_SHOT;

    // proxy only supports TCP and UDP for now.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;

        tcp = (struct tcphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (tcp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    }
    // TODO ben why does 'else if' not work here??
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;

        udp = (struct udphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (udp + 1) > data_end)
            return TC_ACT_OK;

        key.src_port = udp->source;
        key.dst_port = udp->dest;
        udp->check = 0;
    } else {
        // return for non-udp and non-tcp packets
        return TC_ACT_OK;
    }


    __be32 *open_connection_ip = bpf_map_lookup_elem(&open_sessions, &key);

    if (open_connection_ip) {
        new_daddr = *open_connection_ip; // TODO ben this address could have gotten invalid in the meantime!
    } else {
        // if no open connection found, choose new server using round robin.
        // TODO ben Implement other mechanisms than RR here

        struct ip_list *ipl = bpf_map_lookup_elem(&service_to_instance, &ip->daddr);
        if (!ipl) {
            // TODO ben cache packet and trigger update to potentially find IP.
            return TC_ACT_SHOT;
        }

        // select instance IP using RR
        int rand_index = bpf_get_prandom_u32() % ipl->length % MAX_IPS;
        new_daddr = ipl->ips[rand_index];

        const char msg1[] = "lol: %x\n";
        bpf_trace_printk(msg1, sizeof(msg1), new_daddr); // TODO ben remove

        // add new 4-Tuple to our session cache
        bpf_map_update_elem(&open_sessions, &key, &new_daddr, BPF_ANY);

        const char msg2[] = "test: %x\n";
        bpf_trace_printk(msg2, sizeof(msg2), new_daddr); // TODO ben remove
    }

    const char msg14[] = "check before: %x\n";
    bpf_trace_printk(msg14, sizeof(msg14), ip->check); // TODO ben remove

    __s64 sum = bpf_csum_diff((void *)&ip->daddr, 4, (void *)&new_daddr, 4, 0);
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), (void *)&new_daddr, 4, 0) < 0)
        return TC_ACT_SHOT; // Drop packet if modification fails
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + + offsetof(struct iphdr, check), 0, sum, 0);

    return bpf_redirect(skb->ifindex, 0); // TODO ben redirect to egress instantly
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    return outgoing_proxy(skb);
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    return TC_ACT_OK;
}

char _license[]
SEC("license") = "GPL";