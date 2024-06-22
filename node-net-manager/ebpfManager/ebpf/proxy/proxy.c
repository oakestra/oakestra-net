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

struct session_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct bpf_map_def SEC("maps/service_to_instance") service_to_instance = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 128,
};

struct bpf_map_def SEC("maps/round_robin_state") round_robin_state = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u32),
        .max_entries = 128,
};

struct bpf_map_def SEC("maps/open_sessions") open_sessions = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(struct session_key),
        .value_size = sizeof(__u32),
        .max_entries = 1024,
};

int proxy(struct __sk_buff *skb){
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    // check if enough size for ethernet header
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    // check if IPv4. Ebpf proxy only supports IPv4 for now.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    __u32 service_ip = ip->daddr;
    __u32 *instance_ip = bpf_map_lookup_elem(&service_to_instance, &service_ip);
    if (!instance_ip)
        return TC_ACT_OK;

    iphdr_len = ip->ihl * 4;
    if (iphdr_len < sizeof(*ip))
        // TODO ben, this more or less disables the use of IPv4 options
        //  but we need some kind of a bound for IHL for the ebpf verifier
        return TC_ACT_SHOT;

    // proxy only supports TCP and UDP for now.
    if (ip->protocol == IPPROTO_TCP) {
        tcp = (struct tcphdr *)((__u8 *)ip + iphdr_len);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        struct sock *sk = skb->sk;
        if (!sk)
            return TC_ACT_OK;

        __u32 *existing_instance_ip = bpf_map_lookup_elem(&open_connections, &sk);
        if (existing_instance_ip) {
            ip->daddr = *existing_instance_ip;
            return TC_ACT_OK;
        }

        __u32 rr_key = 0;
        __u32 *rr_state = bpf_map_lookup_elem(&round_robin_state, &rr_key);
        if (!rr_state)
            return TC_ACT_OK;

        __u32 next_instance_ip = instance_ip[*rr_state];
        *rr_state = (*rr_state + 1) % MAX_INSTANCES;

        bpf_map_update_elem(&round_robin_state, &rr_key, rr_state, BPF_ANY);
        bpf_map_update_elem(&open_connections, &sk, &next_instance_ip, BPF_ANY);

        ip->daddr = next_instance_ip;
        return TC_ACT_OK;
    } else if (ip->protocol == IPPROTO_UDP) {
        udp = (struct udphdr *)((__u8 *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        __u32 rr_key = 0;
        __u32 *rr_state = bpf_map_lookup_elem(&round_robin_state, &rr_key);
        if (!rr_state)
            return TC_ACT_OK;

        __u32 next_instance_ip = instance_ip[*rr_state];
        *rr_state = (*rr_state + 1) % MAX_INSTANCES;

        bpf_map_update_elem(&round_robin_state, &rr_key, rr_state, BPF_ANY);

        ip->daddr = next_instance_ip;
        return TC_ACT_OK;
    }

    return TC_ACT_OK;
}

SEC("classifier")
int handle_ingress(struct __sk_buff *skb) {
    return proxy(skb);
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb) {
    return proxy(skb);
}