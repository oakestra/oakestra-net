//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <stdbool.h>

// including options an IP header cannot get larger than (2^16 - 1) * 4 60B
#define MAX_IPV4_HEADER_LENGTH 60
#define MIN_IPV4_HEADER_LENGTH 20

// implies that no more than MAX_IPS replicas of one service can exist
#define MAX_IPS 32

// implies that one service cannot open more than MAX_CONVERSION connections to another services on the same source and destination port.
#define MAX_CONVERSION 4

// a session is described from the perspective of the client. We only need the ports because each service has its own ebpf proxy.
struct session_key {
    __be16 src_port;
    __be16 dst_port;
};

struct conversion {
    __be32 service_ip;
    __be32 instance_ip;
};

struct conversion_list {
    uint last_index;
    struct conversion conversions[MAX_CONVERSION];
};

struct ip_list {
    uint length;
    __be32 ips[MAX_IPS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, struct ip_list);
    __uint(max_entries, 128); // TODO maybe increase size in future
    __uint(pinning, LIBBPF_PIN_BY_NAME); // pin by name -> just one map for all proxy instances
} service_to_instance SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct session_key);
    __type(value, struct conversion_list);
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} open_sessions SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} ip_updates SEC(".maps");

extern bool is_ipv4_in_network(__be32 addr);

int outgoing_proxy(struct __sk_buff *skb);
int ingoing_proxy(struct __sk_buff *skb);

SEC("tc")
int handle_ingress(struct __sk_buff *skb) {
    return outgoing_proxy(skb);
}

SEC("tc")
int handle_egress(struct __sk_buff *skb) {
    return ingoing_proxy(skb);
}

int outgoing_proxy(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;

    struct session_key key = {};
    __u32 new_daddr = 0;

    // check if enough size for ethernet header
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_PIPE;
    }

    // check if IPv4. Ebpf proxy only supports IPv4 for now.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_PIPE;
    }

    ip = (struct iphdr *) (eth + 1);
    if ((void *) (ip + 1) > data_end)
        return TC_ACT_PIPE;


    // uint iphdr_len = ip->ihl * 4;
    // TODO for some reason the verifier does not like this. Seting iphdr_len to 20 effectively disables IP options!
    uint iphdr_len = 20;
    // if (iphdr_len < MIN_IPV4_HEADER_LENGTH || iphdr_len > MAX_IPV4_HEADER_LENGTH) {
    //     return TC_ACT_SHOT;
    // }

    if (!is_ipv4_in_network(ip->daddr)) {
        return TC_ACT_PIPE;
    }

    // proxy only supports TCP and UDP for now.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;

        tcp = (struct tcphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (tcp + 1) > data_end)
            return TC_ACT_PIPE;

        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;

        udp = (struct udphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (udp + 1) > data_end)
            return TC_ACT_PIPE;

        key.src_port = udp->source;
        key.dst_port = udp->dest;
    } else {
        // return for non-udp and non-tcp packets
        return TC_ACT_PIPE;
    }

    // check if a TCP/UDP session was already established for this service IP
    struct conversion_list *list_ptr = bpf_map_lookup_elem(&open_sessions, &key);
    if (list_ptr) {
        for (int i = 0; i < MAX_CONVERSION; i++) {
            if (list_ptr->conversions[i].service_ip == ip->daddr) {
                new_daddr = list_ptr->conversions[i].instance_ip; // TODO ben this address could have gotten invalid in the meantime!
            }
        }
    }

    // seems like we haven't found an open session -> choose new server using RR and create new session
    if (!new_daddr) {
        struct ip_list *ipl = bpf_map_lookup_elem(&service_to_instance, &ip->daddr);
        __be32 daddr = ip->daddr;
        bpf_perf_event_output(skb, &ip_updates, BPF_F_CURRENT_CPU, &daddr, sizeof(daddr));
        if (!ipl) {
            // no translation in table found. Drop the packet and hope there is an update next time this IP is used
            return TC_ACT_SHOT; // Drop the packet
        }

        // TODO Implement other mechanisms than RR here
        // select instance IP using RR
        int rand_index = bpf_get_prandom_u32() % ipl->length % MAX_IPS;
        new_daddr = ipl->ips[rand_index];

        struct conversion new_conversion = {
                .service_ip = ip->daddr,
                .instance_ip = new_daddr
        };

        struct conversion_list new_list = {};
        if (list_ptr) {
            new_list = *(list_ptr);
            int index = (new_list.last_index + 1) % MAX_CONVERSION;
            new_list.conversions[index] = new_conversion;
            new_list.last_index = index;
        }
        else {
            new_list.conversions[0] = new_conversion;
            new_list.last_index = 0;
        }
        bpf_map_update_elem(&open_sessions, &key, &new_list, BPF_ANY);
    }

    // replace destination ip and recalculate L3 checksum
    __s64 sum = bpf_csum_diff((void *)&ip->daddr, 4, (void *)&new_daddr, 4, 0);
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, daddr), (void *)&new_daddr, 4, 0) < 0) {
        return TC_ACT_PIPE; // Drop packet if modification fails
    }
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, sum, 0);

    return TC_ACT_PIPE;
}

int ingoing_proxy(struct __sk_buff *skb) {
    void *data = (void *) (long) skb->data;
    void *data_end = (void *) (long) skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip;

    struct session_key key = {};
    __u32 new_daddr = 0;

    // check if enough size for ethernet header
    if ((void *) (eth + 1) > data_end) {
        return TC_ACT_PIPE;
    }

    // check if IPv4. Ebpf proxy only supports IPv4 for now.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_PIPE;
    }

    ip = (struct iphdr *) (eth + 1);
    if ((void *) (ip + 1) > data_end)
        return TC_ACT_PIPE;


    // uint iphdr_len = ip->ihl * 4;
    // TODO for some reason the verifier does not like this. Seting iphdr_len to 20 effectively disables IP options!
    uint iphdr_len = 20;
    // if (iphdr_len < MIN_IPV4_HEADER_LENGTH || iphdr_len > MAX_IPV4_HEADER_LENGTH) {
    //     return TC_ACT_SHOT;
    // }

    // proxy only supports TCP and UDP for now.
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp;

        tcp = (struct tcphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (tcp + 1) > data_end)
            return TC_ACT_PIPE;

        key.src_port = tcp->dest;
        key.dst_port = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp;

        udp = (struct udphdr *) ((__u8 *) ip + iphdr_len);
        if ((void *) (udp + 1) > data_end)
            return TC_ACT_PIPE;

        key.src_port = udp->dest;
        key.dst_port = udp->source;
    } else {
        // return for non-udp and non-tcp packets
        return TC_ACT_PIPE;
    }

    // check if a TCP/UDP session was already established for this service IP
    struct conversion_list *list_ptr = bpf_map_lookup_elem(&open_sessions, &key);
    if (list_ptr) {
        for (int i = 0; i < MAX_CONVERSION; i++) { // TODO ben (length % MAX_CONVERSION) would be better in my opinion  but verfier wants us to loop through all entries
            if (list_ptr->conversions[i].instance_ip == ip->saddr) {
                new_daddr = list_ptr->conversions[i].service_ip; // TODO ben this address could have gotten invalid in the meantime!
            }
        }
    }

    // seems like we haven't found an open session -> no conversion needed
    if (!new_daddr) {
       return TC_ACT_PIPE;
    }

    // replace destination ip and recalculate L3 checksum
    __s64 sum = bpf_csum_diff((void *)&ip->saddr, 4, (void *)&new_daddr, 4, 0);
    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, saddr), (void *)&new_daddr, 4, 0) < 0) {
        return TC_ACT_PIPE; // Drop packet if modification fails
    }
    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check), 0, sum, 0);

    return TC_ACT_PIPE;
}

char _license[]
SEC("license") = "GPL";
