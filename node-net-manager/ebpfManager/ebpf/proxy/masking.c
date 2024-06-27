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

#define IPv4LEN 4
#define IPv6LEN 16

#define IPV4_SUBNET 0x00001E0A // 10.30.0.0 in big endian
#define IPV4_MASK 0x0000FFFF // 255.255.255.0 in big endian

// TODO ben find out the IPv6 subnet
#define IPV6_SUBNET { 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define IPV6_MASK { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

extern bool is_ipv4_in_network(__be32 addr) {
    return (addr & IPV4_MASK) == (IPV4_SUBNET & IPV4_MASK);
}

extern bool is_ipv6_in_network(struct in6_addr *addr) {
    unsigned char subnet[16] = IPV6_SUBNET;
    unsigned char mask[16] = IPV6_MASK;

    for (int i = 0; i < 16; i++) {
        if ((addr->in6_u.u6_addr8[i] & mask[i]) != (subnet[i] & mask[i])) {
            return false;
        }
    }
    return true;
}
