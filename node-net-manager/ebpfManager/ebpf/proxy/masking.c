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

#define IPV4_SUBNET 0xC0A80100 // 192.168.1.0
#define IPV4_MASK 0xFFFFFF00   // 255.255.255.0

#define IPV6_SUBNET                                                                                    \
    {                                                                                                  \
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }
#define IPV6_MASK                                                                                      \
    {                                                                                                  \
        0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 \
    }

extern bool is_ipv4_in_network(__be32 addr) {
    return (addr & IPV4_MASK) == (IPV4_SUBNET & IPV4_MASK);
}

extern bool is_ipv6_in_network(struct in6_addr *addr, struct in6_addr *network, struct in6_addr *mask) {
    for (int i = 0; i < 4; i++) {
        if ((addr->in6_u.u6_addr32[i] & mask->in6_u.u6_addr32[i]) != (network->in6_u.u6_addr32[i] & mask->in6_u.u6_addr32[i])) {
            return false;
        }
    }
    return true;
}
