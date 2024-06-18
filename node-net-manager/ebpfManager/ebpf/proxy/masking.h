//go:build ignore

#ifndef MASKING_H
#define MASKING_H

extern bool is_ipv4_in_network(__be32 addr);
extern bool is_ipv6_in_network(struct in6_addr *addr);

#endif