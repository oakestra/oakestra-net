#!/bin/bash

# Names of the network namespaces
NS1="ns1"
NS2="ns2"

# Name of the bridge
BRIDGE="br0"

# Create the two network namespaces
ip netns add $NS1
ip netns add $NS2

# Create the bridge
ip link add name $BRIDGE type bridge
ip addr add 10.0.0.3/28 dev $BRIDGE

# Create the veth pairs
ip link add veth-$NS1 type veth peer name veth-$NS1-peer
ip link add veth-$NS2 type veth peer name veth-$NS2-peer

# Attach one end of the veth pairs to the network namespaces
ip link set veth-$NS1-peer netns $NS1
ip link set veth-$NS2-peer netns $NS2

# Attach the other ends of the veth pairs to the bridge
ip link set dev veth-$NS1 master $BRIDGE
ip link set dev veth-$NS2 master $BRIDGE

# Assign IP addresses to the interfaces within the namespaces
ip netns exec $NS1 ip addr add 10.0.0.1/28 dev veth-$NS1-peer
ip netns exec $NS2 ip addr add 10.0.0.2/28 dev veth-$NS2-peer

# Bring up the bridge and veths
ip link set dev $BRIDGE up
ip -n $NS1 link set veth-$NS1-peer up
ip -n $NS2 link set veth-$NS2-peer up
ip link set dev veth-$NS1 up
ip link set dev veth-$NS2 up

#Allow traffic in firewall
iptables -A FORWARD -o $BRIDGE -j ACCEPT
iptables -A FORWARD -i $BRIDGE -j ACCEPT

# Set up NAT using iptables to allow outbound traffic from the namespaces
# Adjust eth0 to your default network interface if different
iptables -t nat -A POSTROUTING -s 10.0.0.0/28 -o eth0 -j MASQUERADE

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

#Default Gateway for unknown IPs
ip netns exec $NS1 ip route add default via 10.0.0.3
ip netns exec $NS2 ip route add default via 10.0.0.3

# Configure the namespaces to use the host's DNS settings
mkdir -p /etc/netns/$NS1 /etc/netns/$NS2
cp /etc/resolv.conf /etc/netns/$NS1/
cp /etc/resolv.conf /etc/netns/$NS2/