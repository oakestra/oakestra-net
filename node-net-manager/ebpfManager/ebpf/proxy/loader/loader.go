package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

func main() {
	ifname := "veth-ns1"
	spec, err := ebpf.LoadCollectionSpec("../build/main.o")
	if err != nil {
		log.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatal(err)
	}

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatal(err)
	}

	progIngress := coll.Programs["handle_ingress"]
	if progIngress == nil {
		log.Fatal(err)
	}

	progEgress := coll.Programs["handle_egress"]
	if progEgress == nil {
		log.Fatal(err)
	}

	qdisc := netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: iface.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	if err := netlink.QdiscReplace(&qdisc); err != nil && err.Error() != "file exists" {
		log.Fatal(err)
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Priority:  0,
			Handle:    netlink.MakeHandle(0x1, 0),
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progIngress.String(),
		Fd:           progIngress.FD(),
	}

	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Priority:  0,
			Handle:    netlink.MakeHandle(0x1, 0),
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progEgress.String(),
		Fd:           progEgress.FD(),
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		log.Fatal(err)
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		log.Fatal(err)
	}

	ifname2 := "veth-ns2"

	iface2, err := net.InterfaceByName(ifname2)
	if err != nil {
		log.Fatal(err)
	}

	spec2, err := ebpf.LoadCollectionSpec("../build/print.xdp.o")
	if err != nil {
		log.Fatal(err)
	}

	coll2, err := ebpf.NewCollection(spec2)
	if err != nil {
		log.Fatal(err)
	}

	xdpProg := coll2.Programs["printer"]
	if progEgress == nil {
		log.Fatal(err)
	}

	_, err = link.AttachXDP(link.XDPOptions{
		Program:   xdpProg,
		Interface: iface2.Index,
	})

	if err != nil {
		log.Fatalf("attaching XDP program: %v", err)
	}
}
