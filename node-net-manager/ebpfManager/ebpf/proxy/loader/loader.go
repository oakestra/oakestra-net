package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

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
		log.Fatal("No ingress prog")
	}

	progEgress := coll.Programs["handle_egress"]
	if progEgress == nil {
		log.Fatal("No egress prog")
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

	const MAX_IPS = 32

	type IPList struct {
		Length int32
		IPs    [MAX_IPS]uint32
	}

	serviceToInstance := coll.Maps["service_to_instance"]

	var value IPList
	key := binary.LittleEndian.Uint32(net.ParseIP("10.30.0.2").To4())

	value.Length = 1
	value.IPs[0] = binary.LittleEndian.Uint32(net.ParseIP("10.10.0.2").To4()) //TODO ben just for debugging
	// value.IPs[1] = binary.LittleEndian.Uint32(net.ParseIP("192.168.1.2").To4()) // TODO ben find out why little endian works... Does update function change LE to BE automatically?

	if err := serviceToInstance.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Error updating map: %v", err)
	}
}
