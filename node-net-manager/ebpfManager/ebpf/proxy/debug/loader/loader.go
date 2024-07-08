package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
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

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
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

	// 	serviceToInstance := coll.Maps["ip_updates"]
	//
	// 	var value IPList
	// 	key := binary.LittleEndian.Uint32(net.ParseIP("10.30.0.2").To4())
	//
	// 	value.Length = 1
	// 	value.IPs[0] = binary.LittleEndian.Uint32(net.ParseIP("10.10.0.2").To4()) //TODO ben just for debugging
	// 	// value.IPs[1] = binary.LittleEndian.Uint32(net.ParseIP("192.168.1.2").To4()) // TODO ben find out why little endian works... Does update function change LE to BE automatically?
	//
	// 	if err := serviceToInstance.Update(&key, &value, ebpf.UpdateAny); err != nil {
	// 		log.Fatalf("Error updating map: %v", err)
	// 	}

	packetBuf := coll.Maps["ip_updates"]
	reader, err := perf.NewReader(packetBuf, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}
	defer reader.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		reader.Close()
		os.Exit(0)
	}()

	fmt.Println("Listening for events..")
	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from perf map: %v\n", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			var ip = make(net.IP, 4)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &ip); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			fmt.Printf(ip.String())
		}
	}()
}
