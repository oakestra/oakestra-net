package firewall

import (
	"encoding/binary"
	"fmt"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go firewall firewall.c

var nextId = 0

type Firewall struct {
	Id        int
	FwObjects firewallObjects
	Tcnl      *tc.Tc
	Qdisc     tc.Object
}

func NewFirewall() Firewall {
	fw := Firewall{
		Id: nextId,
	}
	nextId++
	return fw
}

func (e *Firewall) Close() error {
	// TODO ben currently its returning with first error. Try to close as much as possible, even after an error occured
	err := e.FwObjects.Close()
	if err != nil {
		return err
	}

	e.Tcnl.Qdisc().Delete(&e.Qdisc)

	err = e.Tcnl.Close()
	if err != nil {
		return err
	}

	return nil
}

type Protocol uint32

const (
	ICMP Protocol = 0x01
	TCP  Protocol = 0x06
	UDP  Protocol = 0x11
)

type FirewallRule struct {
	srcIp   uint32
	dstIp   uint32
	proto   uint8
	padding [3]uint8
	srcPort uint16
	dstPort uint16
}

func (e *Firewall) AddRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) error {
	rule := FirewallRule{
		srcIp:   binary.LittleEndian.Uint32(srcIp.To4()),
		dstIp:   binary.LittleEndian.Uint32(dstIp.To4()),
		proto:   uint8(proto),
		padding: [3]byte{0x00, 0x00, 0x00},
		srcPort: srcPort,
		dstPort: dstPort,
	}
	value := uint8(1)
	err := e.FwObjects.FwRules.Put(rule, value)
	if err != nil {
		log.Fatalf("Error %s", err)
		return err
	}
	return nil
}

func (e *Firewall) DeleteRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) error {
	rule := FirewallRule{
		srcIp:   binary.LittleEndian.Uint32(srcIp.To4()),
		dstIp:   binary.LittleEndian.Uint32(dstIp.To4()),
		proto:   uint8(proto),
		srcPort: srcPort,
		dstPort: dstPort,
	}
	err := e.FwObjects.FwRules.Delete(rule)
	if err != nil {
		return err
	}
	return nil
}

func (e *Firewall) Load() {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	e.FwObjects = objs
}

//// TODO ben remove if TC attach works
//func (e *Firewall) Attach(ifname string) {
//	iface, err := net.InterfaceByName(ifname)
//	if err != nil {
//		log.Fatalf("Getting interface %s: %s", ifname, err)
//	}
//
//	// Attach count_packets to the network interface.
//	_, err = link.AttachXDP(link.XDPOptions{
//		Program:   e.FwObjects.Firewall,
//		Interface: iface.Index,
//	})
//	if err != nil {
//		log.Fatal("Attaching XDP:", err)
//	}
//}

func (e *Firewall) AttachTC(ifname string) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return
	}
	e.Tcnl = tcnl

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	e.Qdisc = qdisc

	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", ifname, err)
		return
	}

	fdIn := uint32(e.FwObjects.HandleIngress.FD())
	flagsIn := uint32(0x1)
	ingressFilter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdIn,
				Flags: &flagsIn,
			},
		},
	}

	fdEg := uint32(e.FwObjects.HandleEgress.FD())
	flagsEg := uint32(0x1)
	egressFilter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdEg,
				Flags: &flagsEg,
			},
		},
	}

	if err := tcnl.Filter().Add(&ingressFilter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach ingress filter for eBPF program: %v\n", err)
		return
	}

	if err := tcnl.Filter().Add(&egressFilter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach egress filter for eBPF program: %v\n", err)
		return
	}
}
