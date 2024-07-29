package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"log"
	"net"
)

type Firewall struct {
	collection *ebpf.Collection `json:"-"`
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

func NewFirewall(collection *ebpf.Collection) Firewall {
	return Firewall{
		collection: collection,
	}
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
	err := e.collection.Maps["fw_rules"].Put(rule, value)
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
	err := e.collection.Maps["fw_rules"].Delete(rule)
	if err != nil {
		return err
	}
	return nil
}

func (e *Firewall) Close() {}
