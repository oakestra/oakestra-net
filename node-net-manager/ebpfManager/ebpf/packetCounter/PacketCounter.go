package main

import (
	"github.com/cilium/ebpf"
	"log"
)

type PacketCounter struct {
	// ingress and egress are exposed the opposite way to make it more intuitive for the user
	Ingress    uint64           `json:"egress"`
	Egress     uint64           `json:"ingress"`
	collection *ebpf.Collection `json:"-"`
}

func NewPacketCounter(collection *ebpf.Collection) PacketCounter {
	return PacketCounter{
		collection: collection,
	}
}

func (p *PacketCounter) Close() {}

func (p *PacketCounter) refreshCountsFromKernel() {
	err := p.collection.Maps["pkt_count"].Lookup(uint32(0), &p.Ingress)
	if err != nil {
		log.Fatal("map lookup for ingress count failed:", err)
	}
	err = p.collection.Maps["pkt_count"].Lookup(uint32(1), &p.Egress)
	if err != nil {
		log.Fatal("map lookup for egress count failed:", err)
	}
}
