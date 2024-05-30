package main

import (
	"log"
)

type PacketCounter struct {
	Ingress              uint64               `json:"ingress"`
	Egress               uint64               `json:"egress"`
	packetCounterObjects packetCounterObjects `json:"-"`
	id                   string               `json:"-"`
}

func NewPacketCounter(id string) PacketCounter {
	return PacketCounter{
		id: id,
	}
}

func (p *PacketCounter) refreshCountsFromKernel() {
	err := p.packetCounterObjects.PktCount.Lookup(uint32(0), &p.Ingress)
	if err != nil {
		log.Fatal("map lookup for ingress count failed:", err)
	}
	err = p.packetCounterObjects.PktCount.Lookup(uint32(1), &p.Egress)
	if err != nil {
		log.Fatal("map lookup for egress count failed:", err)
	}
}

func (p *PacketCounter) Load() {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs packetCounterObjects
	if err := loadPacketCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	p.packetCounterObjects = objs
	// TODO ben implement killing thread when destroying overall ebpf module
}
