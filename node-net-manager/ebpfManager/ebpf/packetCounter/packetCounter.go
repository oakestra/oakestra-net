package main

import (
	"log"
	"os"
	"os/signal"
	"time"
)

type PacketCounter struct {
	packetCounterObjects packetCounterObjects
	id                   string
}

func NewPacketCounter(id string) PacketCounter {
	return PacketCounter{
		id: id,
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
	go p.printPacketCount()
}

func (p *PacketCounter) printPacketCount() {
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var countIngress uint64
			var countEgress uint64
			err := p.packetCounterObjects.PktCount.Lookup(uint32(0), &countIngress)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			err = p.packetCounterObjects.PktCount.Lookup(uint32(0), &countEgress)
			if err != nil {
				log.Fatal("Map lookup:", err)
			}
			log.Printf("%s: #Ingress %d, #Egress %d", p.id, countIngress, countEgress)
		case <-stop:
			log.Print("Received signal, exiting..")
			return
		}
	}
}
