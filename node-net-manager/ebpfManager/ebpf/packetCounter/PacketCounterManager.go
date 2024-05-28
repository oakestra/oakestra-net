package main

import (
	"NetManager/ebpfManager"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go packetCounter packetCounter.c

type PacketCounterManager struct {
	ebpfManager.ModuleBase
	counters map[string]PacketCounter
	manager  *ebpfManager.EbpfManager
}

func New() ebpfManager.ModuleInterface {
	return &PacketCounterManager{
		counters: make(map[string]PacketCounter),
	}
}

func (p *PacketCounterManager) GetModule() *ebpfManager.ModuleBase {
	return &p.ModuleBase
}

func (p *PacketCounterManager) Configure(config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) {
	p.ModuleBase.Config = config
	p.manager = manager
	router.HandleFunc("/rule", func(writer http.ResponseWriter, request *http.Request) {

	})
}

// TODO ben instead of creating one function per Event, pass a Event channel to the module that emits all events
func (p *PacketCounterManager) NewInterfaceCreated(ifname string) error {
	fmt.Printf("TODO ben 1\n")
	pc := NewPacketCounter(ifname)
	fmt.Printf("TODO ben 2\n")
	pc.Load()
	fmt.Printf("TODO ben 3\n")

	fdIn := uint32(pc.packetCounterObjects.HandleIngress.FD())
	fdEg := uint32(pc.packetCounterObjects.HandleEgress.FD())
	fmt.Printf("TODO ben %d\n", pc.packetCounterObjects.packetCounterPrograms.HandleIngress.FD())
	p.manager.RequestAttach(ifname, fdIn, fdEg)
	p.counters[ifname] = pc
	return nil
}

func (p *PacketCounterManager) DestroyModule() error {
	for ifname := range p.counters {
		// TODO ben iplement destroy
		fmt.Printf("Destroy Packetcounter on: %s\n", ifname)
	}
	return nil
}
