package main

import (
	"NetManager/ebpfManager"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go packetCounter packetCounter.c

type Counts struct {
	ingress int
	egress  int
}

type PacketCounterManager struct {
	ebpfManager.ModuleBase
	counters map[string]*PacketCounter
	manager  *ebpfManager.EbpfManager
}

func New() ebpfManager.ModuleInterface {
	return &PacketCounterManager{
		counters: make(map[string]*PacketCounter),
	}
}

func (p *PacketCounterManager) GetModule() *ebpfManager.ModuleBase {
	return &p.ModuleBase
}

func (p *PacketCounterManager) Configure(config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) {
	p.ModuleBase.Config = config
	p.manager = manager
	router.HandleFunc("/counts", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		p.RefreshAllCounters()
		jsonResponse, err := json.Marshal(p.counters)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		writer.Write(jsonResponse)
	}).Methods("GET")
}

// TODO ben instead of creating one function per Event, pass a Event channel to the module that emits all events
func (p *PacketCounterManager) NewInterfaceCreated(ifname string) error {
	pc := NewPacketCounter(ifname)
	pc.Load()
	fdIn := uint32(pc.packetCounterObjects.HandleIngress.FD())
	fdEg := uint32(pc.packetCounterObjects.HandleEgress.FD())
	p.manager.RequestAttach(ifname, fdIn, fdEg)
	p.counters[ifname] = &pc
	return nil
}

func (p *PacketCounterManager) DestroyModule() error {
	for ifname := range p.counters {
		// TODO ben iplement destroy
		fmt.Printf("Destroy Packetcounter on: %s\n", ifname)
	}
	return nil
}

func (p *PacketCounterManager) RefreshAllCounters() {
	for _, counter := range p.counters {
		counter.refreshCountsFromKernel()
	}
}
