package main

import (
	"NetManager/ebpfManager"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go packetCounter packetCounter.c

type PacketCounterManager struct {
	ebpfManager.ModuleBase
	counters map[string]*PacketCounter
	manager  *ebpfManager.EbpfManager
}

func New(id uint, config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) ebpfManager.ModuleInterface {
	module := PacketCounterManager{
		counters: make(map[string]*PacketCounter),
	}
	module.ModuleBase.Id = id

	module.ModuleBase.Config = config
	module.manager = manager
	router.HandleFunc("/counts", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		module.RefreshAllCounters()
		jsonResponse, err := json.Marshal(module.counters)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		writer.Write(jsonResponse)
	}).Methods("GET")

	return &module
}

func (p *PacketCounterManager) GetModule() *ebpfManager.ModuleBase {
	return &p.ModuleBase
}

// TODO ben instead of creating one function per Event, pass a Event channel to the module that emits all events
func (p *PacketCounterManager) NewInterfaceCreated(ifname string) error {
	coll, _ := p.manager.LoadAndAttach(p.Id, ifname) // TODO ben handle error
	pc := NewPacketCounter(coll)
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
