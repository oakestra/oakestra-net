package main

import (
	"NetManager/ebpfManager"
	"encoding/json"
	"log"
	"net/http"
)

type PacketCounterManager struct {
	base     ebpfManager.ModuleBase
	counters map[string]*PacketCounter // maps ifname to *packetCounter
}

func New(base ebpfManager.ModuleBase) ebpfManager.ModuleInterface {
	module := PacketCounterManager{
		base:     base,
		counters: make(map[string]*PacketCounter),
	}

	module.base.Router.HandleFunc("/counts", func(writer http.ResponseWriter, request *http.Request) {
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

func (p *PacketCounterManager) OnEvent(event ebpfManager.Event) {
	switch event.Type {
	case ebpfManager.AttachEvent:
		attachEvent, ok := event.Data.(ebpfManager.AttachEventData)
		if !ok {
			log.Println("Invalid EventData")
		}
		counter := NewPacketCounter(attachEvent.Collection)
		p.counters[attachEvent.Ifname] = &counter
	case ebpfManager.DetachEvent:
		unattachEvent, ok := event.Data.(ebpfManager.DetachEventData)
		if !ok {
			log.Println("Invalid EventData")
		}
		counter, exists := p.counters[unattachEvent.Ifname]
		if exists {
			counter.Close()
		}
		delete(p.counters, unattachEvent.Ifname)
		break
	}
}

func (p *PacketCounterManager) DestroyModule() error {
	p.counters = nil
	return nil
}

func (p *PacketCounterManager) RefreshAllCounters() {
	for _, counter := range p.counters {
		counter.refreshCountsFromKernel()
	}
}
