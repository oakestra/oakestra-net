package main

import (
	"NetManager/ebpfManager"
	"NetManager/env"
	"log"
	"net/http"
)

type ProxyManager struct {
	base    ebpfManager.ModuleBase
	proxies map[string]*Proxy
	env     *env.EnvironmentManager
}

func New(base ebpfManager.ModuleBase) ebpfManager.ModuleInterface {
	module := ProxyManager{
		base:    base,
		proxies: make(map[string]*Proxy),
	}

	//TODO ben add custom configuration to proxy
	module.base.Router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
	}).Methods("GET")

	return &module
}

func (p *ProxyManager) OnEvent(event ebpfManager.Event) {
	switch event.Type {
	case ebpfManager.AttachEvent:
		attachEvent, ok := event.Data.(ebpfManager.AttachEventData)
		if !ok {
			log.Println("Invalid EventData")
		}
		proxy := NewProxy(attachEvent.Collection, p)
		p.proxies[attachEvent.Ifname] = &proxy
	}
}

func (p *ProxyManager) DestroyModule() error {
	for _, proxy := range p.proxies {
		proxy.Close()
	}
	p.proxies = nil
	return nil
}

func main() {}
