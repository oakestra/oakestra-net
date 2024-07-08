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
		if proxy := NewProxy(attachEvent.Collection, p); proxy != nil {
			p.proxies[attachEvent.Ifname] = proxy
		}
		break
	case ebpfManager.UnattachEvent:
		unattachEvent, ok := event.Data.(ebpfManager.UnattachEventData)
		if !ok {
			log.Println("Invalid EventData")
		}
		proxy, exists := p.proxies[unattachEvent.Ifname]
		if exists {
			proxy.Close()
		}
		delete(p.proxies, unattachEvent.Ifname)
		break
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
