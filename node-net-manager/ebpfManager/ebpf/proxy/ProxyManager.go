package main

import (
	"NetManager/ebpfManager"
	"github.com/gorilla/mux"
	"net/http"
)

type ProxyManager struct {
	ebpfManager.ModuleBase
	proxies map[string]*Proxy
	manager *ebpfManager.EbpfManager
}

func New(id uint, config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) ebpfManager.ModuleInterface {
	module := ProxyManager{
		proxies: make(map[string]*Proxy),
	}
	module.ModuleBase.Id = id
	module.ModuleBase.Config = config
	module.manager = manager

	//TODO ben handler functions
	router.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
	}).Methods("GET")

	return &module
}

func (p *ProxyManager) GetModuleBase() *ebpfManager.ModuleBase {
	return &p.ModuleBase
}

func (p *ProxyManager) Configure(config ebpfManager.Config, router *mux.Router, manager *ebpfManager.EbpfManager) {
	p.ModuleBase.Config = config
	p.manager = manager
	router.HandleFunc("/rule", func(writer http.ResponseWriter, request *http.Request) {
		type ProxyRequest struct {
			Proto   string `json:"proto"`
			SrcIp   string `json:"srcIp"`
			DstIp   string `json:"dstIp"`
			SrcPort uint16 `json:"scrPort"`
			DstPort uint16 `json:"dstPort"`
		}
		writer.WriteHeader(http.StatusOK)
	})
}

func (p *ProxyManager) NewInterfaceCreated(ifname string) error {
	coll, _ := p.manager.LoadAndAttach(p.Id, ifname)
	proxy := NewProxy(coll)
	p.proxies[ifname] = &proxy
	return nil
}

func (p *ProxyManager) DestroyModule() error {
	for _, proxy := range p.proxies {
		proxy.Close()
	}
	p.proxies = nil
	return nil
}

func main() {}
