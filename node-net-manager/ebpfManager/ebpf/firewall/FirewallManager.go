package main

import (
	"NetManager/ebpfManager"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
)

type FirewallManager struct {
	base ebpfManager.ModuleBase
	// maps interface name to firewall
	firewalls map[string]*Firewall
	manager   *ebpfManager.EbpfManager
}

func New(base ebpfManager.ModuleBase) ebpfManager.ModuleInterface {
	module := FirewallManager{
		base:      base,
		firewalls: make(map[string]*Firewall),
	}
	module.Configure()

	return &module
}

func (f *FirewallManager) Configure() {
	f.base.Router.HandleFunc("/rule", func(writer http.ResponseWriter, request *http.Request) {
		type FirewallRequest struct {
			Proto   string `json:"proto"`
			SrcIp   string `json:"srcIp"`
			DstIp   string `json:"dstIp"`
			SrcPort uint16 `json:"scrPort"`
			DstPort uint16 `json:"dstPort"`
		}

		reqBody, _ := io.ReadAll(request.Body)
		var firewallRequest FirewallRequest
		err := json.Unmarshal(reqBody, &firewallRequest)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
		}

		src := net.ParseIP(firewallRequest.SrcIp).To4()
		dst := net.ParseIP(firewallRequest.DstIp).To4()

		proto := TCP
		if request.Proto == "UDP" {
			proto = UDP
		} else if request.Proto == "ICMP" {
			proto = ICMP
		}

		f.AddFirewallRule(src, dst, proto, firewallRequest.SrcPort, firewallRequest.DstPort)

		writer.WriteHeader(http.StatusOK)
	})
}

func (f *FirewallManager) OnEvent(event ebpfManager.Event) {
	switch event.Type {
	case ebpfManager.AttachEvent:
		attachEvent, ok := event.Data.(ebpfManager.AttachEventData)
		if !ok {
			log.Println("Invalid EventData")
		}
		fw := NewFirewall(attachEvent.Collection)
		f.firewalls[attachEvent.Ifname] = &fw
	}
}

func (f *FirewallManager) DestroyModule() error {
	f.firewalls = nil
	return nil
}

func (f *FirewallManager) AddFirewallRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) {
	for _, fw := range f.firewalls {
		fw.AddRule(srcIp, dstIp, proto, srcPort, dstPort)
	}
}

func main() {}
