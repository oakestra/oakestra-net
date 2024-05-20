package main

import (
	"NetManager/ebpfManager/ebpf"
	"encoding/json"
	"github.com/gorilla/mux"
	"io"
	"net"
	"net/http"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go firewall firewall.c

type FirewallManager struct {
	ebpf.Module
	// maps interface name to firewall
	firewalls map[string]Firewall
}

func (e *FirewallManager) AddFirewallRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) {
	for _, fw := range e.firewalls {
		fw.AddRule(srcIp, dstIp, proto, srcPort, dstPort)
	}
}

func (e *FirewallManager) removeFirewall(ifname string) {
	if fw, exists := e.firewalls[ifname]; exists {
		fw.Close()
		delete(e.firewalls, ifname)
	}
}

func (e *FirewallManager) Configure(config ebpf.Config, router *mux.Router) {
	router.HandleFunc("/rule", func(writer http.ResponseWriter, request *http.Request) {
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

		// TODO ben default is always TCP. Does that make sense? + can I add this parsing step to JSON serialiser?
		proto := TCP
		if request.Proto == "UDP" {
			proto = UDP
		} else if request.Proto == "ICMP" {
			proto = ICMP
		}

		e.AddFirewallRule(src, dst, proto, firewallRequest.SrcPort, firewallRequest.DstPort)

		writer.WriteHeader(http.StatusOK)
	})
}

func (e *FirewallManager) NewInterfaceCreated(ifname string) error {
	firewall := NewFirewall()
	firewall.Load()
	firewall.AttachTC(ifname)
	e.firewalls[ifname] = firewall
	return nil
}

func (e *FirewallManager) DestroyModule() error {
	for ifname := range e.firewalls {
		e.removeFirewall(ifname)
	}
	return nil
}

func New() ebpf.ModuleInterface {
	return &FirewallManager{
		Module:    ebpf.Module{},
		firewalls: make(map[string]Firewall),
	}
}

func main() {}
