package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"NetManager/env"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
	"log"
	"plugin"
)

//go:generate ./generate_ebpf.sh

type EbpfManager struct {
	router *mux.Router
}

var ebpfManager EbpfManager

func init() {
	ebpfManager = EbpfManager{}
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func New(env *env.Environment, router *mux.Router) EbpfManager {
	if err := rlimit.RemoveMemlock(); err != nil { // TODO ben what if multiple created?
		log.Fatal("Removing memlock:", err)
	}

	ebpfManager := EbpfManager{
		router: router,
	}

	//ebpfManager.createRestInterface(&ebpfManager.environment) //TODO ben just for dev. Remove later!

	return ebpfManager
}

func (e *EbpfManager) createNewEbpf() {
	// Load the plugin
	plug, err := plugin.Open("ebpfManager/ebpf/firewall/firewall.so")
	if err != nil {
		panic(err)
	}

	// Lookup the symbol for NewGreeter
	sym, err := plug.Lookup("New")
	if err != nil {
		panic(err)
	}

	newModule, ok := sym.(func() ebpf.EbpfModule)
	if !ok {
		panic("Invalid function signature")
	}

	subRouter := e.router.PathPrefix("/firewall").Subrouter()

	// Use the interface
	firewall := newModule()
	firewall.Configure("test", subRouter)
	firewall.NewInterfaceCreated("test")
}

//func (e *EbpfManager) ActivateFirewall() {
//	e.firewallManager = firewall.NewFirewallManager()
//
//	// Attach firewall to all currently active deployments
//	vethList := (e.environment).GetDeployedServicesVeths()
//	for _, vethName := range vethList {
//		e.firewallManager.AttachFirewall(vethName.Name)
//	}
//
//	// TODO ben deregister callback when firewall is deactivated or object is deconstructed!
//	events.GetInstance().RegisterCallback(events.VethCreation, func(event events.CallbackEvent) {
//		if payload, ok := event.Payload.(events.VethCreationPayload); ok {
//			e.firewallManager.AttachFirewall(payload.Name)
//		}
//	})
//}

// TODO ben store for later
//func attachFirewall(c *gin.Context) {
//	var request FirewallRequest
//	if err := c.BindJSON(&request); err != nil {
//		return
//	}
//
//	networkNamespace := "ns1"
//	ifaceName := "veth-ns1-peer"
//	if request.Service == 2 {
//		networkNamespace = "ns2"
//		ifaceName = "veth-ns2-peer"
//	}
//	println(ifaceName)        // TODO ben remove
//	println(networkNamespace) // TODO ben remove

//originalNS, err := netns.Get()
//if err != nil {
//	log.Fatalf("failed to get current namespace: %v", err)
//}
//defer originalNS.Close()
//
//nsHandle, err := netns.GetFromName(networkNamespace)
//if err != nil {
//	log.Fatalf("failed to get network namespace handle: %v", err)
//}
//defer nsHandle.Close()
//
//err = netns.Set(nsHandle)
//if err != nil {
//	log.Fatalf("failed to set network namespace: %v", err)
//}
//defer netns.Set(originalNS) // Revert to the original namespace before exit.
//
//	fw := firewall.New()
//	fw.NewInterfaceCreated("br0")
//}
