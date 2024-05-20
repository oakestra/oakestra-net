package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"errors"
	"fmt"
	"log"
	"plugin"

	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
)

//go:generate ./generate_ebpf.sh

type EbpfManager struct {
	router      *mux.Router
	ebpfModules []ebpf.ModuleInterface
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func New(router *mux.Router) EbpfManager {
	if err := rlimit.RemoveMemlock(); err != nil { // TODO ben what if multiple created?
		log.Fatal("Removing memlock:", err)
	}

	ebpfManager := EbpfManager{
		router:      router,
		ebpfModules: make([]ebpf.ModuleInterface, 0),
	}

	ebpfManager.RegisterHandles()

	return ebpfManager
}

func (e *EbpfManager) createNewEbpf(config ebpf.Config) error {
	objectPath := fmt.Sprintf("ebpfManager/ebpf/%s/%s.so", config.Name, config.Name)

	if !fileExists(objectPath) {
		// todo return err
		return errors.New("no ebpf mpodule installed with this name")
	}

	// Load the plugin
	plug, err := plugin.Open(objectPath)
	if err != nil {
		return errors.New("there was an error loading the ebpf module")
	}

	// every ebpfModule should support a New() method to create an instance of the module
	sym, err := plug.Lookup("New")
	if err != nil {
		// todo return err
		return errors.New("the ebpf module does not adhear to the expected interface")
	}

	newModule, ok := sym.(func() ebpf.ModuleInterface)
	if !ok {
		return errors.New("the ebpf module does not adhear to the expected interface")
	}

	subRouter := e.router.PathPrefix(fmt.Sprintf("/%s", config.Name)).Subrouter()

	// Use the interface
	firewall := newModule()
	firewall.Configure(config, subRouter)
	e.ebpfModules = append(e.ebpfModules, firewall)
	// firewall.NewInterfaceCreated("test")
	return nil
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
