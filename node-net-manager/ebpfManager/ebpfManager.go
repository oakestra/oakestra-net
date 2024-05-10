package ebpfManager

import (
	"NetManager/ebpfManager/ebpf/firewall"
	"NetManager/env"
	"NetManager/events"
	"log"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate ./generate_ebpf.sh

type EbpfManager struct {
	environment     env.EnvironmentManager
	firewallManager firewall.FirewallManager
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func New(env env.EnvironmentManager) EbpfManager {
	if err := rlimit.RemoveMemlock(); err != nil { // TODO ben what if multiple created?
		log.Fatal("Removing memlock:", err)
	}

	ebpfManager := EbpfManager{
		environment: env,
	}

	ebpfManager.createRestInterface(&ebpfManager.environment) //TODO ben just for dev. Remove later!

	return ebpfManager
}

func (e *EbpfManager) ActivateFirewall() {
	e.firewallManager = firewall.NewFirewallManager()

	// Attach firewall to all currently active deployments
	vethList := (e.environment).GetDeployedServicesVeths()
	for _, vethName := range vethList {
		e.firewallManager.AttachFirewall(vethName.Name)
	}

	// Attach firewall to added deployments in the future
	go func() {
		// listen to VethCreationEvents such that a firewall can be attached to new veths
		for true {
			eventChan, _ := events.GetInstance().Register(events.VethCreation, "firewall") // TODO ben "firewall" target name??
			vethCreationEvent := <-eventChan
			if payload, ok := vethCreationEvent.Payload.(events.VethCreationPayload); ok {
				e.firewallManager.AttachFirewall(payload.Name)
			}
		}
	}()
}

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
//	fw.LoadAndAttach("br0")
//}
