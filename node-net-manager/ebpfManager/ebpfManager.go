package ebpfManager

import (
	"NetManager/env"
	"NetManager/events"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/gorilla/mux"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"plugin"
)

//go:generate ./generate_ebpf.sh

type EbpfManager struct {
	router          *mux.Router
	ebpfModules     []ModuleInterface // TODO ben maybe its better to use a list that is sorted by priorities?
	Tcnl            tc.Tc
	Qdisc           tc.Object
	currentPriority int
	nextId          uint
	env             env.EnvironmentManager
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func New(router *mux.Router, env env.EnvironmentManager) EbpfManager {
	if err := rlimit.RemoveMemlock(); err != nil { // TODO ben what if multiple created?
		log.Fatal("Removing memlock:", err)
	}

	ebpfManager := EbpfManager{
		router:      router,
		ebpfModules: make([]ModuleInterface, 0),
		env:         env,
	}

	ebpfManager.init()
	ebpfManager.RegisterHandles()

	return ebpfManager
}

func (e *EbpfManager) init() {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not open rtnetlink socket: %v\n", err)
		return // TODO ben return error
	}
	e.Tcnl = *tcnl

	// callback that notifies all currently registered ebpf modules about the creation of a new veth pair
	events.GetInstance().RegisterCallback(events.VethCreation, func(event events.CallbackEvent) {
		if payload, ok := event.Payload.(events.VethCreationPayload); ok {
			for _, module := range e.ebpfModules {
				module.NewInterfaceCreated(payload.Name)
			}
		}
	})
}

func (e *EbpfManager) createNewEbpf(config Config) error {
	objectPath := fmt.Sprintf("ebpfManager/ebpf/%s/%s.so", config.Name, config.Name)

	if !fileExists(objectPath) {
		// todo ben return err
		return errors.New("no ebpf module installed with this name")
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
		return errors.New("the ebpf module does not adhere to the expected interface")
	}

	newModule, ok := sym.(func() ModuleInterface)
	if !ok {
		return errors.New("the ebpf module does not adhere to the expected interface")
	}

	subRouter := e.router.PathPrefix(fmt.Sprintf("/%s", config.Name)).Subrouter()

	// Use the interface
	module := newModule()
	module.Configure(config, subRouter, e)

	base := module.GetModule()
	base.Id = e.nextId
	e.ebpfModules = append(e.ebpfModules, module)
	e.nextId += 1

	return nil
}

// RequestAttach can be called by plugins in order to request an attachment of an ebpf function. This function will handle chaining
func (e *EbpfManager) RequestAttach(ifname string, fdIngress uint32, fdEgress uint32) error {
	// TODO ben check if tcln != null ??
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}
	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
			Info:    0,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	e.Qdisc = qdisc
	if err := e.Tcnl.Qdisc().Add(&qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "could not assign clsact to %s: %v\n", ifname, err)
		return nil
	}

	flagsIn := uint32(0x1)
	ingressFilter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinIngress),
			Info:    0x300, // uint32(e.currentPriority << 16),
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdIngress,
				Flags: &flagsIn,
			},
		},
	}

	flagsEg := uint32(0x1)
	egressFilter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(iface.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    0x300,
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    &fdEgress,
				Flags: &flagsEg,
			},
		},
	}
	e.currentPriority += 1
	if err := e.Tcnl.Filter().Replace(&ingressFilter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach ingress filter for eBPF program: %v\n", err)
		return nil
	}

	if err := e.Tcnl.Filter().Replace(&egressFilter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach egress filter for eBPF program: %v\n", err)
		return nil
	}
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
