package ebpfManager

import (
	"NetManager/env"
	"NetManager/events"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"plugin"
	"runtime"
)

//go:generate ./generate_ebpf.sh

type EbpfManager struct {
	router          *mux.Router
	ebpfModules     map[uint]ModuleInterface
	currentPriority uint16
	nextId          uint
	env             env.EnvironmentManager
	vethToQdisc     map[string]*netlink.GenericQdisc
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func New(router *mux.Router, env env.EnvironmentManager) EbpfManager {
	ebpfManager := EbpfManager{
		router:          router,
		ebpfModules:     make(map[uint]ModuleInterface),
		vethToQdisc:     make(map[string]*netlink.GenericQdisc),
		env:             env,
		currentPriority: 1,
	}

	ebpfManager.init()
	ebpfManager.RegisterHandles()

	return ebpfManager
}

func (e *EbpfManager) init() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// callback that notifies all currently registered ebpf modules about the creation of a new veth pair
	events.GetInstance().RegisterCallback(events.VethCreation, func(event events.CallbackEvent) {
		if payload, ok := event.Payload.(events.VethCreationPayload); ok {
			for _, module := range e.ebpfModules {
				module.NewInterfaceCreated(payload.Name)
			}
		}
	})
}

func (e *EbpfManager) createNewEbpfModule(config Config) (ModuleInterface, error) {
	objectPath := fmt.Sprintf("ebpfManager/ebpf/%s/%s.so", config.Name, config.Name)

	if !fileExists(objectPath) {
		return nil, errors.New("no ebpf module installed with this name")
	}

	// Load the plugin
	plug, err := plugin.Open(objectPath)
	if err != nil {
		return nil, errors.New("there was an error loading the ebpf module")
	}

	// every ebpfModule should support a New() method to create an instance of the module
	sym, err := plug.Lookup("New")
	if err != nil {
		return nil, errors.New("the ebpf module does not adhere to the expected interface")
	}

	newModule, ok := sym.(func(id uint, config Config, router *mux.Router, manager *EbpfManager) ModuleInterface)
	if !ok {
		return nil, errors.New("the ebpf module does not export a function with the name New or it does not follow the required interface")
	}

	id := e.nextId
	e.nextId += 1
	subRouter := e.router.PathPrefix(fmt.Sprintf("/%d", id)).Subrouter()
	module := newModule(id, config, subRouter, e)
	e.ebpfModules[id] = module

	for _, service := range e.env.GetDeployedServices() {
		module.NewInterfaceCreated(service.Veth.Name)
	}

	return module, nil
}

func (e *EbpfManager) LoadAndAttach(moduleId uint, ifname string) (*ebpf.Collection, error) {
	module := e.ebpfModules[moduleId]
	if module == nil {
		return nil, errors.New(fmt.Sprintf("there is no module with id %d", moduleId))
	}

	coll, err := e.loadEbpf(module.GetModule().Config.Name)
	// TODO ben. make the ebbf manager store one copy of all collections, such that we can close them ourselves in an emergency
	if err != nil {
		return nil, err
	}

	err = e.attachEbpf(ifname, coll)
	if err != nil {
		return nil, err
	}

	return coll, nil
}

func (e *EbpfManager) loadEbpf(moduleName string) (*ebpf.Collection, error) {
	path := fmt.Sprintf("ebpfManager/ebpf/%s/%s.o", moduleName, moduleName)
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	return coll, nil
}

// AttachEbpf can be called by plugins in order to request an attachment of an ebpf function. This function will handle chaining
func (e *EbpfManager) attachEbpf(ifname string, collection *ebpf.Collection) error {
	// TODO ben check if tcln != null ??
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return errors.New(fmt.Sprintf("Getting interface %s: %s", ifname, err))
	}

	progIngress := collection.Programs["handle_ingress"]
	if progIngress == nil {
		return errors.New("program 'handle_ingress' not found")
	}

	progEgress := collection.Programs["handle_egress"]
	if progEgress == nil {
		return errors.New("program 'handle_egress' not found")
	}

	// create qdisc for veth if there is none so far.
	if e.vethToQdisc[ifname] == nil {
		e.vethToQdisc[ifname] = &netlink.GenericQdisc{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			},
			QdiscType: "clsact",
		}
	}

	qdisc := e.vethToQdisc[ifname]
	if err := netlink.QdiscReplace(qdisc); err != nil && err.Error() != "file exists" {
		return err
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Priority:  e.currentPriority,
			Handle:    netlink.MakeHandle(0x1, 0),
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progIngress.String(),
		Fd:           progIngress.FD(),
	}

	egressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Priority:  e.currentPriority,
			Handle:    netlink.MakeHandle(0x1, 0),
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progEgress.String(),
		Fd:           progEgress.FD(),
	}

	e.currentPriority += 1

	runtime.Breakpoint()
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return err
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		return err
	}

	return nil
}

func (e EbpfManager) getAllModules() []ModuleInterface {
	values := make([]ModuleInterface, 0, len(e.ebpfModules))
	for _, module := range e.ebpfModules {
		values = append(values, module)
	}
	return values
}

func (e EbpfManager) getModuleById(id uint) ModuleInterface {
	if module, exists := e.ebpfModules[id]; exists {
		return module
	}
	return nil
}
