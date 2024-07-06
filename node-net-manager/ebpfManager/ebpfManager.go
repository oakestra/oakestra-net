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
)

//go:generate ./generate_ebpf.sh

type ModuleContainer struct {
	module      ModuleInterface
	filters     []FilterPair
	collections []*ebpf.Collection
}

type FilterPair struct {
	ingress *netlink.BpfFilter
	egress  *netlink.BpfFilter
}

type EbpfManager struct {
	router          *mux.Router
	currentPriority uint16
	nextId          uint
	env             env.EnvironmentManager
	idToModule      map[uint]*ModuleContainer
	vethToQdisc     map[string]*netlink.GenericQdisc
}

type FirewallRequest struct {
	Proto   string `json:"proto"`
	SrcIp   string `json:"srcIp"`
	DstIp   string `json:"dstIp"`
	SrcPort uint16 `json:"scrPort"`
	DstPort uint16 `json:"dstPort"`
}

func (m ModuleBase) close() {

}

func New(router *mux.Router, env env.EnvironmentManager) EbpfManager {
	ebpfManager := EbpfManager{
		router:          router,
		idToModule:      make(map[uint]*ModuleContainer),
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
			for _, moduleContainer := range e.idToModule {
				moduleContainer.module.NewInterfaceCreated(payload.Name)
			}
		}
	})
}

// TODO ben most likely we wnat to return TC_ACT_PIPE instead of UNSPEC!! Investigate further
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
	e.idToModule[id] = &ModuleContainer{
		module:  module,
		filters: make([]FilterPair, 0),
	}

	for _, service := range e.env.GetDeployedServices() {
		module.NewInterfaceCreated(service.Veth.Name)
	}

	return module, nil
}

func (e *EbpfManager) LoadAndAttach(moduleId uint, ifname string) (*ebpf.Collection, error) {
	moduleContainer, exists := e.idToModule[moduleId]

	if !exists || moduleContainer.module == nil {
		return nil, errors.New(fmt.Sprintf("there is no module with id %d", moduleId))
	}

	coll, err := e.loadEbpf(moduleContainer.module.GetModuleBase().Config.Name)
	if err != nil {
		return nil, err
	}

	fp, err := e.attachEbpf(ifname, coll)
	if err != nil {
		return nil, err
	}

	moduleContainer.collections = append(moduleContainer.collections, coll)
	moduleContainer.filters = append(moduleContainer.filters, *fp)

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
func (e *EbpfManager) attachEbpf(ifname string, collection *ebpf.Collection) (*FilterPair, error) {
	// TODO ben check if tcln != null ??
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Getting interface %s: %s", ifname, err))
	}

	progIngress := collection.Programs["handle_ingress"]
	if progIngress == nil {
		return nil, errors.New("program 'handle_ingress' not found")
	}

	progEgress := collection.Programs["handle_egress"]
	if progEgress == nil {
		return nil, errors.New("program 'handle_egress' not found")
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
		return nil, err
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: iface.Index,
			Priority:  e.currentPriority,
			Handle:    netlink.MakeHandle(0x1, e.currentPriority),
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
			Handle:    netlink.MakeHandle(0x1, e.currentPriority),
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progEgress.String(),
		Fd:           progEgress.FD(),
	}

	e.currentPriority += 1

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return nil, err
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		return nil, err
	}

	fp := FilterPair{
		ingress: ingressFilter,
		egress:  egressFilter,
	}

	return &fp, nil
}

func (e *EbpfManager) getAllModules() []ModuleInterface {
	values := make([]ModuleInterface, 0, len(e.idToModule))
	for _, moduleContainer := range e.idToModule {
		values = append(values, moduleContainer.module)
	}
	return values
}

func (e *EbpfManager) getModuleById(id uint) ModuleInterface {
	if moduleContainer, exists := e.idToModule[id]; exists {
		return moduleContainer.module
	}
	return nil
}

func (e *EbpfManager) deleteAllModules() {
	for id := range e.idToModule {
		e.deleteModuleById(id)
	}
}

func (e *EbpfManager) deleteModuleById(id uint) {
	if moduleContainer, exists := e.idToModule[id]; exists {
		moduleContainer.module.GetModuleBase().close()
		moduleContainer.module.DestroyModule()

		// remove ebpf filters from ethernet ports if still attached
		for _, fp := range moduleContainer.filters {
			netlink.FilterDel(fp.ingress)
			netlink.FilterDel(fp.egress)
		}

		// unload ebpf program and map if still in kernel
		for _, coll := range moduleContainer.collections {
			coll.Close()
		}

		delete(e.idToModule, id)

		// TODO ben: you can't delete handlers in gorilla mux after they were created! Find work around!
	}
}

// TODO Not really beautiful but this function has to be exposed to make the proxy work. Maybe someone has better suggestion?
func (e *EbpfManager) GetTableEntryByServiceIP(serviceIP net.IP) []net.IP {
	tableEntries := e.env.GetTableEntryByServiceIP(serviceIP)
	nsips := make([]net.IP, len(tableEntries))
	for i, entry := range tableEntries {
		nsips[i] = entry.Nsip
	}
	return nsips
}

func (e *EbpfManager) Close() {
	e.deleteAllModules()
	for veth, qdisc := range e.vethToQdisc {
		netlink.QdiscDel(qdisc)
		delete(e.vethToQdisc, veth)
	}
}
