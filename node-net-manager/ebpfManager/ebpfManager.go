package ebpfManager

import (
	"NetManager/env"
	"NetManager/events"
	"errors"
	"fmt"
	"log"
	"net"
	"plugin"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/mux"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

var (
	enableEbpf  bool
	ebpfManager *EbpfManager
	once        sync.Once
)

type ModuleContainer struct {
	base         ModuleBase
	module       ModuleInterface
	vethToFilter map[string]*FilterPair
}

type FilterPair struct {
	collection *ebpf.Collection
	ingress    *netlink.BpfFilter
	egress     *netlink.BpfFilter
}

type EbpfManager struct {
	router          *mux.Router
	currentPriority uint16
	nextId          uint
	env             env.EnvironmentManager
	idToModule      map[uint]*ModuleContainer
	vethToQdisc     map[string]*netlink.GenericQdisc
}

func SetEnableEbpf(enable bool) {
	enableEbpf = enable
}

func GetEbpfManagerInstance() *EbpfManager {
	if ebpfManager == nil {
		log.Fatal("ebpfManager was used before initialisation.")
		return nil
	}
	return ebpfManager
}

func Init(router *mux.Router, env env.EnvironmentManager) {
	if !enableEbpf {
		return
	}

	once.Do(func() {
		ebpfManager = &EbpfManager{
			router:          router.PathPrefix("/ebpf").Subrouter(),
			idToModule:      make(map[uint]*ModuleContainer),
			vethToQdisc:     make(map[string]*netlink.GenericQdisc),
			env:             env,
			currentPriority: 1,
		}
		ebpfManager.RegisterApi()

		if err := rlimit.RemoveMemlock(); err != nil {
			log.Fatal("Removing memlock:", err)
		}

		// attach currently active modules if new service is deployed
		events.GetInstance().RegisterCallback(events.ServiceCreated, func(event events.CallbackEvent) {
			if payload, ok := event.Payload.(events.ServicePayload); ok {
				for id := range ebpfManager.idToModule {
					ebpfManager.loadAndAttach(id, payload.VethName) // TODO handle error
				}
			}
		})

		// detach currently active modules if service is undeployed
		events.GetInstance().RegisterCallback(events.ServiceRemoved, func(event events.CallbackEvent) {
			if payload, ok := event.Payload.(events.ServicePayload); ok {
				for id := range ebpfManager.idToModule {
					ebpfManager.detach(id, payload.VethName) // TODO handle error
				}
			}
		})
	})
}

func (e *EbpfManager) createNewModule(name string, config interface{}) (*ModuleBase, error) {
	objectPath := fmt.Sprintf("ebpfManager/ebpf/%s/%s.so", name, name)

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

	newModule, ok := sym.(func(base ModuleBase) ModuleInterface)
	if !ok {
		return nil, errors.New("the ebpf module does not export a function with the name New or it does not follow the required interface")
	}

	id := e.nextId
	e.nextId += 1
	priority := e.currentPriority
	e.currentPriority += 1

	subRouter := e.router.PathPrefix(fmt.Sprintf("/%d", id)).Subrouter()
	base := ModuleBase{
		Id:       id,
		Name:     name,
		Priority: priority,
		Config:   config,
		Router:   subRouter,
		Manager:  e,
	}
	module := newModule(base)
	e.idToModule[id] = &ModuleContainer{
		base:         base,
		module:       module,
		vethToFilter: make(map[string]*FilterPair),
	}

	for _, service := range e.env.GetDeployedServices() {
		e.loadAndAttach(id, service.Veth.Name) // TODO ben handle error
	}

	return &base, nil
}

func (e *EbpfManager) loadAndAttach(moduleId uint, ifname string) (*ebpf.Collection, error) {
	moduleContainer, exists := e.idToModule[moduleId]
	priority := moduleContainer.base.Priority
	moduleName := moduleContainer.base.Name
	path := fmt.Sprintf("ebpfManager/ebpf/%s/%s.o", moduleName, moduleName)

	if !exists || moduleContainer.module == nil {
		return nil, errors.New(fmt.Sprintf("there is no module with id %d", moduleId))
	}

	coll, err := e.loadEbpf(path)
	if err != nil {
		return nil, err
	}

	fp, err := e.attachEbpf(ifname, priority, coll)
	if err != nil {
		return nil, err
	}

	moduleContainer.vethToFilter[ifname] = fp

	event := Event{
		Type: AttachEvent,
		Data: AttachEventData{
			Ifname:     ifname,
			Collection: coll,
		},
	}
	e.emitEvent(moduleId, event)

	return coll, nil
}

func (e *EbpfManager) detach(moduleId uint, ifname string) error {
	event := Event{
		Type: DetachEvent,
		Data: DetachEventData{
			Ifname: ifname,
		},
	}
	e.emitEvent(moduleId, event)

	moduleContainer, exists := e.idToModule[moduleId]

	if !exists || moduleContainer.module == nil {
		return errors.New(fmt.Sprintf("there is no module with id %d", moduleId))
	}

	filterPair := moduleContainer.vethToFilter[ifname]

	if filterPair != nil {
		netlink.FilterDel(filterPair.ingress)
		netlink.FilterDel(filterPair.egress)
		filterPair.collection.Close()
	}

	return nil
}

func (e *EbpfManager) loadEbpf(path string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, err
	}

	return coll, nil
}

// AttachEbpf can be called by plugins in order to request an attachment of an ebpf function. This function will handle chaining
func (e *EbpfManager) attachEbpf(ifname string, priority uint16, collection *ebpf.Collection) (*FilterPair, error) {
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
			Priority:  priority,
			Handle:    netlink.MakeHandle(0x1, priority),
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
			Priority:  priority,
			Handle:    netlink.MakeHandle(0x1, priority),
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Protocol:  unix.ETH_P_ALL,
		},
		DirectAction: true,
		Name:         progEgress.String(),
		Fd:           progEgress.FD(),
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return nil, err
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		return nil, err
	}

	fp := FilterPair{
		collection: collection,
		ingress:    ingressFilter,
		egress:     egressFilter,
	}

	return &fp, nil
}

func (e *EbpfManager) emitEventToAll(event Event) {
	for _, moduleContainer := range e.idToModule {
		e.emitEvent(moduleContainer.base.Id, event)
	}
}

func (e *EbpfManager) emitEvent(moduleId uint, event Event) {
	moduleContainer, exists := e.idToModule[moduleId]
	if !exists {
		return
	}
	moduleContainer.module.OnEvent(event)
}

func (e *EbpfManager) getAllModules() []ModuleBase {
	values := make([]ModuleBase, 0, len(e.idToModule))
	for _, moduleContainer := range e.idToModule {
		values = append(values, moduleContainer.base)
	}
	return values
}

func (e *EbpfManager) getModuleById(id uint) *ModuleBase {
	if moduleContainer, exists := e.idToModule[id]; exists {
		return &moduleContainer.base
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
		moduleContainer.module.DestroyModule()

		// detach module from all veths
		for veth := range moduleContainer.vethToFilter {
			e.detach(id, veth)
		}
		delete(e.idToModule, id)

		// TODO: Sub-Router must also be removed again, but once added to the main router, a sub-routers can't be just removed again.
	}
}

func (e *EbpfManager) Close() {
	e.deleteAllModules()
	for veth, qdisc := range e.vethToQdisc {
		netlink.QdiscDel(qdisc)
		delete(e.vethToQdisc, veth)
	}
}

// TODO Not really beautiful but this function has to be exposed to make the proxy work. Open for more beautiful solutions here?
func (e *EbpfManager) GetTableEntryByServiceIP(serviceIP net.IP) []net.IP {
	tableEntries := e.env.GetTableEntryByServiceIP(serviceIP)
	nsips := make([]net.IP, len(tableEntries))
	for i, entry := range tableEntries {
		nsips[i] = entry.Nsip
	}
	return nsips
}
