package ebpfManager

import (
	"github.com/cilium/ebpf"
	"github.com/gorilla/mux"
)

type EventType int

const (
	AttachEvent EventType = iota
	DetachEvent
)

type Event struct {
	Type EventType
	Data interface{}
}

// AttachEventData is emitted by the ebpfManager when a module was attached to an interface.
type AttachEventData struct {
	Ifname     string           // name of the interface it was attached to
	Collection *ebpf.Collection // wrapper for FDs for in-/egress programs and maps
}

// DetachEventData is emitted by the ebpfManager when a module was detached from an interface.
type DetachEventData struct {
	Ifname string // name of the interface it was detached from
}

// ModuleBase represents the attributes that every eBPF module has.
// Every implementation of the ModuleInterface should embed the ModuleBase struct.
type ModuleBase struct {
	Id       uint         `json:"id"`
	Name     string       `json:"name"`
	Priority uint16       `json:"priority"`
	Config   interface{}  `json:"config"`
	Router   *mux.Router  `json:"-"`
	Manager  *EbpfManager `json:"-"`
}

// ModuleInterface defines the interface of an eBPF module that can be plugged into the NetManager at runtime.
// Additionally, the NetManager expects a 'New(id uint, config Config, router *mux.Router, manager *EbpfManager) ModuleInterface' function to be implemented.
// This function return a freshly initialised instance of the ebpf module.
type ModuleInterface interface {

	// OnEvent receives Events from ebpfManager
	OnEvent(event Event)

	// DestroyModule releases all resources that were allocated by the module and are not manages by the ebpf manager
	DestroyModule() error

	// TODO ben handle service undeployment or removal of veths!
}
