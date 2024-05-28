package ebpfManager

import (
	"github.com/gorilla/mux"
)

type Config struct {
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

// ModuleBase represents the attributes that every ebpf ModuleBase has. Every Implementation of an ebpf ModuleBase should
// embed the ModuleBase struct
type ModuleBase struct {
	Id       uint   `json:"id"`
	Config   Config `json:"config"`
	Priority uint   `json:"priority"`
	Active   bool   `json:"active"`
}

// ModuleInterface defines the interface of an ebpf ModuleBase that can be plugged into the NetManager at runtime
// additionally the NetManager expects a 'New() ebpf.ModuleInterface' function to be implemented.
type ModuleInterface interface {

	// GetModule returns ModuleBase struct
	GetModule() *ModuleBase

	// Configure Pass its configuration to the module. This is usually the first method to be called.
	// TODO Ben give manager functions like "register API" such that a ebpfModule gets independent of the underlaying HTTP implementation
	Configure(config Config, router *mux.Router, manager *EbpfManager)

	// NewInterfaceCreated notifies the ebpf module that a new interface (+ service) was created
	NewInterfaceCreated(ifname string) error

	// DestroyModule removes deconstructs the module and releases all ressources
	DestroyModule() error
	// TODO ben do we need to tell the module if a service got undeployed?
	// In general and ebpf function get removed when veth is removed. I think a module should be written in a way such that it can handle this

	// TODO ben does it make sense to have a destroy method for each interface?
}
