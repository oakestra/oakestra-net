package ebpfManager

type Config struct {
	Name   string      `json:"name"`
	Config interface{} `json:"config"`
}

// ModuleBase represents the attributes that every eBPF module has.
// Every implementation of the ModuleInterface should embed the ModuleBase struct.
type ModuleBase struct {
	Id       uint   `json:"id"`
	Config   Config `json:"config"`
	Priority uint   `json:"priority"`
	Active   bool   `json:"active"`
}

// ModuleInterface defines the interface of an eBPF module that can be plugged into the NetManager at runtime.
// Additionally, the NetManager expects a 'New(id uint, config Config, router *mux.Router, manager *EbpfManager) ModuleInterface' function to be implemented.
// This function return a freshly initialised instance of the ebpf module.
type ModuleInterface interface {

	// GetModule returns ModuleBase struct
	GetModuleBase() *ModuleBase

	// NewInterfaceCreated notifies the ebpf module that a new interface (+ service) was created
	NewInterfaceCreated(ifname string) error

	// DestroyModule releases all ressources that were allocated by the module and are not manages by the ebpf manager
	DestroyModule() error

	// TODO ben handle service undeployment or removal of veths!
}
