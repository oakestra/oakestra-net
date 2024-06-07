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

	// DestroyModule removes deconstructs the module and releases all resources
	DestroyModule() error
	// TODO ben do we need to tell the module if a service got undeployed?
	// In general and ebpf function get removed when veth is removed. I think a module should be written in a way such that it can handle this

	// TODO ben does it make sense to have a destroy method for each interface?
}
