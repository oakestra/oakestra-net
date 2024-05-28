package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"os"
)

// TODO ben is this the best place to place util functions like this?
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		// Might be other errors like permission denied
		return false
	}
	return !info.IsDir() // Ensure the path is not a directory
}

func mapInterfacesToModules(modules []ebpf.ModuleInterface) []ebpf.ModuleBase {
	mapped := make([]ebpf.ModuleBase, len(modules))
	for i, module := range modules {
		mapped[i] = *module.GetModule()
	}
	return mapped
}

func getModuleBaseById(modules []ebpf.ModuleInterface, id uint) *ebpf.ModuleBase {
	for _, module := range modules {
		if module.GetModule().Id == id {
			return module.GetModule()
		}
	}
	return nil
}
