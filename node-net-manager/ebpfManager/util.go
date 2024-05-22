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

func mapInterfaceToModule(modules []ebpf.ModuleInterface) []ModuleModel {
	mapped := make([]ModuleModel, len(modules))
	mapper := func(index int, module ebpf.ModuleInterface) ModuleModel {
		model := ModuleModel{}
		model.ID = index // id is just the index in the list
		return model
	}
	for i, module := range modules {
		mapped[i] = mapper(i, module)
	}
	return mapped
}
