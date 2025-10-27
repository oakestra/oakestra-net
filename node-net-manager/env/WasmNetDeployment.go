package env

import (
	"NetManager/logger"
	"net"
)

type WasmDeploymentHandler struct {
	env *Environment
}

var wasmHandler *WasmDeploymentHandler = nil

func GetWasmNetDeployment() *WasmDeploymentHandler {
	if wasmHandler == nil {
		logger.ErrorLogger().Fatal("Wasm Handler not initialized")
	}
	return wasmHandler
}

func InitWasmDeployment(env *Environment) {
	wasmHandler = &WasmDeploymentHandler{
		env: env,
	}
}

func (h *WasmDeploymentHandler) DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error) {
	// For WASM, we currently use the same deployment as containers. If needed, this can be changed in the future.
	netHandler := GetNetDeployment(CONTAINER_RUNTIME)
	return netHandler.DeployNetwork(pid, sname, instancenumber, portmapping)
}
