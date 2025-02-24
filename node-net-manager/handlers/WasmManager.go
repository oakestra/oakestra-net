package handlers

import (
	"NetManager/env"
	"NetManager/logger"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type WasmManager struct {
	Env           *env.Environment
	WorkerID      *string
	Configuration netConfiguration
}

var wasmManager *WasmManager

func init() {
	AvailableRuntimes[env.WASM_RUNTIME] = GetWasmManager
	wasmManager = &WasmManager{}
}

func GetWasmManager() ManagerInterface {
	return wasmManager
}

func (m *WasmManager) Register(Env *env.Environment, WorkerID *string, NodePublicAddress string, NodePublicPort string, Router *mux.Router) {
	m.Env = Env
	m.WorkerID = WorkerID
	m.Configuration = netConfiguration{NodePublicAddress: NodePublicAddress, NodePublicPort: NodePublicPort}

	env.InitWasmDeployment(Env)

	Router.HandleFunc("/wasm/deploy", m.DeployWasmNamespace).Methods("POST")
	Router.HandleFunc("/wasm/undeploy", m.DeleteWasmNamespace).Methods("POST")
}

/*
Endpoint: /wasm/deploy
Usage: Create the network environment for a WASI app using a bridged veth pair.
Method: POST
Request JSON (example):

	{
		"serviceName": "example-wasm-service",
		"portMapping": "80:8080" // example; adjust as needed
	}

Response JSON:

	{
		"serviceName": "example-wasm-service",
		"nsAddress":   "10.10.0.2"
	}
*/
func (m *WasmManager) DeployWasmNamespace(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP request - /wasm/deploy")

	if *m.WorkerID == "" {
		log.Printf("[ERROR] Node not initialized")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	reqBody, _ := io.ReadAll(request.Body)
	log.Printf("ReqBody received: %s", reqBody)
	var requestStruct ContainerDeployTask
	err := json.Unmarshal(reqBody, &requestStruct)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	requestStruct.Runtime = env.WASM_RUNTIME
	requestStruct.PublicAddr = m.Configuration.NodePublicAddress
	requestStruct.PublicPort = m.Configuration.NodePublicPort
	requestStruct.Env = m.Env
	requestStruct.Writer = &writer
	requestStruct.Finish = make(chan TaskReady, 0)

	logger.DebugLogger().Println(requestStruct)
	NewDeployTaskQueue().NewTask(&requestStruct)

	result := <-requestStruct.Finish
	if result.Err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	response := DeployResponse{
		ServiceName: requestStruct.ServiceName,
		NsAddress:   result.IP.String(),
	}

	logger.InfoLogger().Println("Response to /wasm/deploy: ", response)

	writer.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(writer).Encode(response)
	if err != nil {
		writer.WriteHeader(http.StatusInternalServerError)
	}
}

/*
Endpoint: /wasm/undeploy
Usage: Delete the network namespace and clean up the bridged veth pair for a WASM app.
Method: POST
Request JSON:

	{
		serviceName:string #name used to register the service in the first place
		instance:int
	}

Response: 200 OK or an error code.
*/
func (m *WasmManager) DeleteWasmNamespace(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP request - /wasm/undeploy")

	if *m.WorkerID == "" {
		log.Printf("[ERROR] Node not initialized")
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	reqBody, _ := io.ReadAll(request.Body)
	var requestStruct undeployRequest
	err := json.Unmarshal(reqBody, &requestStruct)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	log.Println("WASM undeploy request:", requestStruct)
	m.Env.DeleteWasmNamespace(requestStruct.Servicename, requestStruct.Instancenumber)
	writer.WriteHeader(http.StatusOK)
}
