package server

import (
	"NetManager/ebpfManager"
	"NetManager/env"
	"NetManager/handlers"
	"NetManager/logger"
	"NetManager/mqtt"
	"NetManager/proxy"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type undeployRequest struct {
	Servicename    string `json:"serviceName"`
	Instancenumber int    `json:"instanceNumber"`
}

type registerRequest struct {
	ClientID string `json:"client_id"`
}

type DeployResponse struct {
	ServiceName string `json:"serviceName"`
	NsAddress   string `json:"nsAddress"`
}

type netConfiguration struct {
	NodePublicAddress string
	NodePublicPort    string
	ClusterUrl        string
	ClusterMqttPort   string
}

func HandleRequests(port int) {
	netRouter := mux.NewRouter().StrictSlash(true)
	netRouter.HandleFunc("/register", register).Methods("POST")

	handlers.RegisterAllManagers(&Env, &WorkerID, Configuration.NodePublicAddress, Configuration.NodePublicPort, netRouter)

	ebpfManager.Init(netRouter, &Env)

	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), netRouter))
}

var (
	Env           env.Environment
	Proxy         proxy.GoProxyTunnel
	WorkerID      string
	Configuration netConfiguration
)

/*
Endpoint: /register
Usage: used to initialize the Network manager. The network manager must know his local subnetwork.
Method: POST
Request Json:

	{
		client_id:string # id of the worker node
	}

Response: 200 or Failure code
*/
func register(writer http.ResponseWriter, request *http.Request) {
	logger.InfoLogger().Println("Received registration request, registering the NetManager to the Cluster")

	reqBody, _ := io.ReadAll(request.Body)
	var requestStruct registerRequest
	err := json.Unmarshal(reqBody, &requestStruct)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}
	log.Println(requestStruct)

	// drop the request if the node is already initialized
	if WorkerID != "" {
		if WorkerID == requestStruct.ClientID {
			logger.InfoLogger().Printf("Node already initialized")
			writer.WriteHeader(http.StatusOK)
		} else {
			logger.InfoLogger().Printf("Attempting to re-initialize a node with a different worker ID")
			writer.WriteHeader(http.StatusBadRequest)
		}
		return
	}

	WorkerID = requestStruct.ClientID

	// initialize mqtt connection to the broker
	mqtt.InitNetMqttClient(requestStruct.ClientID, Configuration.ClusterUrl, Configuration.ClusterMqttPort)

	// initialize the proxy tunnel
	Proxy = proxy.New()
	Proxy.Listen()

	// initialize the Env Manager
	Env = *env.NewEnvironmentClusterConfigured(Proxy.HostTUNDeviceName)

	Proxy.SetEnvironment(&Env)

	logger.InfoLogger().Printf("NetManager is now running 🟢")
	writer.WriteHeader(http.StatusOK)
}
