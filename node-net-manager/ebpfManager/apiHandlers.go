package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

type ModuleModel struct {
	ID     int         `json:"id"`
	Config ebpf.Config `json:"config"`
}

func (e *EbpfManager) createEbpf(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP POST request - /ebpf ")

	reqBody, _ := io.ReadAll(request.Body)
	var config ebpf.Config
	err := json.Unmarshal(reqBody, &config)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}
	err = e.createNewEbpf(config)
	if err != nil {
		// TODO ben can returning this error potentially be exploited?
		http.Error(writer, "Error creating Ebpf: "+err.Error(), http.StatusInternalServerError)
	}
	writer.WriteHeader(http.StatusOK)
}

func (e *EbpfManager) getEbpfModules(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP GET request - /ebpf ")
	modules := mapInterfaceToModule(e.ebpfModules) // This function should be implemented to retrieve moduleInterface data
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	jsonResponse, err := json.Marshal(modules)
	if err != nil {
		return
	}
	//update response
	writer.Write(jsonResponse)
}

func (e *EbpfManager) RegisterHandles() {
	if e.router != nil {
		e.router.HandleFunc("", e.getEbpfModules).Methods("GET")
		e.router.HandleFunc("", e.createEbpf).Methods("POST")
	}
}
