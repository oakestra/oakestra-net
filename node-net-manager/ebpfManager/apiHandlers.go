package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

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

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	jsonResponse, err := json.Marshal(e.ebpfModules)
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
