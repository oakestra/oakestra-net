package ebpfManager

import (
	"NetManager/ebpfManager/ebpf"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"strconv"
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
	log.Println("Received HTTP GET request - /ebpf")
	modules := mapInterfacesToModules(e.ebpfModules) // This function should be implemented to retrieve moduleInterface data
	jsonResponse, err := json.Marshal(modules)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

func (e *EbpfManager) getEbpfModule(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP GET request - /ebpf/{id}")

	vars := mux.Vars(request)
	moduleId := vars["id"]
	id, err := strconv.Atoi(moduleId)
	if err != nil || id > len(e.ebpfModules)-1 {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "no firewall with id %s exists", moduleId)
		return
	}
	module := e.ebpfModules[id]
	jsonResponse, err := json.Marshal(module)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

func (e *EbpfManager) RegisterHandles() {
	if e.router != nil {
		e.router.HandleFunc("", e.getEbpfModules).Methods("GET")
		e.router.HandleFunc("/{id}", e.getEbpfModule).Methods("GET")
		e.router.HandleFunc("", e.createEbpf).Methods("POST")
	}
}
