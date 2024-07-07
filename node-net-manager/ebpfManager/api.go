package ebpfManager

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"strconv"
)

func (e *EbpfManager) apiCreateNewModule(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP POST request - /ebpf ")

	reqBody, _ := io.ReadAll(request.Body)
	var config Config
	err := json.Unmarshal(reqBody, &config)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}
	newModule, err := e.createNewModule(config)
	if err != nil {
		// TODO ben can returning this error potentially be exploited?
		http.Error(writer, "Error creating Ebpf: "+err.Error(), http.StatusInternalServerError)
	}
	jsonResponse, err := json.Marshal(newModule)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

func (e *EbpfManager) apiGetAllModules(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP GET request - /ebpf")
	modules := e.getAllModules()
	jsonResponse, err := json.Marshal(modules)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	writer.Write(jsonResponse)
}

func (e *EbpfManager) apiGetModuleById(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP GET request - /ebpf/{id}")

	vars := mux.Vars(request)
	moduleId := vars["id"]
	id, err := strconv.Atoi(moduleId)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "id '%s' is not a valid ebpf module id", moduleId)
		return
	}

	module := e.getModuleById(uint(id))
	if module == nil {
		writer.WriteHeader(http.StatusNotFound)
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "no ebpf modle with id %s exists", moduleId)
		return
	}

	jsonResponse, err := json.Marshal(module)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	writer.WriteHeader(http.StatusOK)
	writer.Header().Set("Content-Type", "application/json")
	writer.Write(jsonResponse)
}

func (e *EbpfManager) apiDeleteModule(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP DELETE request - /ebpf/{id}")

	vars := mux.Vars(request)
	moduleId := vars["id"]
	id, err := strconv.Atoi(moduleId)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		writer.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(writer, "'%s' is not a valid ebpf module id", moduleId)
		return
	}

	e.deleteModuleById(uint(id))

	writer.WriteHeader(http.StatusOK)
}

func (e *EbpfManager) apiDeleteAllModules(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP DELETE request - /ebpf")
	e.deleteAllModules()
	writer.WriteHeader(http.StatusOK)
}

func (e *EbpfManager) RegisterApi() {
	if ebpfManager != nil {
		e.router.HandleFunc("", e.apiCreateNewModule).Methods("POST")
		e.router.HandleFunc("", e.apiGetAllModules).Methods("GET")
		e.router.HandleFunc("/{id}", e.apiGetModuleById).Methods("GET")
		e.router.HandleFunc("", e.apiDeleteAllModules).Methods("DELETE")
		e.router.HandleFunc("/{id}", e.apiDeleteModule).Methods("DELETE")
	}
}
