package ebpfManager

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
)

type ebpfRequest struct {
	name string `json:"name"`
}

func (e *EbpfManager) createEbpf(writer http.ResponseWriter, request *http.Request) {
	log.Println("Received HTTP request - /ebpf ")
	reqBody, _ := io.ReadAll(request.Body)
	var ebpfRequest ebpfRequest
	err := json.Unmarshal(reqBody, &ebpfRequest)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
	}

	e.createNewEbpf()
}

func (e *EbpfManager) RegisterHandles() {
	if e.router != nil {
		e.router.HandleFunc("/ebpf", e.createEbpf).Methods("POST")
	}
}
