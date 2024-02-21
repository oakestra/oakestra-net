package gateway

import (
	"NetManager/logger"
	"NetManager/model"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type helloAnswer struct {
	ID string `json:"id"`
}

func RegisterNetmanager(address string, nodePort string) string {
	mod := model.GetNodeInfo()
	mod.Port, _ = strconv.Atoi(nodePort)
	jsondata, err := json.Marshal(mod)
	if err != nil {
		logger.ErrorLogger().Fatalf("Marshaling of node information failed, %v", err)
	}
	jsonbody := bytes.NewBuffer(jsondata)
	resp, err := http.Post(
		fmt.Sprintf("http://%s:10100/api/net/register", address),
		"application/json",
		jsonbody,
	)
	if err != nil {
		logger.ErrorLogger().Fatalf("Handshake failed, %v", err)
	}
	if resp.StatusCode != 200 {
		logger.ErrorLogger().Fatalf("Handshake failed with error code %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	ans := helloAnswer{}
	responseBytes, _ := io.ReadAll(resp.Body)
	err = json.Unmarshal(responseBytes, &ans)
	if err != nil {
		logger.ErrorLogger().Fatalf("Handshake failed, %v", err)
	}
	return ans.ID
}
