package mqtt

import (
	"NetManager/logger"
	"NetManager/model"
	"NetManager/natTraversal"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var subnetworkResponseChannel chan mqttSubnetworkResponse

type mqttSubnetworkResponse struct {
	Address    string `json:"address"`
	Address_v6 string `json:"addressv6"`
}
type mqttSubnetworkRequest struct {
	METHOD string `json:"METHOD"`
}
type mqttDeployNotification struct {
	Appname        string `json:"appname"`
	Status         string `json:"status"`
	Instancenumber int    `json:"instance_number"`
	Nsip           string `json:"nsip"`
	Nsipv6         string `json:"nsipv6"`
	Hostport       string `json:"host_port"`
	Hostip         string `json:"host_ip"`
}

type natTraversalPayload struct {
	Src          string    `json:"src"`
	NatSrc       string    `json:"nat_src"`
	Dst          string    `json:"dst"`
	NatDst       string    `json:"nat_dst"`
	Timestamp    time.Time `json:"timestamp"`
	OriginatorId string    `json:"originator_id"`
}

func subnetworkAssignmentMqttHandler(_ mqtt.Client, msg mqtt.Message) {
	responseStruct := mqttSubnetworkResponse{}
	err := json.Unmarshal(msg.Payload(), &responseStruct)
	if err != nil {
		log.Println("ERROR - Invalid subnetwork response")
		subnetworkResponseChannel <- mqttSubnetworkResponse{}
		return
	}
	subnetworkResponseChannel <- responseStruct
}

// RequestNATTraversal sends request to the cluster to facilitate NAT traversal
func RequestNATTraversal(src string, dst string, oid string, timestamp time.Time) error {
	payload := natTraversalPayload{Dst: dst, NatSrc: src, OriginatorId: oid, Timestamp: timestamp}
	req, err := json.Marshal(&payload)
	if err != nil {
		return err
	}
	go func() {
		_ = GetNetMqttClient().PublishToBroker("nattraversal/request", string(req))
	}()
	return nil
}

// natTraversalMqttHandler receives a nat traversal request from the cluster
func natTraversalMqttHandler(_ mqtt.Client, msg mqtt.Message) {
	logger.DebugLogger().Println("Received NAT Traversal request")
	// msg is natTraversalPayload
	responseStruct := natTraversalPayload{}

	logger.DebugLogger().Printf("NAT traversal request received: %s", string(msg.Payload()))
	err := json.Unmarshal(msg.Payload(), &responseStruct)
	if err != nil {
		log.Println("ERROR - Invalid nat traversal response")
		return
	}

	hoststring := responseStruct.NatDst

	// format hoststring with [] if ipv6
	idx := strings.LastIndex(hoststring, ":")
	if idx != -1 {
		dstHost := responseStruct.NatDst[:idx]
		dstPort := responseStruct.NatDst[idx+1:]

		if strings.Contains(dstHost, ":") && dstHost[:1] != "[" {
			hoststring = fmt.Sprintf("[%s]:%s", dstHost, dstPort)
		} else {
			hoststring = fmt.Sprintf("%s:%s", dstHost, dstPort)
		}
	}
	logger.DebugLogger().Printf("Attempting NAT traversal with host address %s", hoststring)

	timestamp := responseStruct.Timestamp
	if responseStruct.OriginatorId != model.WorkerID {
		// find this nodes nat addr and forward to other node
		logger.DebugLogger().Printf("I am Node B")
		timestamp, err = natTraversal.InitiateNATTraversal(responseStruct.Src, nil, responseStruct.OriginatorId, RequestNATTraversal)
		if err != nil {
			logger.DebugLogger().Printf("ERROR - NAT traversal error: %s", err)
			return
		}
	} else {
		logger.DebugLogger().Printf("I am Node A")
	}

	natTraversal.ConnectOverNAT(hoststring, timestamp)

	return
}

/*Request a subnetwork to the cluster using the mqtt broker*/
func RequestSubnetworkMqttBlocking() (mqttSubnetworkResponse, error) {
	subnetworkResponseChannel = make(chan mqttSubnetworkResponse, 1)

	request := mqttSubnetworkRequest{METHOD: "GET"}
	jsonreq, _ := json.Marshal(request)
	go func() {
		_ = GetNetMqttClient().PublishToBroker("subnet", string(jsonreq))
	}()

	// waiting for maximum 10 seconds the mqtt handler to receive a response. Otherwise, fail the subnetwork request.
	select {
	case result := <-subnetworkResponseChannel:
		if result.Address != "" || result.Address_v6 != "" {
			return result, nil
		}
	case <-time.After(10 * time.Second):
		log.Printf("TIMEOUT - Table query without response, quitting goroutine")
	}

	return mqttSubnetworkResponse{}, net.UnknownNetworkError("Invalid Subnetwork received")
}

func NotifyDeploymentStatus(appname string, status string, instance int, nsip string, nsipv6 string, hostip string, hostport string) error {
	request := mqttDeployNotification{
		Appname:        appname,
		Status:         status,
		Instancenumber: instance,
		Nsip:           nsip,
		Nsipv6:         nsipv6,
		Hostip:         hostip,
		Hostport:       hostport,
	}
	jsonreq, _ := json.Marshal(request)
	return GetNetMqttClient().PublishToBroker("service/deployed", string(jsonreq))
}
