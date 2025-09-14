package mqtt

import (
	"NetManager/logger"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/quic-go/quic-go"
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
	Src string `json:"src"`
	Dst string `json:"dst"`
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
func RequestNATTraversal(src string, dst string) error {
	payload := natTraversalPayload{Dst: dst, Src: src}
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

	idx := strings.LastIndex(responseStruct.Dst, ":")
	dstHost := responseStruct.Dst[:idx]
	dstPort := responseStruct.Dst[idx+1:]

	// Format hoststring with [] if ipv6
	var hoststring string
	if strings.Contains(dstHost, ":") {
		hoststring = fmt.Sprintf("[%s]:%s", dstHost, dstPort)
	} else {
		hoststring = fmt.Sprintf("%s:%s", dstHost, dstPort)
	}
	logger.DebugLogger().Printf("Attempting NAT traversal with host address %s", hoststring)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-proxy"},
	}

	quicConf := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		EnableDatagrams:      true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// repeat up to 5 times with small delay between attempts
	for i := 0; i < 5; i++ {
		_, err = quic.DialAddr(ctx, hoststring, tlsConf, quicConf)
		if err == nil {
			logger.DebugLogger().Println("Nat traversal succeeded")
			return
		}
		logger.DebugLogger().Println("Nat traversal failed", err)
		time.Sleep(500 * time.Millisecond)
	}

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
