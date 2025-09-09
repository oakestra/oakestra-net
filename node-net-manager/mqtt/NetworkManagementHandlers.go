package mqtt

import (
	"NetManager/logger"
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
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
func RequestNATTraversal(hoststring string) error {
	payload := natTraversalPayload{Dst: hoststring}
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
	err := json.Unmarshal(msg.Payload(), &responseStruct)
	if err != nil {
		log.Println("ERROR - Invalid nat traversal response")
		return
	}

	go func() {
		// repeat up to 5 times with slight delay between each attempt
		tlsConf := &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"quic-proxy"},
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for i := 0; i < 5; i++ {
			_, err = quic.DialAddr(ctx, responseStruct.Dst, tlsConf, &quic.Config{
				HandshakeIdleTimeout: 5 * time.Second,
				MaxIdleTimeout:       2 * time.Minute,
				EnableDatagrams:      true,
			})
			if err == nil {
				log.Println("NAT Traversal succeeded")
				return
			}
		}
	}()
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
