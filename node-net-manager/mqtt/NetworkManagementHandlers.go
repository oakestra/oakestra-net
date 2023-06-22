package mqtt

import (
	"encoding/json"
	"log"
	"net"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var subnetworkResponseChannel chan string

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

func subnetworkAssignmentMqttHandler(client mqtt.Client, msg mqtt.Message) {
	responseStruct := mqttSubnetworkResponse{}
	err := json.Unmarshal(msg.Payload(), &responseStruct)
	if err != nil {
		log.Println("ERROR - Invalid subnetwork response")
		subnetworkResponseChannel <- ""
		return
	}
	subnetworkResponseChannel <- responseStruct.Address
	subnetworkResponseChannel <- responseStruct.Address_v6
}

/*Request a subnetwork to the cluster using the mqtt broker*/
func RequestSubnetworkMqttBlocking() (string, error) {
	subnetworkResponseChannel = make(chan string, 1)

	request := mqttSubnetworkRequest{METHOD: "GET"}
	jsonreq, _ := json.Marshal(request)
	go func() {
		_ = GetNetMqttClient().PublishToBroker("subnet", string(jsonreq))
	}()

	//waiting for maximum 10 seconds the mqtt handler to receive a response. Otherwise fail the subnetwork request.
	select {
	case result := <-subnetworkResponseChannel:
		if result != "" {
			// add whitespace between networks
			// TODO make optional, for network-stack adjustment
			result += " " + <-subnetworkResponseChannel
			return result, nil
		}
	case <-time.After(10 * time.Second):
		log.Printf("TIMEOUT - Table query without response, quitting goroutine")
	}

	return "", net.UnknownNetworkError("Invalid Subnetwork received")
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
