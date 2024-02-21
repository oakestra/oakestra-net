package gateway

import (
	"NetManager/logger"
	"NetManager/mqtt"
	"encoding/json"
	"fmt"
	"net"

	pmqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttGatewayRequest struct {
	GatewayID      string `json:"gateway_id"`
	ServiceJobName string `json:"job_name"`
	InstanceIPv4   net.IP `json:"instance_ip"`
	InstanceIPv6   net.IP `json:"instance_ip_v6"`
	GatewayIPv4    net.IP `json:"gateway_ipv4"`
	GatewayIPv6    net.IP `json:"gateway_ipv6"`
}

type mqttFirewallExpose struct {
	GatewayID     string `json:"gateway_id"`
	ServiceID     string `json:"service_id"`
	ServiceIP     net.IP `json:"service_ip"`
	Internal_Port int    `json:"internal_port"`
	Exposed_Port  int    `json:"exposed_port"`
}

type mqttGatewayDeployed struct {
	Namespace_IP    string `json:"namespace_ip"`
	Namespace_IP_v6 string `json:"namespace_ip_v6"`
}

func GatewayDeploymentHandler(_ pmqtt.Client, msg pmqtt.Message) {
	logger.InfoLogger().Printf("MQTT - Received mqtt gateway deploy message: %s", msg.Payload())

	payload := msg.Payload()
	var req mqttGatewayRequest
	err := json.Unmarshal(payload, &req)
	if err != nil {
		logger.InfoLogger().Println(err)
	}

	// setup MQTT topics
	mqtt.GetNetMqttClient().RegisterTopic(fmt.Sprintf("nodes/%s/net/gateway/expose", mqtt.GetNetMqttClient().ClientID()), GatewayFirewallExposeHandler)
	mqtt.GetNetMqttClient().RegisterTopic(fmt.Sprintf("nodes/%s/net/tablequery/result", mqtt.GetNetMqttClient().ClientID()), mqtt.GetTableQueryRequestCacheInstance().TablequeryResultMqttHandler)

	gateway := StartGatewayProcess(req.GatewayID, req.ServiceJobName, req.GatewayIPv4, req.GatewayIPv6, req.InstanceIPv4, req.InstanceIPv6)
	if gateway == nil {
		return
	}
	// report back successfull setup of gateway
	callbackMsg := &mqttGatewayDeployed{
		Namespace_IP:    gateway.bridgeIPv4.String(),
		Namespace_IP_v6: gateway.bridgeIPv6.String(),
	}
	callbackPayload, _ := json.Marshal(callbackMsg)
	err = mqtt.GetNetMqttClient().PublishToBroker("gateway/deployed", string(callbackPayload))
	if err != nil {
		logger.ErrorLogger().Println("MQTT - Could not notify service-manager.")
	}
}

func GatewayFirewallExposeHandler(_ pmqtt.Client, msg pmqtt.Message) {
	logger.InfoLogger().Printf("MQTT - Received mqtt gateway deploy message: %s", msg.Payload())

	payload := msg.Payload()
	var req mqttFirewallExpose
	err := json.Unmarshal(payload, &req)
	if err != nil {
		logger.InfoLogger().Println(err)
	}
	err = Exposer.EnableServiceExposure(req.ServiceID, req.ServiceIP, req.Internal_Port, req.Exposed_Port)
	if err != nil {
		logger.InfoLogger().Println(err)
	}
}
