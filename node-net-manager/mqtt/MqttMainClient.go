package mqtt

import (
	"NetManager/logger"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

var initMqttClient sync.Once

type NetMqttClient struct {
	topics                 map[string]mqtt.MessageHandler
	clientID               string
	mainMqttClient         mqtt.Client
	brokerUrl              string
	brokerPort             string
	mqttWriteMutex         *sync.Mutex
	mqttTopicsMutex        *sync.RWMutex
	tableQueryRequestCache *TableQueryRequestCache
}

var netMqttClient NetMqttClient

func InitNetMqttClient(clientid string, brokerurl string, brokerport string) *NetMqttClient {
	initMqttClient.Do(func() {
		netMqttClient = NetMqttClient{
			topics:                 make(map[string]mqtt.MessageHandler),
			clientID:               clientid,
			mainMqttClient:         nil,
			brokerUrl:              brokerurl,
			brokerPort:             brokerport,
			mqttWriteMutex:         &sync.Mutex{},
			mqttTopicsMutex:        &sync.RWMutex{},
			tableQueryRequestCache: GetTableQueryRequestCacheInstance(),
		}

		var messageDefaultHandler mqtt.MessageHandler = func(_ mqtt.Client, msg mqtt.Message) {
			log.Printf("DEBUG - Received message: %s from topic: %s\n", msg.Payload(), msg.Topic())
		}

		subscribeHandlerDispatcher := func(client mqtt.Client, msg mqtt.Message) {
			handlerlist := make([]mqtt.MessageHandler, 0)
			netMqttClient.mqttTopicsMutex.RLock()
			for key, handler := range netMqttClient.topics {
				if strings.Contains(msg.Topic(), key) {
					handlerlist = append(handlerlist, handler)
				}
			}
			netMqttClient.mqttTopicsMutex.RUnlock()
			for _, handler := range handlerlist {
				handler(client, msg)
			}
		}

		var connectHandler mqtt.OnConnectHandler = func(client mqtt.Client) {
			log.Println("Connected to the MQTT broker")

			topicsQosMap := make(map[string]byte)
			for key := range netMqttClient.topics {
				topicsQosMap[key] = 1
			}

			// subscribe to all the topics
			tqtoken := client.SubscribeMultiple(topicsQosMap, subscribeHandlerDispatcher)
			tqtoken.Wait()
			log.Printf("Subscribed to topics \n")
		}

		var connectLostHandler mqtt.ConnectionLostHandler = func(_ mqtt.Client, err error) {
			log.Printf("Connect lost: %v", err)
		}

		netMqttClient.topics[fmt.Sprintf("nodes/%s/net/tablequery/result", netMqttClient.clientID)] = netMqttClient.tableQueryRequestCache.TablequeryResultMqttHandler
		netMqttClient.topics[fmt.Sprintf("nodes/%s/net/subnetwork/result", netMqttClient.clientID)] = subnetworkAssignmentMqttHandler

		opts := mqtt.NewClientOptions()
		opts.AddBroker(fmt.Sprintf("tcp://%s:%s", netMqttClient.brokerUrl, netMqttClient.brokerPort))
		opts.SetClientID(clientid)
		opts.SetUsername("")
		opts.SetPassword("")
		opts.SetDefaultPublishHandler(messageDefaultHandler)
		opts.OnConnect = connectHandler
		opts.OnConnectionLost = connectLostHandler

		netMqttClient.runMqttClient(opts)
	})
	return &netMqttClient
}

func GetNetMqttClient() *NetMqttClient {
	return &netMqttClient
}

func (mqttclient *NetMqttClient) ClientID() string {
	return mqttclient.clientID
}

func (mqttclient *NetMqttClient) TableQueryRequestCache() *TableQueryRequestCache {
	return mqttclient.tableQueryRequestCache
}

func (netmqtt *NetMqttClient) runMqttClient(opts *mqtt.ClientOptions) {
	netmqtt.mainMqttClient = mqtt.NewClient(opts)
	if token := netmqtt.mainMqttClient.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}
}

func (netmqtt *NetMqttClient) PublishToBroker(topic string, payload string) error {
	netmqtt.mqttWriteMutex.Lock()
	logger.DebugLogger().Printf("MQTT - publish to - %s - the payload - %s", topic, payload)
	token := netmqtt.mainMqttClient.Publish(fmt.Sprintf("nodes/%s/net/%s", netmqtt.clientID, topic), 1, false, payload)
	netmqtt.mqttWriteMutex.Unlock()
	if token.WaitTimeout(time.Second*5) && token.Error() != nil {
		log.Printf("ERROR: MQTT PUBLISH: %s", token.Error())
	}
	return nil
}

func (netmqtt *NetMqttClient) RegisterTopic(topic string, handler mqtt.MessageHandler) {
	netmqtt.mqttTopicsMutex.Lock()
	defer netmqtt.mqttTopicsMutex.Unlock()
	netmqtt.topics[topic] = handler // adding the topic to the global topic list to be handled in case of disconnection
	tqtoken := netmqtt.mainMqttClient.Subscribe(topic, 1, handler)
	tqtoken.WaitTimeout(time.Second * 5)
}

func (netmqtt *NetMqttClient) DeRegisterTopic(topic string) {
	netmqtt.mqttTopicsMutex.Lock()
	defer netmqtt.mqttTopicsMutex.Unlock()
	netmqtt.mainMqttClient.Unsubscribe(topic)
	delete(netmqtt.topics, topic) // removing topic from the topic list in case of disconnection
}

func (netmqtt *NetMqttClient) RegisterWorker(workerID string) {
	// deregister from gateway deployment topics, since workers cannot function as gateways
	netmqtt.DeRegisterTopic(fmt.Sprintf("nodes/%s/net/gateway/deploy", netmqtt.clientID))
	netmqtt.DeRegisterTopic(fmt.Sprintf("nodes/%s/net/subnetwork/result", netmqtt.clientID))
	netmqtt.DeRegisterTopic(fmt.Sprintf("nodes/%s/net/tablequery/result", netmqtt.clientID))
	// replace old netmanagerID with workerID
	netmqtt.clientID = workerID
	// subscribe to worker specific topics
	netmqtt.RegisterTopic(fmt.Sprintf("nodes/%s/net/tablequery/result", netmqtt.clientID),
		netmqtt.tableQueryRequestCache.TablequeryResultMqttHandler)
	netmqtt.RegisterTopic(fmt.Sprintf("nodes/%s/net/subnetwork/result", netmqtt.clientID),
		subnetworkAssignmentMqttHandler)
}
