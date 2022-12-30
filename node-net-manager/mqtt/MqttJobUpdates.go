package mqtt

import (
	"NetManager/events"
	"NetManager/logger"
	"NetManager/utils"
	"encoding/json"
	"github.com/eclipse/paho.mqtt.golang"
	"log"
	"sync"
	"time"
)

var runningHandlers = utils.NewStringSlice()
var startSync sync.RWMutex

type jobUpdatesTimer struct {
	eventManager events.EventManager
	job          string
	instance     int
	topic        string
	client       mqtt.Client
	env          jobEnvironmentManagerActions
}

type jobEnvironmentManagerActions interface {
	RefreshServiceTable(sname string)
	RemoveServiceEntries(sname string)
	IsServiceDeployed(fullSnameAndInstance string) bool
}

type mqttInterestDeregisterRequest struct {
	Appname string `json:"appname"`
}

func (jut *jobUpdatesTimer) MessageHandler(client mqtt.Client, message mqtt.Message) {
	log.Printf("Received job update regarding %s", message.Topic())
	go jut.env.RefreshServiceTable(jut.job)
}

func (jut *jobUpdatesTimer) startSelfDestructTimeout() {
	/*
		If any worker still requires this job, reset timer. If in 5 minutes nobody needs this service, de-register the interest.
	*/
	log.Printf("self destruction timeout started for job %s", jut.job)
	eventManager := events.GetInstance()
	eventChan, _ := eventManager.Register(events.TableQuery, jut.job)
	for true {
		select {
		case <-eventChan:
			//event received, reset timer
			logger.DebugLogger().Printf("received packet event from: %s", jut.job)
			continue
		case <-time.After(10 * time.Second):
			if !jut.env.IsServiceDeployed(jut.job) {
				//timeout job no longer required
				startSync.Lock()
				defer startSync.Unlock()
				log.Printf("De-registering from %s", jut.job)
				cleanInterestTowardsJob(jut.job)
				jut.client.Unsubscribe(jut.topic)
				delete(TOPICS, jut.topic) //removing topic from the topic list in case of disconnection
				eventManager.DeRegister(events.TableQuery, jut.job)
				jut.env.RemoveServiceEntries(jut.job)
				runningHandlers.RemoveElem(jut.job)
				return
			}
			continue
		}
	}
}

// MqttRegisterInterest :
/* Register an interest in a route for 5 minutes.
If the route is not used for more than 5 minutes the interest is removed
If the instance number is provided, the interest is kept until that instance is deployed in the node */
func MqttRegisterInterest(jobName string, env jobEnvironmentManagerActions, instance ...int) {

	startSync.Lock()
	defer startSync.Unlock()
	if runningHandlers.Exists(jobName) {
		log.Printf("Interest for job %s already registered", jobName)
		return
	}

	instanceNumber := -1
	if len(instance) > 0 {
		instanceNumber = instance[0]
	}

	jobTimer := jobUpdatesTimer{
		eventManager: events.GetInstance(),
		job:          jobName,
		env:          env,
		client:       mainMqttClient,
		instance:     instanceNumber,
	}

	jobTimer.topic = "jobs/" + jobName + "/updates_available"
	TOPICS[jobTimer.topic] = jobTimer.MessageHandler //adding the topic to the global topic list to be handled in case of disconnection
	tqtoken := mainMqttClient.Subscribe(jobTimer.topic, 1, jobTimer.MessageHandler)
	tqtoken.WaitTimeout(time.Second * 5)
	log.Printf("MQTT - Subscribed to %s ", jobTimer.topic)
	runningHandlers.Add(jobTimer.job)
	go jobTimer.startSelfDestructTimeout()
}

func MqttIsInterestRegistered(jobName string) bool {
	startSync.RLock()
	defer startSync.RUnlock()
	if runningHandlers.Exists(jobName) {
		return true
	}
	return false
}

func cleanInterestTowardsJob(jobName string) {
	request := mqttInterestDeregisterRequest{Appname: jobName}
	jsonreq, _ := json.Marshal(request)
	_ = PublishToBroker("interest/remove", string(jsonreq))
}
