package events

import (
	"errors"
	"sync"
)

type EventManager interface {
	Emit(event Event)
	Register(eventType EventType, eventTarget string) (chan Event, error)
	DeRegister(eventType EventType, eventTarget string)
}

type EventType int

type Events struct {
	//map of event target to event kind
	eventTableQueryChannelQueue map[string]chan Event
	vethCreationChannel         chan Event
}

type Event struct {
	EventType    EventType
	EventTarget  string
	EventMessage string
	Payload      interface{}
}

type VethCreationPayload struct {
	Name     string
	PeerName string
}

// TODO ben ensure type safty at compile time for Payload!
//type EventPayload interface {
//	Type() EventType
//}
//
//
//func (v VethCreationPayload) Type() EventType {
//	return VethCreation
//}

const (
	TableQuery EventType = iota

	// VethCreation This event is triggered by the environment when a new veth pair was created.
	VethCreation
)

/* ------------- singleton instance ------- */
var once sync.Once
var rwlock sync.RWMutex
var (
	eventInstance EventManager
)

/* ------------------------------------------*/

func GetInstance() EventManager {
	once.Do(func() {
		eventInstance = &Events{
			eventTableQueryChannelQueue: make(map[string]chan Event, 0),
		}
	})
	return eventInstance
}

func (e *Events) Emit(event Event) {
	rwlock.RLock()
	defer rwlock.RUnlock()
	switch event.EventType {
	case TableQuery:
		channel := e.eventTableQueryChannelQueue[event.EventTarget]
		if channel != nil {
			//check channel buffer capacity to prevent blocking. If this is false, probably no receiver is active.
			if len(channel) < cap(channel) {
				channel <- event
			}
		}
		break
	case VethCreation:
		channel := e.vethCreationChannel
		if channel != nil {
			//check channel buffer capacity to prevent blocking. If this is false, probably no receiver is active.
			if len(channel) < cap(channel) {
				channel <- event
			}
		}
		break
	}
}

func (e *Events) Register(eventType EventType, eventTarget string) (chan Event, error) {
	rwlock.Lock()
	defer rwlock.Unlock()
	switch eventType {
	case TableQuery:
		channel := e.eventTableQueryChannelQueue[eventTarget]
		if channel == nil {
			channel = make(chan Event, 10)
		}
		e.eventTableQueryChannelQueue[eventTarget] = channel
		return channel, nil
	case VethCreation:
		channel := e.vethCreationChannel
		if channel == nil {
			channel = make(chan Event, 10)
		}
		e.vethCreationChannel = channel
		return channel, nil
	}
	return nil, errors.New("Invalid EventType")
}

func (e *Events) DeRegister(eventType EventType, eventTarget string) {
	rwlock.Lock()
	defer rwlock.Unlock()
	switch eventType {
	case TableQuery:
		channel := e.eventTableQueryChannelQueue[eventTarget]
		if channel != nil {
			e.eventTableQueryChannelQueue[eventTarget] = nil
			close(channel)
		}
		break
	case VethCreation:
		channel := e.vethCreationChannel
		close(channel)
		break
	}
}
