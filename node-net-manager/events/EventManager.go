package events

import (
	"errors"
	"fmt"
	"sync"
)

type Callback func(event CallbackEvent)

type EventManager interface {
	Emit(event Event)
	Register(eventType EventType, eventTarget string) (chan Event, error)
	DeRegister(eventType EventType, eventTarget string)

	EmitCallback(event CallbackEvent)
	RegisterCallback(eventType EventType, callback Callback) string
	DeRegisterCallback(eventType EventType, id string)
}

type EventType int

type Events struct {
	//map of event target to event kind
	pubSubChannels map[string]chan Event
	listeners      map[EventType]map[string]Callback
}

type Event struct {
	EventType    EventType
	EventTarget  string
	EventMessage string
}

type CallbackEvent struct {
	EventType EventType
	Payload   interface{}
}

// Payload for events fo type ServiceCreated and ServiceRemoved.
type ServicePayload struct {
	ServiceName  string
	VethName     string
	VethPeerName string
}

// TODO ben add short doc of why we need ChannelEvents and CallbackEvents and what they are
const (
	// ChannelEvents
	TableQuery EventType = iota

	// CallbackEvents
	ServiceCreated
	ServiceRemoved
)

/* ------------- singleton instance ------- */
var once sync.Once
var rwlock sync.RWMutex
var (
	eventInstance EventManager
)

/* ------------------------------------------*/

func (e *Events) EmitCallback(event CallbackEvent) {
	rwlock.RLock()
	defer rwlock.RUnlock()
	callbacks, ok := e.listeners[event.EventType]
	if ok {
		for _, callback := range callbacks {
			callback(event)
		}
	}
}

func (e *Events) RegisterCallback(eventType EventType, callback Callback) string {
	rwlock.RLock()
	defer rwlock.RUnlock()
	id := fmt.Sprintf("%p", &callback) // Generate a unique ID based on the pointer address
	if _, ok := e.listeners[eventType]; !ok {
		e.listeners[eventType] = make(map[string]Callback)
	}
	e.listeners[eventType][id] = callback
	return id
}

func (e *Events) DeRegisterCallback(eventType EventType, id string) {
	rwlock.RLock()
	defer rwlock.RUnlock()
	if callbacks, ok := e.listeners[eventType]; ok {
		delete(callbacks, id)
		if len(callbacks) == 0 {
			delete(e.listeners, eventType)
		}
	}
}

func GetInstance() EventManager {
	once.Do(func() {
		eventInstance = &Events{
			pubSubChannels: make(map[string]chan Event, 0),
			listeners:      make(map[EventType]map[string]Callback),
		}
	})
	return eventInstance
}

func (e *Events) Emit(event Event) {
	rwlock.RLock()
	defer rwlock.RUnlock()
	switch event.EventType {
	case TableQuery:
		channel := e.pubSubChannels[event.EventTarget]
		if channel != nil {
			//check channel buffer capacity to prevent blocking. If this is false, probably no receiver is active.
			if len(channel) < cap(channel) {
				channel <- event
			}
		}
	}
}

func (e *Events) Register(eventType EventType, eventTarget string) (chan Event, error) {
	rwlock.Lock()
	defer rwlock.Unlock()
	switch eventType {
	case TableQuery:
		channel := e.pubSubChannels[eventTarget]
		if channel == nil {
			channel = make(chan Event, 10)
		}
		e.pubSubChannels[eventTarget] = channel
		return channel, nil
	}
	return nil, errors.New("Invalid EventType")
}

func (e *Events) DeRegister(eventType EventType, eventTarget string) {
	rwlock.Lock()
	defer rwlock.Unlock()
	switch eventType {
	case TableQuery:
		channel := e.pubSubChannels[eventTarget]
		if channel != nil {
			e.pubSubChannels[eventTarget] = nil
			close(channel)
		}
	}
}
