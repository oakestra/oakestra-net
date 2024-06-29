package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"log"
	"net"
)

type Proxy struct {
	Collection        *ebpf.Collection `json:"-"`
	serviceToInstance *ebpf.Map
}

// IMPORTANT: Keep this in sync with the definition ix proxy.c
const MAX_IPS = 32

type IPList struct {
	Length int32
	IPs    [MAX_IPS]uint32
}

func (p *Proxy) AddServiceTranslation(serviceIp net.IP) {
	var value IPList
	key := binary.LittleEndian.Uint32(net.ParseIP("10.30.0.1").To4())

	value.Length = 1
	value.IPs[0] = binary.LittleEndian.Uint32(net.ParseIP("192.168.1.1").To4()) //TODO ben just for debugging

	if err := p.serviceToInstance.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Error updating map: %v", err)
	}
}

func NewProxy(collection *ebpf.Collection) Proxy {
	p := Proxy{
		Collection:        collection,
		serviceToInstance: collection.Maps["service_to_instance"], //TODO ben this might fail!
	}
	p.AddServiceTranslation(net.ParseIP("192.168.1.1").To4()) // TODO ben remove
	return p
}
