package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"log"
	"net"
	"os"
	"syscall"
)

type Proxy struct {
	Collection        *ebpf.Collection `json:"-"`
	serviceToInstance *ebpf.Map
	pktBuffer         *ebpf.Map
	socket            int
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

func (p *Proxy) Close() {
	syscall.Close(p.socket)
}

func NewProxy(collection *ebpf.Collection, ifname string) Proxy {
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(socket)

	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get interface: %v\n", err)
		os.Exit(1)
	}
	addr, _ := iface.Addrs()
	if err := syscall.Sendto(socket, packet, 0, &addr); err != nil {
		fmt.Fprintf(os.Stderr, "failed to send packet: %v\n", err)
		os.Exit(1)
	}

	p := Proxy{
		Collection:        collection,
		serviceToInstance: collection.Maps["service_to_instance"], //TODO ben this might fail!
		pktBuffer:         collection.Maps["packet_queue"],        //TODO ben this might fail!
		socket:            socket,
	}

	p.AddServiceTranslation(net.ParseIP("192.168.1.1").To4()) // TODO ben remove
	return p
}

func (p *Proxy) Test() {
	rd, err := perf.NewReader(p.pktBuffer, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf reader: %s", err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("reading from perf reader: %v", err)
			continue
		}

		var pkt packet
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &pkt); err != nil {
			log.Printf("decoding packet: %v", err)
			continue
		}
	}
}

func (p *Proxy) reinjectPacket(data []byte) error {
	return nil
}
