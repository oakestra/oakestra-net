package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"syscall"
)

type Proxy struct {
	Collection        *ebpf.Collection `json:"-"`
	serviceToInstance *ebpf.Map
	ip_updates        *ebpf.Map
	socket            int
}

const MAX_IPS = 32 // IMPORTANT: Keep in sync with ebpf implementation

type IPList struct {
	Length int32
	IPs    [MAX_IPS]uint32
}

func (p *Proxy) AddServiceTranslation(serviceIp net.IP, instanceIP net.IP) {
	var value IPList
	key := binary.LittleEndian.Uint32(serviceIp.To4())

	if err := p.serviceToInstance.Lookup(&key, &value); err != nil {
		if errors.Is(err, unix.ENOENT) {
			value.Length = 0
		} else {
			log.Fatalf("lookup failed: %v", err)
		}
	}

	index := value.Length % MAX_IPS
	value.IPs[index] = binary.LittleEndian.Uint32(instanceIP.To4())
	if value.Length < MAX_IPS {
		value.Length += 1
	}

	if err := p.serviceToInstance.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Error updating map: %v", err)
	}
}

func (p *Proxy) Close() {
	syscall.Close(p.socket)
}

func NewProxy(collection *ebpf.Collection) Proxy {
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create socket: %v\n", err)
		os.Exit(1)
	}
	defer syscall.Close(socket)

	p := Proxy{
		Collection:        collection,
		serviceToInstance: collection.Maps["service_to_instance"], //TODO ben this might fail!
		ip_updates:        collection.Maps["ip_updates"],          //TODO ben this might fail!
		socket:            socket,
	}
	p.StartReadingPerfEvents()
	return p
}

func (p *Proxy) StartReadingPerfEvents() {
	reader, err := perf.NewReader(p.ip_updates, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}

	//TODO BEN close go routine when program closes
	go func() {
		defer reader.Close()
		for {
			record, err := reader.Read()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from perf map: %v\n", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			var ip = make(net.IP, 4)
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &ip); err != nil {
				log.Printf("parsing event: %v", err)
				continue
			}

			p.AddServiceTranslation(ip, ip) // TODO ben get IP from env Manager

			fmt.Printf("Got IP: %s\n", ip.String())
		}
	}()
}
