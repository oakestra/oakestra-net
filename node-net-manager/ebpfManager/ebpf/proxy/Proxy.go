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
	ip_updates        *ebpf.Map
	socket            int
	proxyManager      *ProxyManager
}

const MAX_IPS = 32 // IMPORTANT: Keep in sync with ebpf implementation

type IPList struct {
	Length int32
	IPs    [MAX_IPS]uint32
}

func (p *Proxy) SetServiceTranslations(serviceIp net.IP, instanceIPs []net.IP) {
	if len(instanceIPs) < 1 {
		return
	}

	var value IPList
	key := binary.LittleEndian.Uint32(serviceIp.To4())

	length := len(instanceIPs)
	if length > MAX_IPS {
		length = MAX_IPS
		log.Printf("Ebpf Proxy had to drop IP translations. You might want to increase MAX_IPS.")
	}

	var leIpList [MAX_IPS]uint32
	for i := 0; i < length; i++ {
		leIpList[i] = binary.LittleEndian.Uint32(instanceIPs[i].To4())
	}

	value.IPs = leIpList
	value.Length = int32(length)

	if err := p.serviceToInstance.Update(&key, &value, ebpf.UpdateAny); err != nil {
		log.Fatalf("Error updating map: %v", err)
	}
}

func (p *Proxy) Close() {
	syscall.Close(p.socket)
}

func NewProxy(collection *ebpf.Collection, manager *ProxyManager) Proxy {
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
		proxyManager:      manager,
	}
	p.StartReadingPerfEvents()

	return p
}

// this function keeps polling to check if the ebpf function requests an table lookup
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

			translations := p.proxyManager.manager.GetTableEntryByServiceIP(ip)
			p.SetServiceTranslations(ip, translations) // TODO ben get IP from env Manager

			fmt.Printf("Got IP: %s\n", ip.String())
		}
	}()
}
