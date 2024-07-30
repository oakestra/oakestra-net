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
)

type Proxy struct {
	Collection        *ebpf.Collection `json:"-"`
	serviceToInstance *ebpf.Map
	ip_updates        *ebpf.Map
	proxyManager      *ProxyManager
	done              chan struct{}
	perfReader        *perf.Reader
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

func NewProxy(collection *ebpf.Collection, manager *ProxyManager) *Proxy {
	serviceToInstance, exists := collection.Maps["service_to_instance"]
	if !exists {
		log.Printf("'service_to_instance map' missing. Cannot init proxy")
		return nil
	}
	ipUpdates, exists := collection.Maps["ip_updates"]
	if !exists {
		log.Printf("'ip_updates' map missing. Cannot init proxy")
		return nil
	}

	p := Proxy{
		Collection:        collection,
		serviceToInstance: serviceToInstance,
		ip_updates:        ipUpdates,
		proxyManager:      manager,
	}
	p.startReadingPerfEvents()

	return &p
}

func (p *Proxy) Close() {
	close(p.done)
	p.perfReader.Close()
}

// startReadingPerfEvents waits for perf events to update the lookup table
func (p *Proxy) startReadingPerfEvents() {
	var err error
	p.perfReader, err = perf.NewReader(p.ip_updates, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}

	p.done = make(chan struct{})
	go func() {
		for {
			select {
			case <-p.done:
				return
			default:
				record, err := p.perfReader.Read()
				if err != nil {
					log.Printf("Error reading from perf map: %v\n", err)
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

				// check if IP is in serviceIP subnet. Should always be the case.
				_, ipNet, _ := net.ParseCIDR("10.30.0.0/16")
				if !ipNet.Contains(ip) {
					fmt.Printf("Got IP %s but its not in subnet %s. This should not happen\n", ip.String(), ipNet.String())
				}

				translations := p.proxyManager.base.Manager.GetTableEntryByServiceIP(ip)
				p.SetServiceTranslations(ip, translations)
			}
		}
	}()
}
