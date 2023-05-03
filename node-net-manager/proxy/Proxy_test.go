package proxy

import (
	"NetManager/TableEntryCache"
	"math/rand"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FakeEnv struct {
}

func (fakeenv *FakeEnv) GetTableEntryByServiceIP(ip net.IP) []TableEntryCache.TableEntry {
	entrytable := make([]TableEntryCache.TableEntry, 0)
	//If entry already available
	entry := TableEntryCache.TableEntry{
		Appname:          "a",
		Appns:            "a",
		Servicename:      "b",
		Servicenamespace: "b",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           net.ParseIP("10.0.0.1"),
		Nsip:             net.ParseIP("10.19.2.12"),
		Nsipv6:           net.ParseIP("fd00::12"),
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     TableEntryCache.Closest,
			Address:    net.ParseIP("10.30.255.255"),
			Address_v6: net.ParseIP("fdff:2000::ff"),
		},
			{
				IpType:     TableEntryCache.InstanceNumber,
				Address:    net.ParseIP("10.30.255.254"),
				Address_v6: net.ParseIP("fdff::fe"),
			}},
	}
	entrytable = append(entrytable, entry)
	return entrytable
}

func (fakeenv *FakeEnv) GetTableEntryByNsIP(ip net.IP) (TableEntryCache.TableEntry, bool) {
	entry := TableEntryCache.TableEntry{
		Appname:          "a",
		Appns:            "a",
		Servicename:      "c",
		Servicenamespace: "b",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           net.ParseIP("10.0.0.1"),
		Nsip:             net.ParseIP("10.19.1.1"),
		Nsipv6:           net.ParseIP("fc00::1"),
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     TableEntryCache.Closest,
			Address:    net.ParseIP("10.30.255.252"),
			Address_v6: net.ParseIP("fdff:2000::fc"),
		},
			{
				IpType:     TableEntryCache.InstanceNumber,
				Address:    net.ParseIP("10.30.255.253"),
				Address_v6: net.ParseIP("fdff::fd"),
			}},
	}
	return entry, true
}

func (fakeenv *FakeEnv) GetTableEntryByInstanceIP(ip net.IP) (TableEntryCache.TableEntry, bool) {
	return TableEntryCache.TableEntry{}, false
}

func getFakeTunnel() GoProxyTunnel {
	tunnel := GoProxyTunnel{
		tunNetIP:    "10.19.1.254",
		ifce:        nil,
		isListening: true,
		ProxyIpSubnetwork: net.IPNet{
			IP:   net.ParseIP("10.30.0.0"),
			Mask: net.IPMask(net.ParseIP("255.255.0.0").To4()),
		},
		HostTUNDeviceName: "goProxyTun",
		TunnelPort:        50011,
		listenConnection:  nil,
		proxycache:        NewProxyCache(),
		randseed:          rand.New(rand.NewSource(42)),
		tunNetIPv6:        "fdfe::1337",
		ProxyIPv6Subnetwork: net.IPNet{
			IP:   net.ParseIP("fdff::"),
			Mask: net.CIDRMask(16, 128),
		},
	}
	tunnel.SetEnvironment(&FakeEnv{})
	return tunnel
}

func getFakePacket(srcIP string, dstIP string, srcPort int, dstPort int) (gopacket.Packet, *networkLayer, *transportLayer) {
	ipLayer := networkLayer{&IPv4Packet{&layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Protocol: layers.IPProtocolTCP,
		Version:  4,
	}}}
	tcpLayer := transportLayer{&TCPLayer{&layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}}}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	ip := ipLayer.getLayer().(*layers.IPv4)
	tcpLayer.getTCPLayer().SetNetworkLayerForChecksum(ip)
	_ = gopacket.SerializeLayers(buf, opts, ipLayer.getLayer().(*layers.IPv4), tcpLayer.getTCPLayer())
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default), &ipLayer, &tcpLayer
}

func getFakeV6Packet(srcIP string, dstIP string, srcPort int, dstPort int) (gopacket.Packet, *networkLayer, *transportLayer) {
	ipLayer := networkLayer{&IPv6Packet{&layers.IPv6{
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
		NextHeader: layers.IPProtocolTCP,
		Version:    6,
	}, nil}} // no IPv6 fragment in IPv6Packet struct
	tcpLayer := transportLayer{&TCPLayer{&layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}}}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	ip := ipLayer.getLayer().(*layers.IPv6)
	tcpLayer.getTCPLayer().SetNetworkLayerForChecksum(ip)
	_ = gopacket.SerializeLayers(buf, opts, ipLayer.getLayer().(*layers.IPv6), tcpLayer.getTCPLayer())
	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv6, gopacket.Default), &ipLayer, &tcpLayer
}

func TestOutgoingProxy(t *testing.T) {
	proxy := getFakeTunnel()

	_, ip, tcp := getFakePacket("10.19.1.1", "10.30.255.255", 666, 80)
	_, noip, notcp := getFakePacket("10.19.1.1", "10.20.1.1", 666, 80)

	newpacketproxy := proxy.outgoingProxy(ip, tcp)
	newpacketnoproxy := proxy.outgoingProxy(noip, notcp)
	if newpacketnoproxy != nil {
		t.Error("Packet should not be proxied")
	}

	if ipLayer := newpacketproxy.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if tcpLayer := newpacketproxy.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			ipv4, _ := ipLayer.(*layers.IPv4)
			dstexpected := net.ParseIP("10.19.2.12")
			if !ipv4.DstIP.Equal(dstexpected) {
				t.Error("dstIP = ", ipv4.DstIP.String(), "; want =", dstexpected)
			}
			//tcp, _ := tcpLayer.(*layers.TCP)
			//if !(tcp.SrcPort == layers.TCPPort(proxy.TunnelPort)) {
			//	t.Error("srcPort = ", tcp.SrcPort.String(), "; want = ", proxy.TunnelPort)
			//}
		}
	}
}

func TestIngoingProxy(t *testing.T) {
	proxy := getFakeTunnel()

	_, ip, tcp := getFakePacket("10.30.0.5", "10.19.1.15", 666, 777)
	_, noip, notcp := getFakePacket("10.19.2.1", "10.19.1.12", 666, 80)

	//update proxy proxycache

	entry := ConversionEntry{
		srcip:         net.ParseIP("10.19.1.15"),
		dstip:         net.ParseIP("10.19.2.1"),
		dstServiceIp:  net.ParseIP("10.30.255.255"),
		srcInstanceIp: net.ParseIP("10.30.0.50"),
		srcport:       777,
		dstport:       666,
	}
	proxy.proxycache.Add(entry)

	newpacketproxy := proxy.ingoingProxy(ip, tcp)
	newpacketnoproxy := proxy.ingoingProxy(noip, notcp)

	if ipLayer := newpacketproxy.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if tcpLayer := newpacketproxy.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			ipv4, _ := ipLayer.(*layers.IPv4)
			srcexpected := net.ParseIP("10.30.255.255")
			if !ipv4.SrcIP.Equal(srcexpected) {
				t.Error("srcIp = ", ipv4.SrcIP.String(), "; want =", srcexpected)
			}

			//tcp, _ := tcpLayer.(*layers.TCP)
			//if !(int(tcp.DstPort) == entry.srcport) {
			//	t.Error("dstPort = ", int(tcp.DstPort), "; want = ", entry.srcport)
			//}
		}
	}
	if newpacketnoproxy != nil {
		t.Error("Packet should not be proxied")
	}
}

func TestOutgoingV6Proxy(t *testing.T) {
	proxy := getFakeTunnel()

	_, ip, tcp := getFakeV6Packet("fc00::1", "fdff:2000::ff", 666, 80)
	_, noip, notcp := getFakeV6Packet("fc00::1", "fd00::12", 666, 80)

	newpacketproxy := proxy.outgoingProxy(ip, tcp)
	newpacketnoproxy := proxy.outgoingProxy(noip, notcp)
	if newpacketnoproxy != nil {
		t.Error("Packet should not be proxied")
	}

	if ipLayer := newpacketproxy.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		if tcpLayer := newpacketproxy.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			ipv6, _ := ipLayer.(*layers.IPv6)
			dstexpected := net.ParseIP("fd00::12")
			if !ipv6.DstIP.Equal(dstexpected) {
				t.Error("dstIP = ", ipv6.DstIP.String(), "; want =", dstexpected)
			}
		}
	}
}

func TestIngoingV6Proxy(t *testing.T) {
	proxy := getFakeTunnel()

	_, ip, tcp := getFakeV6Packet("fdff::12", "fc00::15", 666, 777)
	_, noip, notcp := getFakeV6Packet("fc00::1", "fd00::12", 666, 80)

	//update proxy proxycache
	entry := ConversionEntry{
		srcip:         net.ParseIP("fc00::15"),
		dstip:         net.ParseIP("fd00::12"),
		dstServiceIp:  net.ParseIP("fdff:3000::ff"),
		srcInstanceIp: net.ParseIP("fdff::12"),
		srcport:       777,
		dstport:       666,
	}
	proxy.proxycache.Add(entry)
	newpacketproxy := proxy.ingoingProxy(ip, tcp)
	newpacketnoproxy := proxy.ingoingProxy(noip, notcp)
	if newpacketnoproxy != nil {
		t.Error("Packet should not be proxied")
	}

	if ipLayer := newpacketproxy.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		if tcpLayer := newpacketproxy.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			ipv6, _ := ipLayer.(*layers.IPv6)
			srcexpected := net.ParseIP("fdff:3000::ff")
			if !ipv6.SrcIP.Equal(srcexpected) {
				t.Error("srcIp = ", ipv6.SrcIP.String(), "; want =", srcexpected)
			}
		}
	}
}
