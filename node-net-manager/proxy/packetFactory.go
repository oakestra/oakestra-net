package proxy

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type networkLayerPacket interface {
	isNetworkLayer() bool
	getLayer() gopacket.Layer
	decodeNetworkLayer(p gopacket.Packet)
	getTransportLayer() transportLayerProtocol
	defragment() error
	getSrcIP() net.IP
	getDestIP() net.IP
	getProtocolVersion() uint8
	getNextHeader() uint8
	SerializePacket(net.IP, net.IP, transportLayerProtocol) gopacket.Packet
	serializeUDPHeader(*layers.UDP) gopacket.Packet
	serializeTCPHeader(*layers.TCP) gopacket.Packet
}

type networkLayer struct {
	networkLayerPacket
}

func newNetworkLayerPacket(ipt layers.IPProtocol, nl gopacket.NetworkLayer) networkLayerPacket {
	if ipt == layers.IPProtocolIPv4 {
		return newIPv4Packet(nl)
	}
	if ipt == layers.IPProtocolIPv6 {
		return newIPv6Packet(nl)
	}
	return nil
}

func newGoPacket(bytes []byte, ipt layers.IPProtocol) gopacket.Packet {
	if ipt == layers.IPProtocolIPv4 {
		return gopacket.NewPacket(bytes, layers.LayerTypeIPv4, gopacket.Default)
	}
	if ipt == layers.IPProtocolIPv6 {
		return gopacket.NewPacket(bytes, layers.LayerTypeIPv6, gopacket.Default)
	}
	return nil
}
