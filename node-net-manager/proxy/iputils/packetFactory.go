package iputils

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type NetworkLayerPacket interface {
	isNetworkLayer() bool
	Layer() gopacket.Layer
	DecodeNetworkLayer(p gopacket.Packet)
	TransportLayer() TransportLayerProtocol
	Defragment() error
	SourceIP() net.IP
	DestinationIP() net.IP
	ProtocolVersion() uint8
	NextHeader() uint8
	SerializePacket(net.IP, net.IP, TransportLayerProtocol) gopacket.Packet
	serializeUDPHeader(*layers.UDP) gopacket.Packet
	serializeTCPHeader(*layers.TCP) gopacket.Packet
}

type NetworkLayer struct {
	NetworkLayerPacket
}

func NewNetworkLayerPacket(ipt layers.IPProtocol, nl gopacket.NetworkLayer) NetworkLayerPacket {
	if ipt == layers.IPProtocolIPv4 {
		return newIPv4Packet(nl)
	}
	return nil
}

func NewGoPacket(bytes []byte, ipt layers.IPProtocol) gopacket.Packet {
	if ipt == layers.IPProtocolIPv4 {
		return gopacket.NewPacket(bytes, layers.LayerTypeIPv4, gopacket.Default)
	}
	return nil
}
