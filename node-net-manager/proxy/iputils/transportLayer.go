package iputils

import (
	"github.com/google/gopacket/layers"
)

type TransportLayer struct {
	TransportLayerProtocol
}

type TransportLayerProtocol interface {
	SourcePort() uint16
	DestPort() uint16
	Protocol() string
	UDPLayer() *layers.UDP
	TCPLayer() *layers.TCP
}

type UDPLayer struct {
	*layers.UDP
}

type TCPLayer struct {
	*layers.TCP
}

func (l UDPLayer) SourcePort() uint16 {
	return uint16(l.SrcPort)
}

func (l UDPLayer) DestPort() uint16 {
	return uint16(l.DstPort)
}

func (l TCPLayer) SourcePort() uint16 {
	return uint16(l.SrcPort)
}

func (l TCPLayer) DestPort() uint16 {
	return uint16(l.DstPort)
}

func (l TCPLayer) Protocol() string {
	return "TCP"
}

func (l UDPLayer) Protocol() string {
	return "UDP"
}

func (l UDPLayer) UDPLayer() *layers.UDP {
	return l.UDP
}

func (l UDPLayer) TCPLayer() *layers.TCP {
	return nil
}

func (l TCPLayer) UDPLayer() *layers.UDP {
	return nil
}

func (l TCPLayer) TCPLayer() *layers.TCP {
	return l.TCP
}
