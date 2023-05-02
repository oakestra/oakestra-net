package proxy

import (
	"github.com/google/gopacket/layers"
)

type transportLayer struct {
	transportLayerProtocol
}

type transportLayerProtocol interface {
	isTransportLayer() bool
	getSourcePort() uint16
	getDestPort() uint16
	getProtocol() string
	getUDPLayer() *layers.UDP
	getTCPLayer() *layers.TCP
}

type UDPLayer struct {
	*layers.UDP
}

type TCPLayer struct {
	*layers.TCP
}

func (l UDPLayer) isTransportLayer() bool {
	return true
}

func (l TCPLayer) isTransportLayer() bool {
	return true
}

func (l UDPLayer) getSourcePort() uint16 {
	return uint16(l.SrcPort)
}

func (l UDPLayer) getDestPort() uint16 {
	return uint16(l.DstPort)
}

func (l TCPLayer) getSourcePort() uint16 {
	return uint16(l.SrcPort)
}

func (l TCPLayer) getDestPort() uint16 {
	return uint16(l.DstPort)
}

func (l TCPLayer) getProtocol() string {
	return "TCP"
}

func (l UDPLayer) getProtocol() string {
	return "UDP"
}

func (l UDPLayer) getUDPLayer() *layers.UDP {
	return l.UDP
}

func (l UDPLayer) getTCPLayer() *layers.TCP {
	return nil
}

func (l TCPLayer) getUDPLayer() *layers.UDP {
	return nil
}

func (l TCPLayer) getTCPLayer() *layers.TCP {
	return l.TCP
}
