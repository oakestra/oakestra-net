package proxy

import (
	"NetManager/logger"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
)

type IPv4Packet struct {
	*layers.IPv4
}

// IPv4 defragger
var v4defragger = ip4defrag.NewIPv4Defragmenter()

func (packet *IPv4Packet) decodeNetworkLayer(gop gopacket.Packet) {
	ipv4 := gop.Layer(layers.LayerTypeIPv4)
	if ipv4 == nil {
		// not an IPv4 packet
		return
	}
	ipv4Fields := ipv4.(*layers.IPv4)
	packet.IPv4 = ipv4Fields
}

func (packet *IPv4Packet) isNetworkLayer() bool {
	return true
}

func (packet *IPv4Packet) getLayer() gopacket.Layer {
	return packet.IPv4
}

func (packet *IPv4Packet) getProtocolVersion() uint8 {
	return packet.IPv4.Version
}

func (packet *IPv4Packet) getTransportLayer() *transportLayer {
	// TODO discuss this function with Giovanni, since it is ugly as fuck
	if packet == nil {
		logger.ErrorLogger().Println("Got a nil packet")
		return nil
	}
	switch packet.Protocol {
	case layers.IPProtocolUDP:
		logger.DebugLogger().Println("Got a UDP packet to return: ", packet.Protocol)
		udplayer := packet.LayerPayload()
		logger.DebugLogger().Println("UDP packet had payload: ", udplayer)
		udp := &UDPLayer{&layers.UDP{}}
		err := udp.UDP.DecodeFromBytes(udplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv4 UDP packet.")
		}
		logger.DebugLogger().Println("UDP packet returning: ", udp)
		return &transportLayer{udp}
	case layers.IPProtocolTCP:
		logger.DebugLogger().Println("Got a TCP packet to return: ", packet.Protocol)
		tcplayer := packet.LayerPayload()
		logger.DebugLogger().Println("TCP packet had payload: ", tcplayer)
		tcp := &TCPLayer{&layers.TCP{}}
		logger.DebugLogger().Println("TCP packet to be filled: ", tcp)
		err := tcp.TCP.DecodeFromBytes(tcplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv4 TCP packet.")
		}
		logger.DebugLogger().Println("TCP packet returning: ", tcp)
		return &transportLayer{tcp}
	default:
		logger.DebugLogger().Println("Could not determine TransportLayer of IPv4 Packet.")
		return nil
	}
}

func (packet *IPv4Packet) defragment() error {
	ipv4Defrag, err := v4defragger.DefragIPv4(packet.IPv4)
	if err != nil {
		fmt.Println(err)
		return err
	} else if ipv4Defrag == nil {
		return nil // packet fragment, we don't have whole packet yet.
	}
	packet = &IPv4Packet{IPv4: ipv4Defrag}
	return nil
}

func (ip *IPv4Packet) SerializePacket(dstIp net.IP, srcIp net.IP, prot *transportLayer) gopacket.Packet {
	ip.DstIP = dstIp
	ip.SrcIP = srcIp

	if prot.getProtocol() == "TCP" {
		return ip.serializeTCPHeader(prot.getTCPLayer())
	} else {
		return ip.serializeUDPHeader(prot.getUDPLayer())
	}
}

func (ip *IPv4Packet) serializeTCPHeader(tcp *layers.TCP) gopacket.Packet {
	err := tcp.SetNetworkLayerForChecksum(ip.IPv4)
	if err != nil {
		fmt.Println(err)
	}
	return ip.serializeIPHeader(tcp, gopacket.Payload(tcp.Payload))
}

func (ip *IPv4Packet) serializeUDPHeader(udp *layers.UDP) gopacket.Packet {
	err := udp.SetNetworkLayerForChecksum(ip.IPv4)
	if err != nil {
		fmt.Println(err)
	}
	return ip.serializeIPHeader(udp, gopacket.Payload(udp.Payload))
}

func (ip *IPv4Packet) serializeIPHeader(transportLayer gopacket.SerializableLayer, payload gopacket.SerializableLayer) gopacket.Packet {
	newBuffer := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(newBuffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
	if err != nil {
		fmt.Println(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip,
		transportLayer,
		payload,
	)
	if err != nil {
		fmt.Printf("packet serialization failure %v\n", err)
		return nil
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
}

func (packet *IPv4Packet) getDestIP() net.IP {
	return packet.DstIP
}

func (packet *IPv4Packet) getSrcIP() net.IP {
	return packet.SrcIP
}
