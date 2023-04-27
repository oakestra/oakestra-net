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

func (packet *IPv4Packet) decodeNetworkLayer() {
	srcIP := packet.SrcIP.String()
	dstIP := packet.DstIP.String()
	fmt.Printf("Received IPv4 packet from %s to %s\n", srcIP, dstIP)
}

func (packet *IPv4Packet) isNetworkLayer() bool {
	return true
}

func (packet *IPv4Packet) getLayer() gopacket.Layer {
	return packet.IPv4
}

func (packet *IPv4Packet) getTransportLayer() *transportLayerProtocol {
	switch packet.Protocol {
	case layers.IPProtocolUDP:
		udplayer := packet.LayerPayload()
		udp := &layers.UDP{}
		err := udp.DecodeFromBytes(udplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv4 UDP packet.")
		}
		return &transportLayerProtocol{UDP: udp, TCP: nil}
	case layers.IPProtocolTCP:
		tcplayer := packet.LayerPayload()
		tcp := &layers.TCP{}
		err := tcp.DecodeFromBytes(tcplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv4 TCP packet.")
		}
		return &transportLayerProtocol{UDP: nil, TCP: tcp}
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

func (ip *IPv4Packet) SerializePacket(dstIp net.IP, srcIp net.IP, tcp *layers.TCP, udp *layers.UDP) gopacket.Packet {
	ip.DstIP = dstIp
	ip.SrcIP = srcIp

	if tcp != nil {
		return ip.serializeTcpPacket(tcp)
	} else {
		return ip.serializeUdpPacket(udp)
	}
}

func (ip *IPv4Packet) serializeTcpPacket(tcp *layers.TCP) gopacket.Packet {
	err := tcp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		fmt.Println(err)
	}
	return ip.serializeIpPacket(tcp, gopacket.Payload(tcp.Payload))
}

func (ip *IPv4Packet) serializeUdpPacket(udp *layers.UDP) gopacket.Packet {
	err := udp.SetNetworkLayerForChecksum(ip)
	if err != nil {
		fmt.Println(err)
	}
	return ip.serializeIpPacket(udp, gopacket.Payload(udp.Payload))
}

func (ip *IPv4Packet) serializeIpPacket(transportLayer gopacket.SerializableLayer, payload gopacket.SerializableLayer) gopacket.Packet {
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
