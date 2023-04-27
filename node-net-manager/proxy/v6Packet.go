package proxy

import (
	"NetManager/logger"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sipcapture/heplify/ip6defrag"
)

type IPv6Packet struct {
	*layers.IPv6
	*layers.IPv6Fragment
}

// IPv6 defragger
var v6defragger = ip6defrag.NewIPv6Defragmenter()

func (packet *IPv6Packet) isNetworkLayer() bool {
	return true
}

func (packet *IPv6Packet) getLayer() gopacket.Layer {
	return packet.IPv6
}

func (packet *IPv6Packet) decodeNetworkLayer() {
	srcIP := packet.SrcIP.String()
	dstIP := packet.DstIP.String()
	fmt.Printf("Received IPv6 packet from %s to %s\n", srcIP, dstIP)
	if packet.IPv6Fragment != nil {
		fmt.Println("Also received an IPv6Fragment: ", packet.IPv6Fragment.LayerPayload())
	}
}

func (packet *IPv6Packet) defragment() error {
	ipv6Defrag, err := v6defragger.DefragIPv6(packet.IPv6, packet.IPv6Fragment)
	if err != nil {
		fmt.Println(err)
		return err
	} else if ipv6Defrag == nil {
		return fmt.Errorf("packet was a fragment. Saved state and waiting for rest")
	}
	packet.IPv6 = ipv6Defrag
	return nil
}

func (packet *IPv6Packet) getTransportLayer() *transportLayerProtocol {
	switch packet.IPv6.NextHeader {
	case layers.IPProtocolUDP:
		udplayer := packet.IPv6.LayerPayload()
		udp := &layers.UDP{}
		err := udp.DecodeFromBytes(udplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv6 UDP packet.")
		}
		return &transportLayerProtocol{UDP: udp, TCP: nil}
	case layers.IPProtocolTCP:
		tcplayer := packet.IPv6.LayerPayload()
		tcp := &layers.TCP{}
		err := tcp.DecodeFromBytes(tcplayer, gopacket.NilDecodeFeedback)
		if err != nil {
			logger.ErrorLogger().Println("Could not decode IPv6 TCP packet.")
		}
		return &transportLayerProtocol{UDP: nil, TCP: tcp}
	default:
		return nil
	}
}
func (ip *IPv6Packet) serializeIpPacket(transportLayer gopacket.SerializableLayer, payload gopacket.SerializableLayer) gopacket.Packet {
	newBuffer := gopacket.NewSerializeBuffer()
	err := ip.SerializeTo(newBuffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true})
	if err != nil {
		fmt.Println(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(
		buffer,
		gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip.IPv6,
		transportLayer,
		payload,
	)
	if err != nil {
		fmt.Printf("packet serialization failure %v\n", err)
		return nil
	}

	return gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
}
