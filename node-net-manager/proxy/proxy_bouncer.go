package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/env"
	"NetManager/logger"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// MigrationCandidate represents a service that is being migrated
type MigrationCandidate struct {
	ServiceIP      net.IP                     `json:"service_ip"`
	InstanceIP     net.IP                     `json:"instance_ip"`
	TableEntry     TableEntryCache.TableEntry `json:"table_entry"`
	RemoteNodeIP   net.IP                     `json:"remote_node_ip"`
	RemoteNodePort int                        `json:"remote_node_port"`
	BouncerPort    int                        `json:"bouncer_port"`
	CreatedAt      time.Time                  `json:"created_at"`
}

// BufferedPacket represents a packet that has been buffered during migration
type BufferedPacket struct {
	Data      []byte    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
	SrcAddr   net.IP    `json:"src_addr"`
	DstAddr   net.IP    `json:"dst_addr"`
	SrcPort   int       `json:"src_port"`
	DstPort   int       `json:"dst_port"`
}

// BouncerMessage represents a message sent between bouncers via UDP
type BouncerMessage struct {
	MessageType string           `json:"message_type"`
	ServiceIP   string           `json:"service_ip"`
	Data        []byte           `json:"data,omitempty"`
	Packets     []BufferedPacket `json:"packets,omitempty"`
	Timestamp   int64            `json:"timestamp"`
	SenderIP    string           `json:"sender_ip"`
	SenderPort  int              `json:"sender_port"`
}

// Message types
const (
	MSG_REQUEST_DUMP     = "REQUEST_DUMP"
	MSG_DUMP_RESPONSE    = "DUMP_RESPONSE"
	MSG_BUFFERED_TRAFFIC = "BUFFERED_TRAFFIC"
	MSG_HEALTH_CHECK     = "HEALTH_CHECK"
)

// LocalMigrationBouncer handles traffic for services that have migrated locally
type LocalMigrationBouncer struct {
	candidate         MigrationCandidate
	packetBuffer      []BufferedPacket
	bufferMutex       sync.RWMutex
	maxBufferSize     int
	maxBufferDuration time.Duration
	remoteBouncer     *RemoteMigrationBouncer
	isBuffering       bool
	bufferChannel     chan BufferedPacket
	stopChannel       chan bool
	environment       env.EnvironmentManager
	udpServer         *net.UDPConn
	udpServerPort     int
}

// RemoteMigrationBouncer handles communication with remote migration bouncers
type RemoteMigrationBouncer struct {
	candidate      MigrationCandidate
	localBouncer   *LocalMigrationBouncer
	proxyTunnel    *GoProxyTunnel
	isReceiving    bool
	receiveChannel chan []byte
	stopChannel    chan bool
	environment    env.EnvironmentManager
	udpClient      *net.UDPConn
	remoteAddr     *net.UDPAddr
}

// ProxyBouncer manages all migration bouncers
type ProxyBouncer struct {
	localBouncers  map[string]*LocalMigrationBouncer
	remoteBouncers map[string]*RemoteMigrationBouncer
	mutex          sync.RWMutex
	environment    env.EnvironmentManager
	proxyTunnel    *GoProxyTunnel
	baseUDPPort    int
}

// NewProxyBouncer creates a new ProxyBouncer instance
func NewProxyBouncer(environment env.EnvironmentManager, proxyTunnel *GoProxyTunnel, baseUDPPort int) *ProxyBouncer {
	return &ProxyBouncer{
		localBouncers:  make(map[string]*LocalMigrationBouncer),
		remoteBouncers: make(map[string]*RemoteMigrationBouncer),
		mutex:          sync.RWMutex{},
		environment:    environment,
		proxyTunnel:    proxyTunnel,
		baseUDPPort:    baseUDPPort,
	}
}

// SetLocalMigrationCandidate creates a local migration bouncer for a service
func (pb *ProxyBouncer) SetLocalMigrationCandidate(candidate MigrationCandidate) error {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	serviceKey := candidate.ServiceIP.String()
	if _, exists := pb.localBouncers[serviceKey]; exists {
		return fmt.Errorf("local migration candidate already exists for service %s", serviceKey)
	}

	bouncer := &LocalMigrationBouncer{
		candidate:         candidate,
		packetBuffer:      make([]BufferedPacket, 0),
		bufferMutex:       sync.RWMutex{},
		maxBufferSize:     10000,            // Maximum number of packets to buffer
		maxBufferDuration: 30 * time.Second, // Maximum time to keep packets in buffer
		isBuffering:       true,
		bufferChannel:     make(chan BufferedPacket, 1000),
		stopChannel:       make(chan bool),
		environment:       pb.environment,
		udpServerPort:     candidate.BouncerPort,
	}

	pb.localBouncers[serviceKey] = bouncer

	// Start buffering goroutine
	go bouncer.startBuffering()

	// Start UDP server for this bouncer
	go bouncer.startUDPServer()

	logger.InfoLogger().Printf("Local migration candidate set for service %s", serviceKey)
	return nil
}

// SetRemoteMigrationCandidate creates a remote migration bouncer for a service
func (pb *ProxyBouncer) SetRemoteMigrationCandidate(candidate MigrationCandidate) error {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	serviceKey := candidate.ServiceIP.String()
	if _, exists := pb.remoteBouncers[serviceKey]; exists {
		return fmt.Errorf("remote migration candidate already exists for service %s", serviceKey)
	}

	// Create UDP connection to remote bouncer
	address := fmt.Sprintf("%s:%d", candidate.RemoteNodeIP.String(), candidate.BouncerPort)
	remoteAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return fmt.Errorf("failed to resolve remote bouncer address: %v", err)
	}

	udpConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to remote bouncer: %v", err)
	}

	bouncer := &RemoteMigrationBouncer{
		candidate:      candidate,
		udpClient:      udpConn,
		remoteAddr:     remoteAddr,
		proxyTunnel:    pb.proxyTunnel,
		isReceiving:    false,
		receiveChannel: make(chan []byte, 1000),
		stopChannel:    make(chan bool),
		environment:    pb.environment,
	}

	pb.remoteBouncers[serviceKey] = bouncer

	// Request traffic dump from remote bouncer
	go bouncer.requestTrafficDump()

	// Check if there's a corresponding local bouncer and link them
	if localBouncer, exists := pb.localBouncers[serviceKey]; exists {
		localBouncer.remoteBouncer = bouncer
		bouncer.localBouncer = localBouncer
		// Stop buffering and start dumping
		localBouncer.isBuffering = false
		go localBouncer.dumpBufferedTraffic()
	}

	logger.InfoLogger().Printf("Remote migration candidate set for service %s", serviceKey)
	return nil
}

// RemoveLocalMigrationCandidate removes a local migration bouncer
func (pb *ProxyBouncer) RemoveLocalMigrationCandidate(serviceIP net.IP) error {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	serviceKey := serviceIP.String()
	bouncer, exists := pb.localBouncers[serviceKey]
	if !exists {
		return fmt.Errorf("local migration candidate not found for service %s", serviceKey)
	}

	// Stop bouncer
	bouncer.stop()
	delete(pb.localBouncers, serviceKey)

	logger.InfoLogger().Printf("Local migration candidate removed for service %s", serviceKey)
	return nil
}

// RemoveRemoteMigrationCandidate removes a remote migration bouncer
func (pb *ProxyBouncer) RemoveRemoteMigrationCandidate(serviceIP net.IP) error {
	pb.mutex.Lock()
	defer pb.mutex.Unlock()

	serviceKey := serviceIP.String()
	bouncer, exists := pb.remoteBouncers[serviceKey]
	if !exists {
		return fmt.Errorf("remote migration candidate not found for service %s", serviceKey)
	}

	// Stop bouncer
	bouncer.stop()
	delete(pb.remoteBouncers, serviceKey)

	logger.InfoLogger().Printf("Remote migration candidate removed for service %s", serviceKey)
	return nil
}

// InterceptPacket intercepts packets that should be handled by migration bouncers
func (pb *ProxyBouncer) InterceptPacket(packet []byte, srcIP, dstIP net.IP, srcPort, dstPort int) bool {
	pb.mutex.RLock()
	defer pb.mutex.RUnlock()

	serviceKey := dstIP.String()

	// Check if this packet is for a local migration candidate
	if localBouncer, exists := pb.localBouncers[serviceKey]; exists {
		if localBouncer.isBuffering {
			// Buffer the packet
			bufferedPacket := BufferedPacket{
				Data:      packet,
				Timestamp: time.Now(),
				SrcAddr:   srcIP,
				DstAddr:   dstIP,
				SrcPort:   srcPort,
				DstPort:   dstPort,
			}

			select {
			case localBouncer.bufferChannel <- bufferedPacket:
				return true // Packet intercepted and buffered
			default:
				logger.ErrorLogger().Printf("Buffer channel full for service %s, dropping packet", serviceKey)
				return true // Still intercepted, but dropped
			}
		}
	}

	return false // Packet not intercepted
}

// LocalMigrationBouncer methods

func (lmb *LocalMigrationBouncer) startBuffering() {
	logger.InfoLogger().Printf("Started buffering for service %s", lmb.candidate.ServiceIP.String())

	for {
		select {
		case packet := <-lmb.bufferChannel:
			lmb.bufferMutex.Lock()

			// Check buffer size limit
			if len(lmb.packetBuffer) >= lmb.maxBufferSize {
				// Remove oldest packet
				lmb.packetBuffer = lmb.packetBuffer[1:]
			}

			lmb.packetBuffer = append(lmb.packetBuffer, packet)
			lmb.bufferMutex.Unlock()

			logger.DebugLogger().Printf("Buffered packet for service %s, buffer size: %d",
				lmb.candidate.ServiceIP.String(), len(lmb.packetBuffer))

		case <-lmb.stopChannel:
			logger.InfoLogger().Printf("Stopped buffering for service %s", lmb.candidate.ServiceIP.String())
			return
		}
	}
}

func (lmb *LocalMigrationBouncer) dumpBufferedTraffic() {
	if lmb.remoteBouncer == nil {
		logger.ErrorLogger().Printf("No remote bouncer available for service %s", lmb.candidate.ServiceIP.String())
		return
	}

	lmb.bufferMutex.RLock()
	packets := make([]BufferedPacket, len(lmb.packetBuffer))
	copy(packets, lmb.packetBuffer)
	lmb.bufferMutex.RUnlock()

	if len(packets) == 0 {
		logger.InfoLogger().Printf("No buffered packets to dump for service %s", lmb.candidate.ServiceIP.String())
		return
	}

	// Create bouncer message
	message := BouncerMessage{
		MessageType: MSG_BUFFERED_TRAFFIC,
		ServiceIP:   lmb.candidate.ServiceIP.String(),
		Packets:     packets,
		Timestamp:   time.Now().Unix(),
		SenderIP:    lmb.candidate.RemoteNodeIP.String(), // Our local IP from remote perspective
		SenderPort:  lmb.udpServerPort,
	}

	// Serialize message
	messageBytes, err := json.Marshal(message)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to serialize buffered traffic message: %v", err)
		return
	}

	// Send to remote bouncer
	_, err = lmb.remoteBouncer.udpClient.Write(messageBytes)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to send buffered traffic for service %s: %v",
			lmb.candidate.ServiceIP.String(), err)
		return
	}

	logger.InfoLogger().Printf("Successfully dumped %d buffered packets for service %s",
		len(packets), lmb.candidate.ServiceIP.String())

	// Clear buffer after successful dump
	lmb.bufferMutex.Lock()
	lmb.packetBuffer = lmb.packetBuffer[:0]
	lmb.bufferMutex.Unlock()
}

func (lmb *LocalMigrationBouncer) startUDPServer() {
	address := fmt.Sprintf(":%d", lmb.udpServerPort)
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to resolve UDP address %s: %v", address, err)
		return
	}

	lmb.udpServer, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to listen on UDP port %d: %v", lmb.udpServerPort, err)
		return
	}

	logger.InfoLogger().Printf("Local bouncer UDP server listening on %s", address)

	// Start message handler
	go lmb.handleUDPMessages()
}

func (lmb *LocalMigrationBouncer) handleUDPMessages() {
	buffer := make([]byte, 64*1024) // 64KB buffer

	for {
		select {
		case <-lmb.stopChannel:
			return
		default:
			lmb.udpServer.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := lmb.udpServer.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout is expected for graceful shutdown
				}
				logger.ErrorLogger().Printf("UDP read error: %v", err)
				continue
			}

			// Parse message
			var message BouncerMessage
			err = json.Unmarshal(buffer[:n], &message)
			if err != nil {
				logger.ErrorLogger().Printf("Failed to parse bouncer message: %v", err)
				continue
			}

			logger.DebugLogger().Printf("Received message type %s from %s", message.MessageType, clientAddr.String())

			switch message.MessageType {
			case MSG_REQUEST_DUMP:
				lmb.handleDumpRequest(&message, clientAddr)
			case MSG_HEALTH_CHECK:
				lmb.handleHealthCheck(&message, clientAddr)
			}
		}
	}
}

func (lmb *LocalMigrationBouncer) handleDumpRequest(message *BouncerMessage, clientAddr *net.UDPAddr) {
	logger.InfoLogger().Printf("Received traffic dump request for service %s from %s",
		message.ServiceIP, clientAddr.String())

	// Send response
	response := BouncerMessage{
		MessageType: MSG_DUMP_RESPONSE,
		ServiceIP:   message.ServiceIP,
		Timestamp:   time.Now().Unix(),
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to serialize dump response: %v", err)
		return
	}

	_, err = lmb.udpServer.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to send dump response: %v", err)
		return
	}

	// Stop buffering and start dumping
	lmb.isBuffering = false
	go lmb.dumpBufferedTraffic()
}

func (lmb *LocalMigrationBouncer) handleHealthCheck(message *BouncerMessage, clientAddr *net.UDPAddr) {
	response := BouncerMessage{
		MessageType: MSG_HEALTH_CHECK,
		ServiceIP:   message.ServiceIP,
		Timestamp:   time.Now().Unix(),
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to serialize health check response: %v", err)
		return
	}

	_, err = lmb.udpServer.WriteToUDP(responseBytes, clientAddr)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to send health check response: %v", err)
	}
}

func (lmb *LocalMigrationBouncer) stop() {
	close(lmb.stopChannel)
	if lmb.udpServer != nil {
		lmb.udpServer.Close()
	}
}

// RemoteMigrationBouncer methods

func (rmb *RemoteMigrationBouncer) requestTrafficDump() {
	message := BouncerMessage{
		MessageType: MSG_REQUEST_DUMP,
		ServiceIP:   rmb.candidate.ServiceIP.String(),
		Timestamp:   time.Now().Unix(),
		SenderIP:    rmb.candidate.RemoteNodeIP.String(), // Our local IP from remote perspective
		SenderPort:  rmb.candidate.BouncerPort,
	}

	messageBytes, err := json.Marshal(message)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to serialize traffic dump request: %v", err)
		return
	}

	_, err = rmb.udpClient.Write(messageBytes)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to request traffic dump for service %s: %v",
			rmb.candidate.ServiceIP.String(), err)
		return
	}

	logger.InfoLogger().Printf("Successfully requested traffic dump for service %s",
		rmb.candidate.ServiceIP.String())

	// Start listening for responses
	go rmb.listenForMessages()
}

func (rmb *RemoteMigrationBouncer) listenForMessages() {
	buffer := make([]byte, 64*1024) // 64KB buffer

	for {
		select {
		case <-rmb.stopChannel:
			return
		default:
			rmb.udpClient.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := rmb.udpClient.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue // Timeout is expected for graceful shutdown
				}
				logger.ErrorLogger().Printf("UDP read error: %v", err)
				continue
			}

			// Parse message
			var message BouncerMessage
			err = json.Unmarshal(buffer[:n], &message)
			if err != nil {
				logger.ErrorLogger().Printf("Failed to parse bouncer message: %v", err)
				continue
			}

			logger.DebugLogger().Printf("Received message type %s", message.MessageType)

			switch message.MessageType {
			case MSG_DUMP_RESPONSE:
				rmb.handleDumpResponse(&message)
			case MSG_BUFFERED_TRAFFIC:
				rmb.handleBufferedTraffic(&message)
			}
		}
	}
}

func (rmb *RemoteMigrationBouncer) handleDumpResponse(message *BouncerMessage) {
	logger.InfoLogger().Printf("Received dump response for service %s", message.ServiceIP)
	rmb.isReceiving = true
}

func (rmb *RemoteMigrationBouncer) handleBufferedTraffic(message *BouncerMessage) {
	logger.InfoLogger().Printf("Received %d buffered packets for service %s",
		len(message.Packets), message.ServiceIP)

	processedCount := 0
	for _, packet := range message.Packets {
		// Forward each packet to the local service
		rmb.forwardToLocalService(packet.Data)
		processedCount++
	}

	logger.InfoLogger().Printf("Processed %d buffered packets for service %s",
		processedCount, message.ServiceIP)
}

func (rmb *RemoteMigrationBouncer) forwardToLocalService(packetData []byte) {
	// Use ProxyTunnel methods to forward the packet to the local migrated application
	ip, prot := decodePacket(packetData)
	if ip == nil {
		logger.DebugLogger().Println("Failed to decode packet for local forwarding")
		return
	}

	// Update destination to local service
	newPacket := ip.SerializePacket(rmb.candidate.InstanceIP, ip.GetSrcIP(), prot)
	if newPacket == nil {
		logger.ErrorLogger().Println("Failed to serialize packet for local forwarding")
		return
	}

	// Write to TUN interface for local delivery
	packetBytes := packetToByte(newPacket)
	_, err := rmb.proxyTunnel.ifce.Write(packetBytes)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to write packet to TUN interface: %v", err)
	}
}

func (rmb *RemoteMigrationBouncer) stop() {
	close(rmb.stopChannel)
	if rmb.udpClient != nil {
		rmb.udpClient.Close()
	}
}
