# ProxyBouncer - Service Migration Traffic Management

The ProxyBouncer component provides traffic buffering and forwarding capabilities during service migration in Oakestra. It ensures zero-downtime migrations by temporarily buffering traffic for migrating services and then forwarding it to the new destination.

## Architecture

The ProxyBouncer consists of three main components:

### 1. ProxyBouncer (Main Controller)
- Manages all migration scenarios
- Coordinates between local and remote bouncers
- Provides the main API for migration management

### 2. LocalMigrationBouncer (Source Node)
- Buffers traffic for services migrating away from this node
- Runs a UDP server to communicate with remote bouncers
- Dumps buffered traffic when requested by remote bouncer

### 3. RemoteMigrationBouncer (Destination Node)
- Handles services migrating to this node
- Connects to source node bouncer via UDP
- Forwards received traffic to the local migrated service

## Key Features

- **Zero-downtime migration**: Traffic is buffered during migration
- **UDP-based communication**: Simple, efficient inter-bouncer communication
- **Configurable buffering**: Buffer size and duration limits
- **Integration with existing proxy**: Works with ProxyTunnel infrastructure
- **Graceful error handling**: Handles network failures and timeouts

## Usage

### Basic Setup

```go
// Initialize the proxy bouncer
environment := getEnvironmentManager()
proxyTunnel := getProxyTunnel()
basePort := 8000
bouncer := NewProxyBouncer(environment, proxyTunnel, basePort)
```

### Source Node (Service Migrating Away)

```go
// Set up local migration candidate
candidate := MigrationCandidate{
    ServiceIP:     net.ParseIP("10.30.0.100"),     // Service being migrated
    InstanceIP:    net.ParseIP("10.30.0.101"),     // Current instance IP
    RemoteNodeIP:  net.ParseIP("192.168.1.200"),   // Destination node
    BouncerPort:   8001,                           // Port for bouncer communication
    CreatedAt:     time.Now(),
}

err := bouncer.SetLocalMigrationCandidate(candidate)
if err != nil {
    log.Fatalf("Failed to set local migration candidate: %v", err)
}

// Traffic is now being buffered for this service
```

### Destination Node (Service Migrating Here)

```go
// Set up remote migration candidate
candidate := MigrationCandidate{
    ServiceIP:     net.ParseIP("10.30.0.100"),     // Same service IP
    InstanceIP:    net.ParseIP("10.30.0.201"),     // New local instance IP
    RemoteNodeIP:  net.ParseIP("192.168.1.100"),   // Source node
    BouncerPort:   8001,                           // Source bouncer port
    CreatedAt:     time.Now(),
}

err := bouncer.SetRemoteMigrationCandidate(candidate)
if err != nil {
    log.Fatalf("Failed to set remote migration candidate: %v", err)
}

// Buffered traffic will be received and forwarded to local service
```

### Packet Interception

```go
// In main packet processing loop
func processPacket(packet []byte, srcIP, dstIP net.IP, srcPort, dstPort int) {
    // Check if packet should be handled by migration bouncer
    if bouncer.InterceptPacket(packet, srcIP, dstIP, srcPort, dstPort) {
        return // Packet was intercepted and buffered
    }
    
    // Continue with normal packet processing
    // ...
}
```

### Cleanup After Migration

```go
// Remove migration candidates when migration is complete
err = bouncer.RemoveLocalMigrationCandidate(serviceIP)
if err != nil {
    log.Printf("Failed to remove local candidate: %v", err)
}

err = bouncer.RemoveRemoteMigrationCandidate(serviceIP)
if err != nil {
    log.Printf("Failed to remove remote candidate: %v", err)
}
```

## Communication Protocol

Bouncers communicate using JSON messages over UDP:

### Message Types

1. **REQUEST_DUMP**: Remote bouncer requests buffered traffic
2. **DUMP_RESPONSE**: Local bouncer acknowledges dump request
3. **BUFFERED_TRAFFIC**: Local bouncer sends buffered packets
4. **HEALTH_CHECK**: Connection health verification

### Message Format

```go
type BouncerMessage struct {
    MessageType string          `json:"message_type"`
    ServiceIP   string          `json:"service_ip"`
    Packets     []BufferedPacket `json:"packets,omitempty"`
    Timestamp   int64           `json:"timestamp"`
    SenderIP    string          `json:"sender_ip"`
    SenderPort  int             `json:"sender_port"`
}
```

## Integration with ProxyTunnel

The ProxyBouncer is designed to integrate seamlessly with the existing ProxyTunnel:

1. **Packet Decoding**: Uses ProxyTunnel's `decodePacket()` function
2. **Packet Encoding**: Uses ProxyTunnel's `packetToByte()` function  
3. **TUN Interface**: Writes forwarded packets to ProxyTunnel's TUN interface
4. **Environment**: Shares the same EnvironmentManager for service lookups

## Configuration

```go
// Buffer configuration
maxBufferSize := 10000              // Maximum packets to buffer
maxBufferDuration := 30 * time.Second // Maximum time to keep packets

// Port configuration  
baseUDPPort := 8000                 // Base port for bouncer communication
```

## Error Handling

- **Buffer Overflow**: Oldest packets are dropped when buffer is full
- **Network Timeouts**: UDP operations have configurable timeouts
- **Connection Failures**: Graceful degradation when remote bouncer unavailable
- **Graceful Shutdown**: Proper cleanup of resources on stop

## Monitoring and Logging

The component provides detailed logging:

- **Info**: Migration candidate operations, traffic dumps
- **Debug**: Individual packet processing, message exchanges
- **Error**: Network failures, serialization errors

## Thread Safety

All components are thread-safe:

- **Mutex Protection**: Shared data structures are protected
- **Channel Communication**: Goroutines communicate via channels
- **Atomic Operations**: Where appropriate for performance

## Limitations

- **UDP Communication**: No built-in reliability (application handles retries)
- **Memory Usage**: Buffered packets consume memory during migration
- **Network Dependency**: Requires network connectivity between nodes
- **Port Management**: Requires coordination of bouncer ports

## Future Enhancements

- **Compression**: Compress buffered traffic for network efficiency
- **Reliability**: Add retry and acknowledgment mechanisms
- **Metrics**: Expose migration metrics for monitoring
- **Load Balancing**: Support for multi-instance migrations
- **Encryption**: Add security for inter-bouncer communication
