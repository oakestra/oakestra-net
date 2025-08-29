ProxyBouncer Usage Example

The ProxyBouncer component manages service migration by buffering traffic and
coordinating between source and destination nodes during migration.

## Key Components:

1. **MigrationCandidate**: Represents a service being migrated
2. **LocalMigrationBouncer**: Handles services migrating FROM this node
3. **RemoteMigrationBouncer**: Handles services migrating TO this node
4. **ProxyBouncer**: Main coordinator managing all migration bouncers

## Migration Flow:

### Local Migration (source node):
1. Set LocalMigrationCandidate - starts buffering packets for the migrating service
2. InterceptPacket() buffers all traffic to the service during migration
3. When RemoteMigrationCandidate is set up, buffering stops and traffic is dumped
4. Remove candidates when migration is complete

### Remote Migration (destination node):
1. Set RemoteMigrationCandidate - connects to source node bouncer
2. Requests traffic dump from source node
3. Receives buffered traffic and forwards to local migrated service
4. Remove candidates when migration is complete

## Example Usage:

```go
// Initialize
environment := GetEnvironmentManager()
proxyTunnel := GetProxyTunnel()
bouncer := NewProxyBouncer(environment, proxyTunnel, 8000)

// Source node - service migrating away
localCandidate := MigrationCandidate{
    ServiceIP:     net.ParseIP("10.30.0.100"),
    InstanceIP:    net.ParseIP("10.30.0.101"),
    RemoteNodeIP:  net.ParseIP("192.168.1.200"), // destination
    BouncerPort:   8001,
}
bouncer.SetLocalMigrationCandidate(localCandidate)

// Destination node - service migrating here
remoteCandidate := MigrationCandidate{
    ServiceIP:     net.ParseIP("10.30.0.100"), // same service
    InstanceIP:    net.ParseIP("10.30.0.201"), // new local IP
    RemoteNodeIP:  net.ParseIP("192.168.1.100"), // source
    BouncerPort:   8001,
}
bouncer.SetRemoteMigrationCandidate(remoteCandidate)

// Integration with packet processing
func processPacket(packet []byte, srcIP, dstIP net.IP, srcPort, dstPort int) {
    // Check if packet should be handled by migration bouncer
    if bouncer.InterceptPacket(packet, srcIP, dstIP, srcPort, dstPort) {
        return // Packet was buffered for migration
    }

    // Normal packet processing...
}

// Cleanup after migration
bouncer.RemoveLocalMigrationCandidate(serviceIP)
bouncer.RemoveRemoteMigrationCandidate(serviceIP)
```

## Communication Protocol:

Bouncers communicate via UDP using JSON messages:
- REQUEST_DUMP: Request to start dumping buffered traffic
- DUMP_RESPONSE: Acknowledgment of dump request
- BUFFERED_TRAFFIC: Batch of buffered packets
- HEALTH_CHECK: Connection health verification

## Integration Points:

1. **With ProxyTunnel**: Uses existing packet decoding/encoding and TUN interface
2. **With EnvironmentManager**: Accesses service translation tables
3. **With Main Processing Loop**: InterceptPacket() called during packet processing

## Error Handling:

- Graceful degradation if remote bouncer unavailable
- Buffer overflow protection (oldest packets dropped)
- Timeout handling for network operations
- Proper cleanup on stop/remove operations
*/
