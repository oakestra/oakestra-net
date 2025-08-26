package proxy

/*
Integration Guide: Adding ProxyBouncer to ProxyTunnel

This guide shows how to integrate the ProxyBouncer component with the existing
ProxyTunnel to support service migration scenarios.

## Steps for Integration:

### 1. Add ProxyBouncer to GoProxyTunnel struct:

```go
type GoProxyTunnel struct {
    // ... existing fields ...

    // Add proxy bouncer for migration support
    proxyBouncer    *ProxyBouncer
}
```

### 2. Initialize ProxyBouncer in constructor:

```go
func NewGoProxyTunnel(config Configuration, environment env.EnvironmentManager) *GoProxyTunnel {
    proxy := &GoProxyTunnel{
        // ... existing initialization ...
    }

    // Initialize proxy bouncer with base UDP port
    baseUDPPort := config.TunnelPort + 1000 // Use different port range
    proxy.proxyBouncer = NewProxyBouncer(environment, proxy, baseUDPPort)

    return proxy
}
```

### 3. Integrate with packet processing in outgoingMessage():

```go
func (proxy *GoProxyTunnel) outgoingMessage() {
    for {
        select {
        case msg := <-proxy.outgoingChannel:
            ip, prot := decodePacket(*msg.content)
            if ip == nil {
                continue
            }

            // Extract packet information
            srcIP := ip.GetSrcIP()
            dstIP := ip.GetDestIP()
            srcPort, dstPort := -1, -1
            if prot != nil {
                srcPort = int(prot.GetSourcePort())
                dstPort = int(prot.GetDestPort())
            }

            // Check if packet should be handled by migration bouncer
            if proxy.proxyBouncer.InterceptPacket(*msg.content, srcIP, dstIP, srcPort, dstPort) {
                continue // Packet intercepted and buffered
            }

            // ... existing proxy logic ...
        }
    }
}
```

### 4. Add migration management methods to GoProxyTunnel:

```go
// Migration management methods
func (proxy *GoProxyTunnel) SetLocalMigrationCandidate(candidate MigrationCandidate) error {
    return proxy.proxyBouncer.SetLocalMigrationCandidate(candidate)
}

func (proxy *GoProxyTunnel) SetRemoteMigrationCandidate(candidate MigrationCandidate) error {
    return proxy.proxyBouncer.SetRemoteMigrationCandidate(candidate)
}

func (proxy *GoProxyTunnel) RemoveLocalMigrationCandidate(serviceIP net.IP) error {
    return proxy.proxyBouncer.RemoveLocalMigrationCandidate(serviceIP)
}

func (proxy *GoProxyTunnel) RemoveRemoteMigrationCandidate(serviceIP net.IP) error {
    return proxy.proxyBouncer.RemoveRemoteMigrationCandidate(serviceIP)
}
```

### 5. Update configuration to include bouncer settings:

```go
type Configuration struct {
    // ... existing fields ...

    // Migration bouncer settings
    BouncerBasePort   int    `json:"BouncerBasePort"`
    BufferMaxSize     int    `json:"BufferMaxSize"`
    BufferMaxDuration int    `json:"BufferMaxDuration"` // seconds
}
```

### 6. Usage example in main application:

```go
func handleMigration(proxyTunnel *GoProxyTunnel, serviceIP, destinationIP net.IP, destinationPort int) error {
    // Create migration candidate
    candidate := MigrationCandidate{
        ServiceIP:      serviceIP,
        InstanceIP:     getInstanceIP(serviceIP),
        RemoteNodeIP:   destinationIP,
        BouncerPort:    destinationPort,
        CreatedAt:      time.Now(),
    }

    // Set up local migration (source node)
    err := proxyTunnel.SetLocalMigrationCandidate(candidate)
    if err != nil {
        return fmt.Errorf("failed to set local migration candidate: %v", err)
    }

    // Later, when migration is complete
    defer proxyTunnel.RemoveLocalMigrationCandidate(serviceIP)

    return nil
}
```

## Configuration Example:

```json
{
    "HostTunnelDeviceName": "oakestra",
    "ProxySubnetwork": "10.30.0.0",
    "ProxySubnetworkMask": "255.255.0.0",
    "TunnelIP": "192.168.1.100",
    "TunnelPort": 6000,
    "MTUSize": 1500,
    "BouncerBasePort": 7000,
    "BufferMaxSize": 10000,
    "BufferMaxDuration": 30
}
```

## Error Handling:

```go
func (proxy *GoProxyTunnel) handleMigrationError(err error, serviceIP net.IP) {
    logger.ErrorLogger().Printf("Migration error for service %s: %v", serviceIP.String(), err)

    // Cleanup partial migration state
    proxy.RemoveLocalMigrationCandidate(serviceIP)
    proxy.RemoveRemoteMigrationCandidate(serviceIP)
}
```

## Testing:

```go
func TestMigrationIntegration(t *testing.T) {
    // Create test environment
    env := createTestEnvironment()
    config := Configuration{
        TunnelPort: 6000,
        BouncerBasePort: 7000,
    }

    proxyTunnel := NewGoProxyTunnel(config, env)

    // Test local migration setup
    candidate := MigrationCandidate{
        ServiceIP: net.ParseIP("10.30.0.100"),
        // ... other fields
    }

    err := proxyTunnel.SetLocalMigrationCandidate(candidate)
    assert.NoError(t, err)

    // Test packet interception
    packet := createTestPacket()
    intercepted := proxyTunnel.proxyBouncer.InterceptPacket(
        packet, net.ParseIP("10.30.0.1"), net.ParseIP("10.30.0.100"), 8080, 80)
    assert.True(t, intercepted)

    // Cleanup
    err = proxyTunnel.RemoveLocalMigrationCandidate(candidate.ServiceIP)
    assert.NoError(t, err)
}
```
*/
