package gateway

import (
	"NetManager/logger"
	"NetManager/network"
	"NetManager/proxy"
	"net"

	"github.com/coreos/go-iptables/iptables"
)

type ServiceExposer interface {
	EnableServiceExposure(string, net.IP, int, int) error
	DisableServiceExposure(string) error
}

/*
* idea for possible firewall configuration
type FirewallConfiguration struct {
	iptable4        network.IpTable
	iptable6        network.IpTable
	exposedServices map[string]ServiceEntry
	exposedPorts    map[int]bool
	FirewallID      string
	publicInterface string
	publicIPv4      net.IP
	publicIPv6      net.IP
}
*/

type ServiceEntry struct {
	serviceIP   net.IP
	servicePort int
	exposedPort int
}

var Exposer ServiceExposer

func StartGatewayProcess(id string, gatewayServiceName string, gatewayIPv4 net.IP, gatewayIPv6 net.IP, instanceIPv4 net.IP, instanceIPv6 net.IP) *GatewayConfiguration {
	ip, ifaceName := network.GetLocalIPandIface()
	if gatewayIPv4.String() != ip && gatewayIPv6.String() != ip {
		return nil
	}
	bridgeIPs, err := network.GetInterfaceIPByName("goProxyBridge")
	if err != nil {
		return nil
	}
	logger.InfoLogger().Println("Configuring Gateway")
	config := &GatewayConfiguration{
		GatewayID:        id,
		gatewayName:      gatewayServiceName,
		gatewayIPv4:      gatewayIPv4,
		gatewayIPv6:      gatewayIPv6,
		gatewayInterface: ifaceName,
		instanceIPv4:     instanceIPv4,
		instanceIPv6:     instanceIPv6,
		bridgeIPv4:       bridgeIPs[0],
		bridgeIPv6:       bridgeIPs[1],
		oakestraTunnel:   proxy.Proxy().HostTUNDeviceName,
		oakestraBridge:   "goProxyBridge",
		exposedServices:  make(map[string]ServiceEntry),
		exposedPorts:     make(map[int]bool),
		iptable4:         network.NewOakestraIPTable(iptables.ProtocolIPv4),
		iptable6:         network.NewOakestraIPTable(iptables.ProtocolIPv6),
	}

	err = config.enableForwarding()
	if err != nil {
		logger.ErrorLogger().Println("Cannot enable forwarding")
		return nil
	}

	Exposer = config

	err = config.configureProxy()
	if err != nil {
		logger.ErrorLogger().Println("Cannot set up proxyTable")
		return nil
	}
	logger.InfoLogger().Println("Gateway configured.")
	return config
}
