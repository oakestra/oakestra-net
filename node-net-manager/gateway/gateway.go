package gateway

import (
	"NetManager/TableEntryCache"
	"NetManager/logger"
	"NetManager/network"
	"NetManager/proxy"
	"fmt"
	"net"
	"strconv"
)

// implements ServiceExposer
type GatewayConfiguration struct {
	iptable6         network.IpTable
	iptable4         network.IpTable
	exposedServices  map[string]ServiceEntry
	exposedPorts     map[int]bool
	gatewayName      string
	gatewayInterface string
	GatewayID        string
	oakestraTunnel   string
	oakestraBridge   string
	instanceIPv6     net.IP
	bridgeIPv6       net.IP
	bridgeIPv4       net.IP
	instanceIPv4     net.IP
	gatewayIPv6      net.IP
	gatewayIPv4      net.IP
}

func (gw *GatewayConfiguration) configureProxy() error {
	gatewayEntry := &TableEntryCache.TableEntry{
		JobName:          gw.gatewayName,
		Appname:          "a",
		Appns:            "b",
		Servicename:      "c",
		Servicenamespace: "d",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           gw.gatewayIPv4,
		Nodeport:         proxy.Proxy().TunnelPort,
		Nsip:             gw.bridgeIPv4,
		Nsipv6:           gw.bridgeIPv6,
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     0, // InstanceIP
			Address:    gw.instanceIPv4,
			Address_v6: gw.instanceIPv6,
		}},
	}
	logger.InfoLogger().Println("Adding Entry:", gatewayEntry)
	proxy.Proxy().Env().AddTableQueryEntry(*gatewayEntry)

	entry, ok := proxy.Proxy().Env().GetTableEntryByInstanceIP(gw.instanceIPv4)
	// selfcheck
	if !ok {
		return fmt.Errorf("could not find recently added entry by instanceIP")
	}
	logger.InfoLogger().Println("Successfully added Entry and found by InstanceIP:", entry)

	entry, ok = proxy.Proxy().Env().GetTableEntryByNsIP(gw.bridgeIPv4)
	if !ok {
		return fmt.Errorf("could not find recently added entry by instanceIP")
	}
	logger.InfoLogger().Println("Successfully added Entry and found by NsIP:", entry)
	return nil
}

func (gw *GatewayConfiguration) EnableServiceExposure(serviceID string, serviceIP net.IP, servicePort int, exposedPort int) error {
	logger.InfoLogger().Printf("Enabling: %s with %s:%d - opening %d", serviceID, serviceIP.String(), servicePort, exposedPort)
	// rules are set up by the order they are hit
	if serviceIP.To4() != nil {
		// PREROUTING
		// rewrites destination to be the service inside oakestra
		err := gw.iptable4.AppendUnique("nat", "PREROUTING",
			"-i", gw.gatewayInterface,
			"-p", "tcp", // tcp only
			"-d", gw.gatewayIPv4.String(), // destination gateway public IP
			"--dport", strconv.Itoa(exposedPort), // to the exposed service port
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("%s:%d", serviceIP.String(), servicePort)) // change destination to serviceIP:servicePort
		if err != nil {
			logger.ErrorLogger().Println("Error in PREROUTING iptable4 rule.")
			return err
		}

		// FORWARD
		// enable forwarding to service destination port
		err = gw.iptable4.AppendUnique("filter", "FORWARD",
			"-i", gw.gatewayInterface,
			"-o", gw.oakestraTunnel,
			"-p", "tcp", "--syn",
			"--dport", strconv.Itoa(servicePort),
			"-m", "conntrack",
			"--ctstate", "NEW",
			"-j", "ACCEPT",
		)
		if err != nil {
			return err
		}

		// POSTROUTING
		// rewrite packet source to be the bridge namespace IP
		err = gw.iptable4.AppendUnique("nat", "POSTROUTING",
			"-o", gw.oakestraTunnel,
			"-p", "tcp",
			"-d", serviceIP.String(),
			"--dport", strconv.Itoa(servicePort),
			"-j", "SNAT",
			"--to-source", gw.bridgeIPv4.String())
		if err != nil {
			logger.ErrorLogger().Println("Error in POSTROUTING iptable4 rule.")
			return err
		}

	} else if serviceIP.To16() != nil {

		// PREROUTING
		// rewrites destination to be the service inside oakestra
		err := gw.iptable6.AppendUnique("nat", "PREROUTING",
			"-i", gw.gatewayInterface,
			"-p", "tcp",
			"-d", gw.gatewayIPv6.String(),
			"--dport", strconv.Itoa(exposedPort),
			"-j", "DNAT",
			"--to-destination", fmt.Sprintf("[%s]:%d", serviceIP.String(), servicePort))
		if err != nil {
			logger.ErrorLogger().Println("Error in PREROUTING iptable6 rule.")
			return err
		}

		// FORWARD
		// enable forwarding to service destination port
		err = gw.iptable6.AppendUnique("filter", "FORWARD",
			"-i", gw.gatewayInterface,
			"-o", gw.oakestraTunnel,
			"-p", "tcp", "--syn",
			"--dport", strconv.Itoa(servicePort),
			"-m", "conntrack",
			"--ctstate", "NEW",
			"-j", "ACCEPT",
		)
		if err != nil {
			return err
		}

		// POSTROUTING
		// rewrite packet source to be the bridge namespace IP
		err = gw.iptable6.AppendUnique("nat", "POSTROUTING",
			"-o", gw.oakestraTunnel,
			"-p", "tcp",
			"-d", serviceIP.String(),
			"--dport", strconv.Itoa(servicePort),
			"-j", "SNAT",
			"--to-source", gw.bridgeIPv6.String())
		if err != nil {
			logger.ErrorLogger().Println("Error in POSTROUTING iptable6 rule.")
			return err
		}
	}

	gw.exposedPorts[exposedPort] = true
	gw.exposedServices[serviceID] = ServiceEntry{
		serviceIP:   serviceIP,
		exposedPort: exposedPort,
		servicePort: servicePort,
	}
	return nil
}

func (gw *GatewayConfiguration) DisableServiceExposure(serviceID string) error {
	_, exists := gw.exposedServices[serviceID]
	if !exists {
		return fmt.Errorf("service does not exist")
	}
	logger.InfoLogger().Printf("Closing ports for service %s", serviceID)
	// TODO: remove firewall rules

	delete(gw.exposedServices, serviceID)
	return nil
}

// Enable forwarding for already known connections.
// This is done once and can be left as is
func (gw *GatewayConfiguration) enableForwarding() error {
	// ingress = Internet to Oakestra
	// egress = Oakestra to Internet

	// For IPv4
	// ingress traffic forwarding
	err := gw.iptable4.AppendUnique("filter", "FORWARD",
		"-i", gw.gatewayInterface,
		"-o", gw.oakestraTunnel,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	// egress traffic forwarding
	err = gw.iptable4.AppendUnique("filter", "FORWARD",
		"-o", gw.gatewayInterface,
		"-i", gw.oakestraTunnel,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	// For IPv6
	// ingress traffic forwarding
	err = gw.iptable6.AppendUnique("filter", "FORWARD",
		"-i", gw.gatewayInterface,
		"-o", gw.oakestraTunnel,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	// egress traffic forwarding
	err = gw.iptable6.AppendUnique("filter", "FORWARD",
		"-o", gw.gatewayInterface,
		"-i", gw.oakestraTunnel,
		"-m", "conntrack",
		"--ctstate", "ESTABLISHED,RELATED",
		"-j", "ACCEPT",
	)
	if err != nil {
		return err
	}

	return nil
}
