package firewall

import (
	"net"
)

type FirewallManager struct {
	// maps interface name to firewall
	firewalls map[string]Firewall
}

// TODO does this have to be a pointer or can i return the object? Look up compiler behavior.
func NewFirewallManager() FirewallManager {
	return FirewallManager{
		firewalls: make(map[string]Firewall),
	}
}

func (e *FirewallManager) AddFirewallRule(srcIp net.IP, dstIp net.IP, proto Protocol, srcPort uint16, dstPort uint16) {
	for _, fw := range e.firewalls {
		fw.AddRule(srcIp, dstIp, proto, srcPort, dstPort)
	}
}

func (e *FirewallManager) AttachFirewall(ifname string) {
	firewall := NewFirewall()
	firewall.Load()
	firewall.AttachTC(ifname)
	e.firewalls[ifname] = firewall
}

func (e *FirewallManager) RemoveFirewall(ifname string) {
	if fw, exists := e.firewalls[ifname]; exists {
		fw.Close()
		delete(e.firewalls, ifname)
	}
}

func (e *FirewallManager) RemoveAllFirewalls() {
	for ifname := range e.firewalls {
		e.RemoveFirewall(ifname)
	}
}
