package firewall

type FirewallManager struct {
	// maps interface name to firewall
	firewalls map[string]*Firewall
}

// TODO does this have to be a pointer or can i return the object? Look up compiler behavior.
func NewFirewallManager() FirewallManager {
	return FirewallManager{
		firewalls: make(map[string]*Firewall),
	}
}

func (e FirewallManager) AddFirewall(ifname string) {
	firewall := NewFirewall()
	firewall.Load()
	firewall.AttachTC(ifname)
	e.firewalls[ifname] = &firewall
}

func (e FirewallManager) RemoveFirewall(ifname string) {
	delete(e.firewalls, ifname)
}

func (e FirewallManager) RemoveAllFirewalls() {
	for ifname := range e.firewalls {
		delete(e.firewalls, ifname)
	}
}
