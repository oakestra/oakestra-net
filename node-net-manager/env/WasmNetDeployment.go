package env

import (
	"NetManager/logger"
	"NetManager/mqtt"
	"NetManager/network"
	"fmt"
	"net"
	"os/exec"
	"runtime/debug"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type WasmDeploymentHandler struct {
	env *Environment
}

var wasmHandler *WasmDeploymentHandler = nil

func GetWasmNetDeployment() *WasmDeploymentHandler {
	if wasmHandler == nil {
		logger.ErrorLogger().Fatal("Wasm Handler not initialized")
	}
	return wasmHandler
}

func InitWasmDeployment(env *Environment) {
	wasmHandler = &WasmDeploymentHandler{
		env: env,
	}
}

func (h *WasmDeploymentHandler) DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error) {
	env := h.env
	nsName := fmt.Sprintf("%s.instance.%d", sname, instancenumber)

	// Create a cleanup function to ensure proper cleanup on error
	cleanup := func(veth *netlink.Veth) {
		if veth != nil {
			_ = netlink.LinkDel(veth)
		}
		exec.Command("ip", "netns", "del", nsName).Run()
	}

	// Clean any existing namespace or interfaces with same name
	exec.Command("ip", "netns", "del", nsName).Run()

	// Create veth pair with proper naming convention
	hashedName := network.NameUniqueHash(sname, 4)
	hostVethName := fmt.Sprintf("veth%s%s%s", "00", fmt.Sprintf("%d", instancenumber), hashedName)
	nsVethName := fmt.Sprintf("veth%s%s%s", "01", fmt.Sprintf("%d", instancenumber), hashedName)

	// Remove any existing veth with same name
	exec.Command("ip", "link", "del", hostVethName).Run()

	// Create namespace
	cmd := exec.Command("ip", "netns", "add", nsName)
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to create namespace %s: %v", nsName, err)
		return nil, nil, err
	}

	// Create veth pair with proper MTU
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostVethName,
			MTU:  env.mtusize,
		},
		PeerName: nsVethName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		logger.ErrorLogger().Printf("Failed to create veth pair: %v", err)
		cleanup(nil)
		return nil, nil, err
	}

	// Use the environment bridge instead of hardcoded "br0"
	bridgeName := env.config.HostBridgeName
	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to get bridge %s: %v", bridgeName, err)
		cleanup(veth)
		return nil, nil, err
	}

	// Assign peer veth to namespace
	peerVeth, err := netlink.LinkByName(nsVethName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to retrieve peer veth: %v", err)
		cleanup(veth)
		return nil, nil, err
	}
	nsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to get namespace handle: %v", err)
		cleanup(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetNsFd(peerVeth, int(nsHandle)); err != nil {
		logger.ErrorLogger().Printf("Failed to move veth into namespace: %v", err)
		nsHandle.Close()
		cleanup(veth)
		return nil, nil, err
	}
	nsHandle.Close()

	// Connect host veth to bridge
	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to retrieve host veth: %v", err)
		cleanup(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetMaster(hostVeth, bridge); err != nil {
		logger.ErrorLogger().Printf("Failed to set bridge master for host veth: %v", err)
		cleanup(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		logger.ErrorLogger().Printf("Failed to set host veth up: %v", err)
		cleanup(veth)
		return nil, nil, err
	}

	// Generate dynamic IP addresses instead of hardcoded ones
	ip, err := env.generateAddress()
	if err != nil {
		logger.ErrorLogger().Printf("Failed to generate IPv4 address: %v", err)
		cleanup(veth)
		return nil, nil, err
	}

	// Generate IPv6 address
	ipv6, err := env.generateIPv6Address()
	if err != nil {
		logger.ErrorLogger().Printf("Failed to generate IPv6 address: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		return nil, nil, err
	}

	// Configure IPv4 in namespace
	if err := env.addPeerLinkNetworkByNsName(nsName, ip.String()+env.config.HostBridgeMask, nsVethName); err != nil {
		logger.ErrorLogger().Printf("Failed to assign IPv4 to namespace veth: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Configure IPv6 in namespace
	// Disable DAD for faster IPv6 setup
	if err := env.execInsideNsByName(nsName, func() error {
		cmd := exec.Command("sysctl", "-w", "net.ipv6.conf.default.accept_dad=0")
		err := cmd.Run()
		if err != nil {
			return err
		}
		cmd = exec.Command("sysctl", "-w", "net.ipv6.conf."+nsVethName+".accept_dad=0")
		err = cmd.Run()
		return err
	}); err != nil {
		logger.ErrorLogger().Printf("Failed to disable DAD: %v", err)
	}

	if err := env.addPeerLinkNetworkByNsName(nsName, ipv6.String()+env.config.HostBridgeIPv6Prefix, nsVethName); err != nil {
		logger.ErrorLogger().Printf("Failed to assign IPv6 to namespace veth: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Setup loopback interface
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to set loopback up in namespace: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Add default routes
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "route", "add", "default", "via", env.config.HostBridgeIP)
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to add default IPv4 route: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "-6", "route", "add", "default", "via", env.config.HostBridgeIPv6)
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to add default IPv6 route: %v", err)
		// Continue anyway as IPv6 is optional
	}

	// Set firewall rules
	if err = env.setVethFirewallRules(hostVethName); err != nil {
		logger.ErrorLogger().Printf("Failed to set firewall rules: %v", err)
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Manage ports
	if err = network.ManageContainerPorts(ip, portmapping, network.OpenPorts); err != nil {
		logger.ErrorLogger().Printf("Error in ManageContainerPorts v4: %v", err)
		debug.PrintStack()
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	if err = network.ManageContainerPorts(ipv6, portmapping, network.OpenPorts); err != nil {
		logger.ErrorLogger().Printf("Error in ManageContainerPorts v6: %v", err)
		debug.PrintStack()
		cleanup(veth)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Register in deployedServices
	env.deployedServicesLock.Lock()
	env.deployedServices[nsName] = service{
		ip:          ip,
		ipv6:        ipv6,
		sname:       sname,
		portmapping: portmapping,
		veth:        veth,
	}
	env.deployedServicesLock.Unlock()

	env.BookVethNumber()
	
	logger.DebugLogger().Printf("Successful network creation for WASM namespace %s with IP %s, IPv6 %s", nsName, ip.String(), ipv6.String())
	return ip, ipv6, nil
}

func (env *Environment) DeleteWasmNamespace(sname string, instance int) {
	nsName := fmt.Sprintf("%s.instance.%d", sname, instance)

	env.deployedServicesLock.RLock()
	s, ok := env.deployedServices[nsName]
	env.deployedServicesLock.RUnlock()

	if ok {
		_ = env.translationTable.RemoveByNsip(s.ip)
		env.deployedServicesLock.Lock()
		delete(env.deployedServices, nsName)
		env.deployedServicesLock.Unlock()
		env.freeContainerAddress(s.ip)
		env.freeContainerAddress(s.ipv6)
		_ = network.ManageContainerPorts(s.ip, s.portmapping, network.ClosePorts)
		_ = network.ManageContainerPorts(s.ipv6, s.portmapping, network.ClosePorts)
		_ = netlink.LinkDel(s.veth)
		exec.Command("ip", "netns", "del", nsName).Run()
		
		// if no interest registered delete all remaining info about the service
		if !mqtt.MqttIsInterestRegistered(sname) {
			env.RemoveServiceEntries(sname)
		}
	}
}
