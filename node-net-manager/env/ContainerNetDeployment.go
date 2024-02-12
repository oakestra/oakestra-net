package env

import (
	"NetManager/logger"
	"NetManager/mqtt"
	"NetManager/network"
	"fmt"
	"net"
	"runtime/debug"

	"github.com/vishvananda/netlink"
)

type ContainerDeyplomentHandler struct {
	env *Environment
}

var containerHandler *ContainerDeyplomentHandler = nil

func GetContainerNetDeployment() *ContainerDeyplomentHandler {
	if containerHandler == nil {
		logger.ErrorLogger().Fatal("Container Handler not initialized")
	}
	return containerHandler
}

func InitContainerDeployment(env *Environment) {
	containerHandler = &ContainerDeyplomentHandler{
		env: env,
	}
}

// AttachNetworkToContainer Attach a Docker container to the bridge and the current network environment
func (h *ContainerDeyplomentHandler) DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error) {
	env := h.env

	cleanup := func(veth *netlink.Veth) {
		_ = netlink.LinkDel(veth)
	}

	vethIfce, err := env.createVethsPairAndAttachToBridge(sname, env.mtusize)
	if err != nil {
		go cleanup(vethIfce)
		return nil, nil, err
	}

	// Attach veth2 to the docker container
	logger.DebugLogger().Println("Attaching peerveth to container ")
	peerVeth, err := netlink.LinkByName(vethIfce.PeerName)
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}
	if err := netlink.LinkSetNsPid(peerVeth, pid); err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	// generate a new ip for this container
	ip, err := env.generateAddress()
	logger.DebugLogger().Println("Returned IPv4 address in deploy:", ip)
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	// generate a new ipv6 for this container
	ipv6, err := env.generateIPv6Address()
	logger.DebugLogger().Println("Returned IPv6 address in deploy:", ipv6)
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	// set ip to the container veth
	logger.DebugLogger().Println("Assigning ip ", ip.String()+env.config.HostBridgeMask, " to container ")
	if err := env.addPeerLinkNetwork(pid, ip.String()+env.config.HostBridgeMask, vethIfce.PeerName); err != nil {
		logger.DebugLogger().Println("Error in addPeerLinkNetwork")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	logger.DebugLogger().Println("Assigning ipv6 ", ipv6.String()+env.config.HostBridgeIPv6Prefix, " to container ")
	if err := env.addPeerLinkNetwork(pid, ipv6.String()+env.config.HostBridgeIPv6Prefix, vethIfce.PeerName); err != nil {
		logger.DebugLogger().Println("Error in addPeerLinkNetworkv6")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	// Add traffic route to bridge
	logger.DebugLogger().Println("Setting container routes ")
	if err = env.setContainerRoutes(pid, vethIfce.PeerName); err != nil {
		logger.DebugLogger().Println("Error in setContainerRoutes")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	env.BookVethNumber()

	if err = env.setVethFirewallRules(vethIfce.Name); err != nil {
		logger.DebugLogger().Println("Error in setFirewallRules")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	if err = network.ManageContainerPorts(ip, portmapping, network.OpenPorts); err != nil {
		logger.DebugLogger().Println("Error in ManageContainerPorts v4")
		debug.PrintStack()
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	if err = network.ManageContainerPorts(ipv6, portmapping, network.OpenPorts); err != nil {
		logger.DebugLogger().Println("Error in ManageContainerPorts v6")
		debug.PrintStack()
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		env.freeContainerAddress(ipv6)
		return nil, nil, err
	}

	testdeployer := service{
		ip:          ip,
		ipv6:        ipv6,
		sname:       sname,
		portmapping: portmapping,
		veth:        vethIfce,
	}
	logger.DebugLogger().Printf("Adding service to deployedServices table: %v", testdeployer)
	logger.DebugLogger().Printf("deployedServices table before addition: %v", env.deployedServices)
	env.deployedServicesLock.Lock()
	env.deployedServices[fmt.Sprintf("%s.%d", sname, instancenumber)] = testdeployer
	env.deployedServicesLock.Unlock()
	logger.DebugLogger().Printf("New deployedServices table: %v", env.deployedServices)
	return ip, ipv6, nil
}

func (env *Environment) DetachContainer(sname string, instance int) {
	snameAndInstance := fmt.Sprintf("%s.%d", sname, instance)
	logger.DebugLogger().Printf("DetachContainer deployedServices table: %v", env.deployedServices)
	env.deployedServicesLock.RLock()
	s, ok := env.deployedServices[snameAndInstance]
	logger.DebugLogger().Printf("Matched service %s to detach: %v", snameAndInstance, s)
	env.deployedServicesLock.RUnlock()
	if ok {
		// TODO Remove ipv6?
		_ = env.translationTable.RemoveByNsip(s.ip)
		env.deployedServicesLock.Lock()
		delete(env.deployedServices, snameAndInstance)
		env.deployedServicesLock.Unlock()
		env.freeContainerAddress(s.ip)
		env.freeContainerAddress(s.ipv6)
		_ = network.ManageContainerPorts(s.ip, s.portmapping, network.ClosePorts)
		_ = network.ManageContainerPorts(s.ipv6, s.portmapping, network.ClosePorts)
		_ = netlink.LinkDel(s.veth)
		// if no interest registered delete all remaining info about the service
		if !mqtt.MqttIsInterestRegistered(sname) {
			env.RemoveServiceEntries(sname)
		}
	}
}
