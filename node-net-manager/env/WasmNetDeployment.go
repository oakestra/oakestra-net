package env

import (
	"NetManager/logger"
	"NetManager/network"
	"fmt"
	"net"
	"os/exec"

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
	nsName := fmt.Sprintf("%s.instance.%d", sname, instancenumber)

	hostVethName := fmt.Sprintf("veth-br-%d", instancenumber)
	nsVethName := fmt.Sprintf("veth-ns-%d", instancenumber)

	exec.Command("ip", "netns", "del", nsName).Run()
	exec.Command("ip", "link", "del", hostVethName).Run()

	cmd := exec.Command("ip", "netns", "add", nsName)
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to create namespace %s: %v", nsName, err)
		return nil, nil, err
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: hostVethName,
			MTU:  1500,
		},
		PeerName: nsVethName,
	}
	if err := netlink.LinkAdd(veth); err != nil {
		logger.ErrorLogger().Printf("Failed to create veth pair: %v", err)
		return nil, nil, err
	}

	bridgeName := "br0"
	bridge, err := netlink.LinkByName(bridgeName)
	if err != nil {
		la := netlink.NewLinkAttrs()
		la.Name = bridgeName
		bridge = &netlink.Bridge{LinkAttrs: la}
		if err := netlink.LinkAdd(bridge); err != nil {
			logger.ErrorLogger().Printf("Failed to create bridge: %v", err)
			netlink.LinkDel(veth)
			return nil, nil, err
		}
		if err := netlink.LinkSetUp(bridge); err != nil {
			logger.ErrorLogger().Printf("Failed to set bridge up: %v", err)
			netlink.LinkDel(veth)
			return nil, nil, err
		}
		addr, _ := netlink.ParseAddr("10.10.0.1/24")
		if err := netlink.AddrAdd(bridge, addr); err != nil {
			logger.ErrorLogger().Printf("Failed to add IP to bridge: %v", err)
			netlink.LinkDel(veth)
			return nil, nil, err
		}
	}

	peerVeth, err := netlink.LinkByName(nsVethName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to retrieve peer veth: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	nsHandle, err := netns.GetFromName(nsName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to get namespace handle: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetNsFd(peerVeth, int(nsHandle)); err != nil {
		logger.ErrorLogger().Printf("Failed to move veth into namespace: %v", err)
		netlink.LinkDel(veth)
		nsHandle.Close()
		return nil, nil, err
	}
	nsHandle.Close()

	hostVeth, err := netlink.LinkByName(hostVethName)
	if err != nil {
		logger.ErrorLogger().Printf("Failed to retrieve host veth: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetMaster(hostVeth, bridge); err != nil {
		logger.ErrorLogger().Printf("Failed to set bridge master for host veth: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		logger.ErrorLogger().Printf("Failed to set host veth up: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}

	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "addr", "add", "10.10.0.2/24", "dev", nsVethName)
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to assign IP to namespace veth: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", nsVethName, "up")
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to set namespace veth up: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}
	cmd = exec.Command("ip", "netns", "exec", nsName, "ip", "link", "set", "lo", "up")
	if err := cmd.Run(); err != nil {
		logger.ErrorLogger().Printf("Failed to set loopback up in namespace: %v", err)
		netlink.LinkDel(veth)
		return nil, nil, err
	}

	logger.DebugLogger().Printf("Successful network creation for WASM namespace %s", nsName)
	ip, _, _ := net.ParseCIDR("10.10.0.2/24")
	return ip, nil, nil
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
		_ = network.ManageContainerPorts(s.ip, s.portmapping, network.ClosePorts)
		_ = netlink.LinkDel(s.veth)
		exec.Command("ip", "netns", "del", nsName).Run()
	}
}
