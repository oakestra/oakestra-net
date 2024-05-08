package env

import (
	"NetManager/logger"
	"NetManager/network"
	"fmt"
	"net"
	"os/exec"
	"runtime/debug"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type UnikernelDeyplomentHandler struct {
	env *Environment
}

var unikernelHandler *UnikernelDeyplomentHandler = nil

func GetUnikernelNetDeployment() *UnikernelDeyplomentHandler {
	if unikernelHandler == nil {
		logger.ErrorLogger().Fatal("Unikernel Handler not initialized")
	}
	return unikernelHandler
}

func InitUnikernelDeployment(env *Environment) {
	unikernelHandler = &UnikernelDeyplomentHandler{
		env: env,
	}
}

func (h *UnikernelDeyplomentHandler) DeployNetwork(pid int, sname string, instancenumber int, portmapping string) (net.IP, net.IP, error) {
	env := h.env
	name := sname
	sname = fmt.Sprintf("%s.instance.%d", sname, instancenumber)

	cleanup := func(veth *netlink.Veth) {
		_ = netlink.LinkDel(veth)
	}

	logger.DebugLogger().Println("Creating veth pair for unikernel deployment")
	vethIfce, err := env.createVethsPairAndAttachToBridge(sname, env.mtusize)
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	peerVeth, err := netlink.LinkByName(vethIfce.PeerName)
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	logger.DebugLogger().Printf("Creating Namespace for unikernel (%s)", sname)
	nscreation := exec.Command("ip", "netns", "add", sname)
	err = nscreation.Run()
	// ns, err := netns.NewNamed(sname) ## Changes Namespace of current application
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}
	ns, err := netns.GetFromName(sname)
	if err != nil {
		logger.DebugLogger().Printf("Unable to find namespace: %v", err)
		return nil, nil, err
	}

	cleanup = func(veth *netlink.Veth) {
		_ = netlink.LinkDel(veth)
		ns.Close()
		err = netns.DeleteNamed(sname)
		if err != nil {
			logger.DebugLogger().Printf("Unable to delete namespace: %v", err)
		}
	}

	// Move peer veth to namespace
	if err := netlink.LinkSetNsFd(peerVeth, int(ns)); err != nil {
		logger.DebugLogger().Printf("Error %s: %v", peerVeth.Attrs().Name, err)
		cleanup(vethIfce)
		return nil, nil, err
	}

	// Get IP for veth interface
	ip, err := env.generateAddress()
	if err != nil {
		cleanup(vethIfce)
		return nil, nil, err
	}

	// Set IP for veth interface
	if err := env.addPeerLinkNetworkByNsName(sname, ip.String()+env.config.HostBridgeMask, vethIfce.PeerName); err != nil {
		logger.DebugLogger().Println("Unable to configure Peer")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, nil, err
	}

	// Create Macvtap device inside the namespace
	logger.DebugLogger().Println("Creating Macvtap device")
	err = env.execInsideNsByName(sname, func() error {

		// Set default route for the namespace
		dst, err := netlink.ParseIPNet("0.0.0.0/0")
		if err != nil {
			return err
		}

		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: peerVeth.Attrs().Index,
			Dst:       dst,
			Gw:        net.ParseIP(env.config.HostBridgeIP),
		})
		if err != nil {
			logger.DebugLogger().Printf("Failed to set route in Ns: %v", err)
			return err
		}

		// create and configure macvtap device
		mvtAttr := netlink.NewLinkAttrs()
		mvtAttr.Name = "tap0"
		mvtAttr.ParentIndex = peerVeth.Attrs().Index
		macvtap := &netlink.Macvtap{
			Macvlan: netlink.Macvlan{
				LinkAttrs: mvtAttr,
				Mode:      netlink.MACVLAN_MODE_BRIDGE,
			},
		}

		if err := netlink.LinkAdd(macvtap); err != nil {
			logger.DebugLogger().Printf("Unable to create macvtap netlink %v", err)
			return err
		}
		if err := netlink.LinkSetUp(macvtap); err != nil {
			logger.DebugLogger().Printf("Unable to set macvtap netlink up %v", err)
			return err
		}

		_, err = netlink.LinkByName(macvtap.Name)
		if err != nil {
			logger.DebugLogger().Printf("Unable to retrieve the new macvtap netlink %v", err)
			return err
		}

		return nil
	})

	if err != nil {
		logger.DebugLogger().Printf("Failed to configure Ns for Unikernel\n")
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, nil, err
	}

	env.BookVethNumber()

	if err = env.setVethFirewallRules(vethIfce.Name); err != nil {
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, nil, err
	}

	if err = network.ManageContainerPorts(ip, portmapping, network.OpenPorts); err != nil {
		debug.PrintStack()
		cleanup(vethIfce)
		env.freeContainerAddress(ip)
		return nil, nil, err
	}

	env.deployedServicesLock.Lock()
	env.deployedServices[sname] = service{
		ip:          ip,
		sname:       name,
		portmapping: portmapping,
		veth:        vethIfce,
	}
	env.deployedServicesLock.Unlock()
	logger.DebugLogger().Println("Successful Network creation for Unikernel")
	return ip, nil, nil
}

func (env *Environment) DeleteUnikernelNamespace(sname string, instance int) {
	name := fmt.Sprintf("%s.instance.%d", sname, instance)
	s, ok := env.deployedServices[name]
	if ok {
		_ = env.translationTable.RemoveByNsip(s.ip)
		env.deployedServicesLock.Lock()
		delete(env.deployedServices, name)
		env.deployedServicesLock.Unlock()
		env.freeContainerAddress(s.ip)
		_ = network.ManageContainerPorts(s.ip, s.portmapping, network.ClosePorts)
		_ = netlink.LinkDel(s.veth)
		_ = netns.DeleteNamed(name)
	}
}
