package proxy

import (
	"NetManager/env"
	"NetManager/logger"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"

	"github.com/songgao/water"
	"tailscale.com/net/interfaces"
)

var proxyTunnel GoProxyTunnel

func Proxy() *GoProxyTunnel {
	return &proxyTunnel
}

// create a  new GoProxyTunnel with the configuration from the custom local file
func New() GoProxyTunnel {
	port, err := strconv.Atoi(os.Getenv("PUBLIC_WORKER_PORT"))
	if err != nil {
		logger.InfoLogger().Printf("Default to tunport 50103")
		port = 50103
	}
	mtusize := os.Getenv("TUN_MTU_SIZE")
	if len(mtusize) == 0 {
		logger.InfoLogger().Printf("Default to mtusize 1450")
		mtusize = "1450"
	}
	proxySubnetworkMask := os.Getenv("PROXY_SUBNETWORK_MASK")
	if len(proxySubnetworkMask) == 0 {
		logger.InfoLogger().Printf("Default proxy subnet mask to 255.255.0.0")
		proxySubnetworkMask = "255.255.0.0"
	}
	proxySubnetwork := os.Getenv("PROXY_SUBNETWORK")
	if len(proxySubnetwork) == 0 {
		logger.InfoLogger().Printf("Default proxy subnetwork to 10.30.0.0")
		proxySubnetwork = "10.30.0.0"
	}
	tunNetIP := os.Getenv("TUN_NET_IP")
	if len(tunNetIP) == 0 {
		logger.InfoLogger().Printf("Default to tunNetIP 10.19.1.254")
		tunNetIP = "10.19.1.254"
	}

	tunconfig := Configuration{
		HostTUNDeviceName:   "goProxyTun",
		ProxySubnetwork:     proxySubnetwork,
		ProxySubnetworkMask: proxySubnetworkMask,
		TunNetIP:            tunNetIP,
		TunnelPort:          port,
		Mtusize:             mtusize,
	}
	proxyTunnel = NewCustom(tunconfig)

	return proxyTunnel
}

// create a  new GoProxyTunnel with a custom configuration
func NewCustom(configuration Configuration) GoProxyTunnel {
	proxy := GoProxyTunnel{
		isListening:      false,
		errorChannel:     make(chan error),
		finishChannel:    make(chan bool),
		stopChannel:      make(chan bool),
		connectionBuffer: make(map[string]*net.UDPConn),
		proxycache:       NewProxyCache(),
		udpwrite:         sync.RWMutex{},
		tunwrite:         sync.RWMutex{},
		incomingChannel:  make(chan incomingMessage, 1000),
		outgoingChannel:  make(chan outgoingMessage, 1000),
		mtusize:          configuration.Mtusize,
		randseed:         rand.New(rand.NewSource(42)),
	}

	// parse configuration file
	tunconfig := configuration
	proxy.HostTUNDeviceName = tunconfig.HostTUNDeviceName
	proxy.ProxyIpSubnetwork = net.IPNet{
		IP:   net.ParseIP(tunconfig.ProxySubnetwork),
		Mask: net.IPMask(net.ParseIP(tunconfig.ProxySubnetworkMask).To4()),
	}
	proxy.TunnelPort = tunconfig.TunnelPort
	proxy.tunNetIP = tunconfig.TunNetIP

	// create the TUN device
	proxy.createTun()

	// set local ip
	ipstring, _ := getLocalIPandIface()
	proxy.localIP = net.ParseIP(ipstring)

	logger.InfoLogger().Printf("Created ProxyTun device: %s\n", proxy.ifce.Name())
	logger.InfoLogger().Printf("Local Ip detected: %s\n", proxy.localIP.String())

	return proxy
}

func (proxy *GoProxyTunnel) SetEnvironment(env env.EnvironmentManager) {
	proxy.Environment = env
}

func (proxy *GoProxyTunnel) IsListening() bool {
	return proxy.isListening
}

// start listening for packets in the TUN Proxy device
func (proxy *GoProxyTunnel) Listen() {
	if !proxy.isListening {
		logger.InfoLogger().Println("Starting proxy listening mode")
		go proxy.tunOutgoingListen()
		go proxy.tunIngoingListen()
	}
}

// create an instance of the proxy TUN device and setup the environment
func (proxy *GoProxyTunnel) createTun() {
	// create tun device
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = proxy.HostTUNDeviceName
	ifce, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	logger.InfoLogger().Println("Bringing tun up with addr " + proxy.tunNetIP + "/12")
	cmd := exec.Command("ip", "addr", "add", proxy.tunNetIP+"/12", "dev", ifce.Name())
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "up")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// disabling reverse path filtering
	logger.InfoLogger().Println("Disabling tun dev reverse path filtering")
	cmd = exec.Command("echo", "0", ">", "/proc/sys/net/ipv4/conf/"+ifce.Name()+"/rp_filter")
	err = cmd.Run()
	if err != nil {
		log.Printf("Error disabling tun dev reverse path filtering: %s ", err.Error())
	}

	// Increasing the MTU on the TUN dev
	logger.InfoLogger().Println("Changing TUN's MTU")
	cmd = exec.Command("ip", "link", "set", "dev", ifce.Name(), "mtu", proxy.mtusize)
	err = cmd.Run()
	if err != nil {
		log.Fatal(err.Error())
	}

	// Add network routing rule, Done by default by the system
	logger.InfoLogger().
		Printf("adding routing rule for %s to %s\n", proxy.ProxyIpSubnetwork.String(), ifce.Name())
	cmd = exec.Command("ip", "route", "add", "10.30.0.0/12", "dev", ifce.Name())
	_, _ = cmd.Output()

	// add firewalls rules
	logger.InfoLogger().Println("adding firewall rule " + ifce.Name())
	cmd = exec.Command("iptables", "-A", "INPUT", "-i", "tun0", "-m", "state",
		"--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// listen to local socket
	lstnAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%v", proxy.TunnelPort))
	if nil != err {
		log.Fatal("Unable to get UDP socket:", err)
	}
	lstnConn, err := net.ListenUDP("udp", lstnAddr)
	if nil != err {
		log.Fatal("Unable to listen on UDP socket:", err)
	}
	err = lstnConn.SetReadBuffer(BUFFER_SIZE)
	if nil != err {
		log.Fatal("Unable to set Read Buffer:", err)
	}

	proxy.HostTUNDeviceName = ifce.Name()
	proxy.ifce = ifce
	proxy.listenConnection = lstnConn
}

// GetLocalIP returns the non loopback local IP of the host and the associated interface
func getLocalIPandIface() (string, string) {
	list, err := net.Interfaces()
	if err != nil {
		log.Printf("not net Interfaces found")
		panic(err)
	}
	defaultIfce, err := interfaces.DefaultRouteInterface()
	if err != nil {
		log.Printf("not default Interfaces found")
		panic(err)
	}

	for _, iface := range list {
		addrs, err := iface.Addrs()
		if err != nil {
			panic(err)
		}
		for idx, address := range addrs {
			logger.DebugLogger().Printf("idx: %d IP: %s", idx, address.String())
			// check the address type and if it is not a loopback the display it
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() &&
				iface.Name == defaultIfce {
				if ipnet.IP.To4() != nil {
					log.Println(
						"Local Interface in use: ",
						iface.Name,
						" with addr ",
						ipnet.IP.String(),
					)
					return ipnet.IP.String(), iface.Name
				}
			}
		}
	}

	return "", ""
}
