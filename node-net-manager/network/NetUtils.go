package network

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"time"

	"tailscale.com/net/interfaces"
)

// GetLocalIP returns the non loopback local IP of the host and the associated interface
func GetLocalIPandIface() (string, string) {
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
		for _, address := range addrs {
			// check the address type and if it is not a loopback the display it
			if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && iface.Name == defaultIfce {
				// TODO DISCUSS: Should we first check for IPv6 on the interface first and fallback to v4?
				if ipnet.IP.To4() != nil {
					log.Println("Local Interface in use: ", iface.Name, " with addr ", ipnet.IP.String())
					return ipnet.IP.String(), iface.Name
				}
			}
		}
	}

	return "", ""
}

func NameUniqueHash(name string, size int) string {
	shaHashFunc := sha1.New()
	shaHashFunc.Write([]byte(fmt.Sprintf("%s,%s", time.Now().String(), name)))
	hashed := shaHashFunc.Sum(nil)
	for size > len(hashed) {
		hashed = append(hashed, hashed...)
	}
	hashedAndEncoded := base64.URLEncoding.EncodeToString(hashed)
	return hashedAndEncoded[:size]
}

// Given an IP, give IP+inc
// TODO rework, since it is not safe for use
func NextIP(ip net.IP, inc uint) net.IP {
	ipBytes := ip.To16()
	for i := len(ipBytes) - 1; i >= 0; i-- {
		if ipBytes[i] == 255 {
			ipBytes[i] = 0
		} else {
			ipBytes[i] = ipBytes[i] + byte(inc)
			break
		}
	}
	return net.IP(ipBytes)
}

//Given an ipv4, gives the next IP
/*
func NextIP(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)
	return net.IPv4(v0, v1, v2, v3)
}

func NextIPv6(ip net.IP, inc uint) net.IP {
	i := ip.To16()

	// transform IP address to 128 bit Integer and increment by one
	ipInt := new(big.Int).SetBytes(i)
	ipInt.Add(ipInt, big.NewInt(1))

	// transform new incremented IP address back to net.IP format and return
	ret := make(net.IP, net.IPv6len)
	ipInt.FillBytes(ret)

	return ret
}*/
