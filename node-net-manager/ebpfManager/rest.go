package ebpfManager

import (
	"NetManager/env"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (e *EbpfManager) createRestInterface(manager *env.EnvironmentManager) {
	router := gin.Default()
	router.GET("/ebpf/environment", func(c *gin.Context) {
		vethList := (*manager).GetDeployedServicesVeths()
		ret := make([]string, 0)
		for _, veth := range vethList {
			ret = append(ret, veth.Name)
			ret = append(ret, veth.PeerName)
		}
		c.JSON(http.StatusOK, gin.H{"strings": ret})
	})

	//router.GET("/ebpf/activate", func(c *gin.Context) {
	//	e.ActivateFirewall()
	//	c.Status(200)
	//})
	//
	//router.DELETE("/ebpf/firewall", func(c *gin.Context) {
	//	e.firewallManager.RemoveAllFirewalls()
	//	c.Status(200)
	//})

	//router.POST("/ebpf/firewall", func(c *gin.Context) {
	//	type FirewallRequest struct {
	//		Proto   string `json:"proto"`
	//		SrcIp   string `json:"srcIp"`
	//		DstIp   string `json:"dstIp"`
	//		SrcPort uint16 `json:"scrPort"`
	//		DstPort uint16 `json:"dstPort"`
	//	}
	//
	//	var request FirewallRequest
	//	if err := c.BindJSON(&request); err != nil {
	//		return
	//	}
	//
	//	src := net.ParseIP(request.SrcIp).To4()
	//	dst := net.ParseIP(request.DstIp).To4()
	//
	//	// TODO ben default is always TCP. Does that make sense? + can I add this parsing step to JSON serialiser?
	//	proto := firewall.TCP
	//	if request.Proto == "UDP" {
	//		proto = firewall.UDP
	//	} else if request.Proto == "ICMP" {
	//		proto = firewall.ICMP
	//	}
	//
	//	e.firewallManager.AddFirewallRule(src, dst, proto, request.SrcPort, request.DstPort)
	//
	//	c.Status(http.StatusOK)
	//})

	go router.Run(":8081")
}
