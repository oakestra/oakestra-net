package ebpfManager

import (
	"NetManager/env"
	"github.com/gin-gonic/gin"
	"net/http"
)

func (e EbpfManager) createRestInterface(manager *env.EnvironmentManager) {
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

	router.GET("/ebpf/activate", func(c *gin.Context) {
		e.ActivateFirewall()
		c.Status(200)
	})

	go router.Run(":8081")
}
