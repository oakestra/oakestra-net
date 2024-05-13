package env

import (
	"log"

	"github.com/tkanos/gonfig"
)

type NetConfiguration struct {
	NodePublicAddress string
	NodePublicPort    string
	ClusterUrl        string
	ClusterMqttPort   string
}

var configuration *NetConfiguration
var cfgFile = "/etc/netmanager/netcfg.json" // default configuration file

func GetConfiguration() NetConfiguration {
	if configuration == nil {
		err := gonfig.GetConf(cfgFile, configuration)
		if err != nil {
			log.Fatal(err)
		}
	}
	return *configuration
}

func InitConfigurationFile(file string) {
	cfgFile = file
}
