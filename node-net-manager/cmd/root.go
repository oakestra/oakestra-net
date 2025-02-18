package cmd

import (
	"NetManager/ebpfManager"
	"NetManager/logger"
	"NetManager/network"
	"NetManager/server"
	"log"
	"slices"
	"time"

	"github.com/spf13/cobra"
	"github.com/tkanos/gonfig"
)

var (
	rootCmd = &cobra.Command{
		Use:   "NetManager",
		Short: "Start a NetManager",
		Long:  `Start a New Oakestra Worker Node`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return startNetManager()
		},
	}
	cfgFile    string
	daemonMode bool
)

const MONITORING_CYCLE = time.Second * 2

func Execute() error {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&cfgFile, "cfg", "c", "/etc/netmanager/netcfg.json", "Path of the netcfg.json configuration file")
}

func startNetManager() error {

	err := gonfig.GetConf(cfgFile, &server.Configuration)
	if err != nil {
		log.Fatal(err)
	}

	if server.Configuration.Debug {
		logger.SetDebugMode()
	}

	if slices.Contains(server.Configuration.Experimental, "ebpf") {
		ebpfManager.SetEnableEbpf(true)
	}

	log.Print(server.Configuration)

	network.IptableFlushAll()

	log.Println("NetManager started, but waiting for NodeEngine registration 🟠")
	server.HandleRequests()

	return nil

}
