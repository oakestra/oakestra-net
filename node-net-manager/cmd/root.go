package cmd

import (
	"NetManager/logger"
	"NetManager/network"
	"log"
	"strings"
	"time"

	"NetManager/ebpfManager"
	"NetManager/server"

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
	cfgFile              string
	localPort            int
	debugMode            bool
	daemonMode           bool
	experimentalFeatures map[string]bool
)

const MONITORING_CYCLE = time.Second * 2

func Execute() error {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVarP(&cfgFile, "cfg", "c", "/etc/netmanager/netcfg.json", "Path of the netcfg.json configuration file")
	rootCmd.Flags().IntVarP(&localPort, "port", "p", 6000, "Default local port of the NetManager")
	rootCmd.Flags().BoolVarP(&debugMode, "debug", "D", false, "Enable debug logs")
	experimental := rootCmd.Flags().StringP("experimental", "e", "", "Comma-separated list of experimental features to enable")
	cobra.OnInitialize(func() {
		// Parse experimental features if provided
		experimentalFeatures = make(map[string]bool)
		if *experimental != "" {
			for _, feature := range strings.Split(*experimental, ",") {
				experimentalFeatures[strings.TrimSpace(feature)] = true
			}
		}
	})
}

func startNetManager() error {
	err := gonfig.GetConf(cfgFile, &server.Configuration)
	if err != nil {
		log.Fatal(err)
	}

	if debugMode {
		logger.SetDebugMode()
	}

	if experimentalFeatures["ebpf"] {
		ebpfManager.SetEnableEbpf(true)
	}

	log.Print(server.Configuration)

	network.IptableFlushAll()

	log.Println("NetManager started, but waiting for NodeEngine registration 🟠")
	server.HandleRequests(localPort)

	return nil
}
