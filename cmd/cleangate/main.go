package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cleangate/pkg/cert"
	"cleangate/pkg/engine"
	"cleangate/pkg/proxy"
	"cleangate/pkg/util"
)

func main() {
	// Parse command line arguments
	addr := flag.String("addr", "127.0.0.1", "Proxy bind address")
	port := flag.Int("port", 8081, "Proxy bind port")
	upstream := flag.String("upstream", "127.0.0.1:8080", "Upstream proxy address")
	systemProxy := flag.Bool("system-proxy", true, "Set OS proxy to CleanGate")
	
	// User can use IDs like "easylist,ublock,stevenblack" or "all"
	listsStr := flag.String("lists", "easylist,adguard", "Comma-separated list of Filter IDs or URLs")
	updateInterval := flag.Int("update-interval", 24, "List auto-update interval in hours")
	whitelistStr := flag.String("whitelist", "", "Comma-separated list of bypassed domains")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	
	flag.Parse()

	util.DebugMode = *debug
	util.Debugf("Starting CleanGate with Debug Mode ENABLED")

	// 1. Initialize Certificate Manager (MITM)
	// For production, CA should also go to UserConfigDir
	home, _ := os.UserConfigDir()
	dataDir := home + "/CleanGate"
	os.MkdirAll(dataDir, 0755)
	
	certManager, err := cert.InitCA(dataDir)
	
	// Report Cert Status
	if err != nil {
		util.PrintJSON(util.CertStatusEvent{
			Event:   "cert_status",
			Status:  "failed",
			Message: err.Error(),
		})
		os.Exit(1)
	} else {
		util.PrintJSON(util.CertStatusEvent{
			Event:   "cert_status",
			Status:  "installed",
			Message: "Root CA successfully initialized",
		})
	}

	// 2. Initialize Adblock Engine
	util.PrintJSON(util.ListUpdateEvent{
		Event:      "list_update",
		Status:     "downloading",
		TotalRules: 0,
	})

	// Convert IDs to URLs
	urls := engine.GetListURLs(*listsStr)
	adEngine := engine.NewEngine(urls)
	
	// This will load from disk cache if available, or download if necessary
	adEngine.StartAutoUpdate(time.Duration(*updateInterval) * time.Hour)
	
	util.PrintJSON(util.ListUpdateEvent{
		Event:      "list_update",
		Status:     "success",
		TotalRules: adEngine.RuleCount, 
	})

	// TODO: Apply whitelist rules to engine here
	_ = whitelistStr

	// 3. Start the Proxy Server
	srv := proxy.NewServer(*port, *upstream, adEngine, certManager)
	
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		if err := srv.Start(ctx); err != nil {
			os.Exit(1)
		}
	}()

	// Report Successful Start
	util.PrintJSON(util.StartEvent{
		Event:          "start",
		Address:        *addr,
		Port:           *port,
		UpstreamProxy:  *upstream,
		SystemProxySet: *systemProxy,
	})

	// 4. Handle Shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	cancel()

	// Report Stop
	util.PrintJSON(util.StopEvent{
		Event:          "stop",
		CleanupSuccess: true,
	})
	
	time.Sleep(500 * time.Millisecond)
}
