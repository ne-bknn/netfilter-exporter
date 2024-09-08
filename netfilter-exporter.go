package main

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ne-bknn/netfilter-exporter/internal/backend"
	"github.com/ne-bknn/netfilter-exporter/internal/backend/iptables"
	"github.com/ne-bknn/netfilter-exporter/internal/backend/nftables"
	"github.com/ne-bknn/netfilter-exporter/internal/config"
	"github.com/ne-bknn/netfilter-exporter/internal/logs"
	"github.com/ne-bknn/netfilter-exporter/internal/server"
)

func main() {
	logger := logs.GetLogger()
	config, err := config.GetConfig(logger)
	if err != nil {
		return
	}
	// Create your firewall backend instance
	var firewallBackend backend.FirewallBackend
	if config.Engine == "iptables" {
		firewallBackend = iptables.MakeIPTablesBackend()
	} else {
		firewallBackend = nftables.MakeNFTablesBackend()
	}

	// Create a new FirewallExporter
	exporter := server.NewFirewallExporter(firewallBackend)

	// Register the exporter
	prometheus.MustRegister(exporter)

	// Expose the metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	if err := http.ListenAndServe(":9090", nil); err != nil {
		log.Fatalf("Error starting HTTP server: %v", err)
	}
}
