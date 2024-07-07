package main

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ne-bknn/netfilter-exporter/internal/backend/iptables"
	"github.com/ne-bknn/netfilter-exporter/internal/server"
)

func main() {
	// Create your firewall backend instance
	firewallBackend := iptables.MakeIPTablesBackend() // Replace with your actual backend

	// Create a new FirewallExporter
	exporter := server.NewFirewallExporter(firewallBackend)

	// Register the exporter
	prometheus.MustRegister(exporter)

	// Expose the metrics endpoint
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":9090", nil)
}
