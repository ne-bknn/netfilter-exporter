package server

import (
	"log"

	"github.com/ne-bknn/netfilter-exporter/internal/backend"
	"github.com/prometheus/client_golang/prometheus"
)

type FirewallExporter struct {
	backend      backend.FirewallBackend
	collectError prometheus.Gauge
}

func NewFirewallExporter(backend backend.FirewallBackend) *FirewallExporter {
	return &FirewallExporter{
		backend: backend,
		collectError: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "netfilter_exporter_collection_error",
				Help: "Whether an error occured during metric collection",
			},
		),
	}
}

func (e *FirewallExporter) Describe(ch chan<- *prometheus.Desc) {
	// e.collectError.Describe(ch)
}

func (e *FirewallExporter) Collect(ch chan<- prometheus.Metric) {
	rules, err := e.backend.GetRules()

	if err != nil {
		log.Printf("Error collecting rules: %+v", err)
		e.collectError.Set(1)
		e.collectError.Collect(ch)
		return
	}

	e.collectError.Set(0)

	for _, rule := range rules {
		labels := make(prometheus.Labels)
		labels["chain"] = rule.Chain
		labels["table"] = rule.Table
		for tagKey, tagValue := range rule.Tags {
			labels[tagKey] = tagValue
		}

		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("firewall_rule_packet_count", "Number of packets matching the firewall rule", nil, labels),
			prometheus.CounterValue,
			float64(rule.PacketCount),
		)
		ch <- prometheus.MustNewConstMetric(
			prometheus.NewDesc("firewall_rule_byte_count", "Number of bytes matching the firewall rule", nil, labels),
			prometheus.CounterValue,
			float64(rule.ByteCount),
		)
	}

	e.collectError.Collect(ch)
}
