package server

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ne-bknn/netfilter-exporter/internal/backend"
)

type MockFirewallBackend struct{}

func NewMockFirewallBackend() *MockFirewallBackend {
	return &MockFirewallBackend{}
}

func (m *MockFirewallBackend) GetRules() ([]backend.Rule, error) {
	return []backend.Rule{
		{
			Tags:        map[string]string{"foo": "bar"},
			Chain:       "INPUT",
			Table:       "filter",
			PacketCount: 1234,
			ByteCount:   5678,
		},
		{
			Tags:        map[string]string{"key": "value"},
			Chain:       "OUTPUT",
			Table:       "filter",
			PacketCount: 2345,
			ByteCount:   6789,
		},
	}, nil
}

func (*MockFirewallBackend) GetName() string {
	return "mock"
}

func TestFirewallExporter(t *testing.T) {
	mockBackend := NewMockFirewallBackend()

	exporter := NewFirewallExporter(mockBackend)

	reg := prometheus.NewRegistry()
	reg.MustRegister(exporter)

	expectedMetrics := `
# HELP firewall_rule_byte_count Number of bytes matching the firewall rule
# TYPE firewall_rule_byte_count counter
firewall_rule_byte_count{chain="INPUT",foo="bar",table="filter"} 5678
firewall_rule_byte_count{chain="OUTPUT",key="value",table="filter"} 6789
# HELP firewall_rule_packet_count Number of packets matching the firewall rule
# TYPE firewall_rule_packet_count counter
firewall_rule_packet_count{chain="INPUT",foo="bar",table="filter"} 1234
firewall_rule_packet_count{chain="OUTPUT",key="value",table="filter"} 2345
`

	// testutil.CollectAndCompare is sensitive to labels order, which
	// is extremely dumb^W inconvenient. The whole purpose of this function
	// should be to simplify metric comparison and it fails at doing so.
	// so when expanding this test text-defined metrics should be
	// adjusted to match ordering from exporter (???)
	actualMetrics := testutil.CollectAndCompare(exporter, strings.NewReader(expectedMetrics), "firewall_rule_packet_count", "firewall_rule_byte_count")

	if actualMetrics != nil {
		t.Errorf("Unexpected metrics output:\n%s", actualMetrics)
	}
}

type MockErrorFirewallBackend struct{}

func (m *MockErrorFirewallBackend) GetRules() ([]backend.Rule, error) {
	return nil, errors.New("mock error")
}

func (MockErrorFirewallBackend) GetName() string {
	return "mockerr"
}

func TestFirewallExporterError(t *testing.T) {
	// Create a new MockErrorFirewallBackend
	mockErrorBackend := &MockErrorFirewallBackend{}

	// Create a new FirewallExporter
	exporter := NewFirewallExporter(mockErrorBackend)

	// Register the exporter with a new registry
	reg := prometheus.NewRegistry()
	reg.MustRegister(exporter)

	// Define the expected metrics output
	expectedMetrics := `
# HELP netfilter_exporter_collection_error Whether an error occured during metric collection
# TYPE netfilter_exporter_collection_error gauge
netfilter_exporter_collection_error 1
`

	// Gather the actual metrics output
	err := testutil.CollectAndCompare(exporter, strings.NewReader(expectedMetrics), "firewall_exporter_collect_error")

	// Check for any errors
	if err != nil {
		t.Errorf("Unexpected metrics output:\n%+v", err)
	}
}
