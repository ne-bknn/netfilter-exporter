package iptables

import (
	"flag"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"testing"
)

var EnableSystemTests = flag.Bool("run_system_tests", false, "Run tests that operate against the live kernel")

func AmIRoot(t *testing.T) bool {
	t.Helper()

	u, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	return u.Uid == "0"
}

func TestParseIptablesXML(t *testing.T) {
	xmlData, err := os.ReadFile("testdata/iptables-rules.xml")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	iptablesRules, err := parseIPTablesXML(strings.NewReader(string(xmlData)))
	if err != nil {
		t.Fatalf("Failed to parse XML: %v", err)
	}

	if iptablesRules.Version != "1.0" {
		t.Errorf("Expected version '1.0', got '%s'", iptablesRules.Version)
	}

	if len(iptablesRules.Tables) == 0 {
		t.Errorf("Expected at least one table, got none")
	}
}

func TestGetRules(t *testing.T) {
	xmlData, err := os.ReadFile("testdata/iptables-2.xml")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	mockReadXML := func() (io.Reader, error) {
		return strings.NewReader(string(xmlData)), nil
	}

	backend := NewIPTablesBackend(mockReadXML, parseIPTablesXML)

	rules, err := backend.GetRules()
	if err != nil {
		t.Fatalf("Failed to get rules: %v", err)
	}

	if len(rules) != 4 {
		t.Fatalf("Expected 4 rules, got %d", len(rules))
	}

	expectedRules := []struct {
		expectedTags  map[string]string
		expectedChain string
		expectedTable string
	}{
		{
			expectedTags:  map[string]string{"foo": "bar"},
			expectedChain: "INPUT",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"key": "value"},
			expectedChain: "OUTPUT",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"log": "forward"},
			expectedChain: "FORWARD",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"port": "8080"},
			expectedChain: "CUSTOM_CHAIN",
			expectedTable: "filter",
		},
	}

	for _, expectedRule := range expectedRules {
		found := false
		for _, rule := range rules {
			if rule.Chain == expectedRule.expectedChain && rule.Table == expectedRule.expectedTable {
				matched := true
				for key, value := range expectedRule.expectedTags {
					if rule.Tags[key] != value {
						matched = false
						break
					}
				}
				if matched {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("Expected rule not found: chain=%s, table=%s, tags=%v",
				expectedRule.expectedChain, expectedRule.expectedTable, expectedRule.expectedTags)
		}
	}
}

func BenchmarkParseIPTablesXML(b *testing.B) {
	xmlData, err := os.ReadFile("testdata/iptables-rules.xml")
	if err != nil {
		b.Fatalf("Failed to read test data file: %v", err)
	}

	xmlReader := strings.NewReader(string(xmlData))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		xmlReader.Seek(0, io.SeekStart)

		_, err := parseIPTablesXML(xmlReader)
		if err != nil {
			b.Fatalf("Failed to parse XML: %v", err)
		}
	}
}

func FuzzParseIPTablesXML(f *testing.F) {
	initialSeeds := []string{
		"<iptables-rules version=\"1.0\"><table name=\"filter\"><chain name=\"INPUT\" policy=\"ACCEPT\" packet-count=\"0\" byte-count=\"0\"></chain></table></iptables-rules>",
		"<iptables-rules version=\"1.0\"></iptables-rules>",
		"<iptables-rules version=\"1.0><table name=\"filter\"><chain name=\"INPUT\" policy=\"ACCEPT\" packet-count=\"0\" byte-count=\"0\"></chain></table></iptables-rules>",
		"<invalid-xml>",
		"",
	}

	for _, seed := range initialSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		reader := strings.NewReader(data)

		_, _ = parseIPTablesXML(reader)
	})
}

func TestSystemGetRules(t *testing.T) {
	applyIPTablesRules := func(t *testing.T) {
		commands := [][]string{
			{"iptables", "-N", "CUSTOM_CHAIN"},
			{"iptables", "-A", "INPUT", "-s", "192.168.1.1", "-m", "comment", "--comment", "\"netfilter-exporter foo=bar\"", "-j", "ACCEPT"},
			{"iptables", "-A", "OUTPUT", "-d", "192.168.1.2", "-m", "comment", "--comment", "\"netfilter-exporter key=value\"", "-j", "DROP"},
			{"iptables", "-A", "FORWARD", "-s", "192.168.1.0/24", "-m", "comment", "--comment", "\"netfilter-exporter log=forward\"", "-j", "LOG"},
			{"iptables", "-A", "CUSTOM_CHAIN", "-p", "tcp", "--dport", "8080", "-m", "comment", "--comment", "\"netfilter-exporter port=8080\"", "-j", "REJECT"},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to apply iptables rule: %v", err)
			}
		}
	}

	removeIPTablesRules := func(t *testing.T) {
		commands := [][]string{
			{"iptables", "-D", "INPUT", "-s", "192.168.1.1", "-m", "comment", "--comment", "\"netfilter-exporter foo=bar\"", "-j", "ACCEPT"},
			{"iptables", "-D", "OUTPUT", "-d", "192.168.1.2", "-m", "comment", "--comment", "\"netfilter-exporter key=value\"", "-j", "DROP"},
			{"iptables", "-D", "FORWARD", "-s", "192.168.1.0/24", "-m", "comment", "--comment", "\"netfilter-exporter log=forward\"", "-j", "LOG"},
			{"iptables", "-D", "CUSTOM_CHAIN", "-p", "tcp", "--dport", "8080", "-m", "comment", "--comment", "\"netfilter-exporter port=8080\"", "-j", "REJECT"},
			{"iptables", "-F", "CUSTOM_CHAIN"},
			{"iptables", "-X", "CUSTOM_CHAIN"},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to remove iptables rule: %v", err)
			}
		}
	}

	if !*EnableSystemTests {
		t.Skip("System tests are not enabled")
	}

	if !AmIRoot(t) {
		t.Skip("System tests are enabled, but current user is not root")
	}

	applyIPTablesRules(t)

	defer removeIPTablesRules(t)

	backend := MakeIPTablesBackend()

	rules, err := backend.GetRules()
	if err != nil {
		t.Fatalf("Failed to get rules: %v", err)
	}

	expectedRules := []struct {
		expectedTags  map[string]string
		expectedChain string
		expectedTable string
	}{
		{
			expectedTags:  map[string]string{"foo": "bar"},
			expectedChain: "INPUT",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"key": "value"},
			expectedChain: "OUTPUT",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"log": "forward"},
			expectedChain: "FORWARD",
			expectedTable: "filter",
		},
		{
			expectedTags:  map[string]string{"port": "8080"},
			expectedChain: "CUSTOM_CHAIN",
			expectedTable: "filter",
		},
	}

	for _, expectedRule := range expectedRules {
		found := false
		for _, rule := range rules {
			if rule.Chain == expectedRule.expectedChain && rule.Table == expectedRule.expectedTable {
				matched := true
				for key, value := range expectedRule.expectedTags {
					if rule.Tags[key] != value {
						matched = false
						break
					}
				}
				if matched {
					found = true
					break
				}
			}
		}
		if !found {
			t.Errorf("Expected rule not found: chain=%s, table=%s, tags=%v",
				expectedRule.expectedChain, expectedRule.expectedTable, expectedRule.expectedTags)
		}
	}
}
