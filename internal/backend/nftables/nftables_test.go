package nftables

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
	u, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	return u.Uid == "0"
}

func TestGetRules(t *testing.T) {
	jsonData, err := os.ReadFile("testdata/nftables.json")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	mockReadJSON := func() (io.Reader, error) {
		return strings.NewReader(string(jsonData)), nil
	}

	backend := NewNFTablesBackend(mockReadJSON, parseNftablesJSON)

	rules, err := backend.GetRules()
	if err != nil {
		t.Fatalf("Failed to get rules: %v", err)
	}

	// Adjust the expected number of rules based on the JSON data
	if len(rules) != 6 {
		t.Fatalf("Expected 6 rules, got %d", len(rules))
	}

	// Define the expected rules based on the JSON data
	expectedRules := []struct {
		expectedTags  map[string]string
		expectedChain string
		expectedTable string
	}{
		{
			expectedTags:  map[string]string{},
			expectedChain: "INPUT",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{},
			expectedChain: "INPUT",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{"comment": "ALLOW INPUT"},
			expectedChain: "INPUT",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{},
			expectedChain: "FORWARD",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{},
			expectedChain: "FORWARD",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{},
			expectedChain: "OUTPUT",
			expectedTable: "mangle",
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

func TestParseNftablesJSON(t *testing.T) {
	jsonData, err := os.ReadFile("testdata/nftables.json")
	if err != nil {
		t.Fatalf("Failed to read test data file: %v", err)
	}

	nftables, err := parseNftablesJSON(strings.NewReader(string(jsonData)))
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if len(nftables.Nftables) == 0 {
		t.Errorf("Expected at least one nftable, got none")
	}

	if nftables.Nftables[0].Metainfo.Version != "1.0.9" {
		t.Errorf("Expected version '1.0.9', got '%s'", nftables.Nftables[0].Metainfo.Version)
	}
}

func FuzzParseNftablesJSON(f *testing.F) {
	initialSeeds := []string{
		`{"nftables":[{"metainfo":{"version":"1.0.9"}}]}`,
		`{"nftables":[]}`,
		`{"nftables":[{"metainfo":{"version":"1.0.9"}},{"table":{"family":"ip","name":"filter"}}]}`,
		`{"invalid-json":}`,
		``,
	}

	for _, seed := range initialSeeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data string) {
		reader := strings.NewReader(data)

		_, _ = parseNftablesJSON(reader)
	})
}

func BenchmarkParseNftablesJSON(b *testing.B) {
	jsonData, err := os.ReadFile("testdata/nftables.json")
	if err != nil {
		b.Fatalf("Failed to read test data file: %v", err)
	}

	jsonReader := strings.NewReader(string(jsonData))

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		jsonReader.Seek(0, io.SeekStart)

		_, err := parseNftablesJSON(jsonReader)
		if err != nil {
			b.Fatalf("Failed to parse JSON: %v", err)
		}
	}
}

func TestSystemGetRules(t *testing.T) {
	t.Skip()

	applyNFTablesRules := func(t *testing.T) {
		commands := [][]string{
			{"nft", "add", "table", "ip", "mangle"},
			{"nft", "add", "chain", "ip", "mangle", "INPUT", "{ type filter hook input priority 0; }"},
			{"nft", "add", "rule", "ip", "mangle", "INPUT", "ip", "saddr", "192.168.1.1", "accept", "comment", "\"netfilter-exporter foo=bar\""},
			{"nft", "add", "rule", "ip", "mangle", "INPUT", "ip", "daddr", "192.168.1.2", "drop", "comment", "\"netfilter-exporter key=value\""},
			{"nft", "add", "rule", "ip", "mangle", "INPUT", "ip", "saddr", "192.168.1.0/24", "log", "comment", "\"netfilter-exporter log=forward\""},
			{"nft", "add", "chain", "ip", "mangle", "CUSTOM_CHAIN", "{ type filter hook prerouting priority 0; }"},
			{"nft", "add", "rule", "ip", "mangle", "CUSTOM_CHAIN", "tcp", "dport", "8080", "reject", "comment", "\"netfilter-exporter port=8080\""},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to apply nftables rule: %v, rule: %+v", err, cmdArgs)
			}
		}
	}

	removeNFTablesRules := func(t *testing.T) {
		commands := [][]string{
			{"nft", "flush", "chain", "ip", "mangle", "INPUT"},
			{"nft", "delete", "chain", "ip", "mangle", "INPUT"},
			{"nft", "flush", "chain", "ip", "mangle", "CUSTOM_CHAIN"},
			{"nft", "delete", "chain", "ip", "mangle", "CUSTOM_CHAIN"},
			{"nft", "delete", "table", "ip", "mangle"},
		}

		for _, cmdArgs := range commands {
			cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
			if err := cmd.Run(); err != nil {
				t.Fatalf("Failed to remove nftables rule: %v", err)
			}
		}
	}

	if !*EnableSystemTests {
		t.Skip("System tests are not enabled")
	}

	if !AmIRoot(t) {
		t.Skip("System tests are enabled, but current user is not root")
	}

	applyNFTablesRules(t)

	defer removeNFTablesRules(t)

	backend := MakeNFTablesBackend()

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
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{"key": "value"},
			expectedChain: "INPUT",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{"log": "forward"},
			expectedChain: "INPUT",
			expectedTable: "mangle",
		},
		{
			expectedTags:  map[string]string{"port": "8080"},
			expectedChain: "CUSTOM_CHAIN",
			expectedTable: "mangle",
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
