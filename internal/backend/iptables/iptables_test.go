package iptables

import (
	"io"
	"os"
	"strings"
	"testing"
)

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
