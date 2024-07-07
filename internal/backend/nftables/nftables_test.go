package nftables

import (
	"os"
	"strings"
	"testing"
)

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
