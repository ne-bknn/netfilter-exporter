package nftables

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
)

type Nftables struct {
	Nftables []Nftable `json:"nftables"`
}

type Nftable struct {
	Metainfo *Metainfo `json:"metainfo,omitempty"`
	Table    *Table    `json:"table,omitempty"`
	Chain    *Chain    `json:"chain,omitempty"`
	Rule     *Rule     `json:"rule,omitempty"`
}

type Metainfo struct {
	Version           string `json:"version"`
	ReleaseName       string `json:"release_name"`
	JsonSchemaVersion int    `json:"json_schema_version"`
}

type Table struct {
	Family string `json:"family"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
}

type Chain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type Rule struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Handle  int    `json:"handle"`
	Expr    []Expr `json:"expr"`
	Comment string `json:"comment,omitempty"`
}

type Expr struct {
	Match   *Match   `json:"match,omitempty"`
	Xt      *Xt      `json:"xt,omitempty"`
	Counter *Counter `json:"counter,omitempty"`
	Accept  *Accept  `json:"accept,omitempty"`
}

type Match struct {
	Op    string `json:"op"`
	Left  Left   `json:"left"`
	Right Right  `json:"right"`
}

type Left struct {
	Payload Payload `json:"payload"`
}

type Payload struct {
	Protocol string `json:"protocol"`
	Field    string `json:"field"`
}

type Right struct {
	Prefix Prefix `json:"prefix"`
}

type Prefix struct {
	Addr string `json:"addr"`
	Len  int    `json:"len"`
}

type Xt struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type Counter struct {
	Packets int `json:"packets"`
	Bytes   int `json:"bytes"`
}

type Accept struct{}

func readNftablesJSON() (io.Reader, error) {
	cmd := exec.Command("nft", "list", "ruleset", "-j")
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error getting stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting nft command: %w", err)
	}

	return output, nil
}

func parseNftablesJSON(r io.Reader) (*Nftables, error) {
	var nftables Nftables
	if err := json.NewDecoder(r).Decode(&nftables); err != nil {
		return nil, fmt.Errorf("error decoding JSON: %w", err)
	}
	return &nftables, nil
}

func main() {
	output, err := readNftablesJSON()
	if err != nil {
		fmt.Println(err)
		return
	}

	nftables, err := parseNftablesJSON(output)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(nftables)
}
