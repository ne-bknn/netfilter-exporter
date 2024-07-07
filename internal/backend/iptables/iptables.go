package iptables

import (
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/ne-bknn/netfilter-exporter/internal/backend"
)

type IptablesRules struct {
	XMLName xml.Name `xml:"iptables-rules"`
	Version string   `xml:"version,attr"`
	Tables  []Table  `xml:"table"`
}

type Table struct {
	Name   string  `xml:"name,attr"`
	Chains []Chain `xml:"chain"`
}

type Chain struct {
	Name        string `xml:"name,attr"`
	Policy      string `xml:"policy,attr,omitempty"`
	PacketCount int    `xml:"packet-count,attr"`
	ByteCount   int    `xml:"byte-count,attr"`
	Rules       []Rule `xml:"rule"`
}

type Rule struct {
	PacketCount uint64      `xml:"packet-count,attr"`
	ByteCount   uint64      `xml:"byte-count,attr"`
	Conditions  *Conditions `xml:"conditions,omitempty"`
	Actions     *Actions    `xml:"actions,omitempty"`
}

type Conditions struct {
	Matches   []Match    `xml:"match"`
	Comments  []Comment  `xml:"comment>comment"`
	Conntrack *Conntrack `xml:"conntrack,omitempty"`
	Addrtype  *Addrtype  `xml:"addrtype,omitempty"`
}

type Match struct {
	S      string `xml:"s,omitempty"`
	D      string `xml:"d,omitempty"`
	O      string `xml:"o,omitempty"`
	I      string `xml:"i,omitempty"`
	Invert bool   `xml:"invert,attr,omitempty"`
}

type Comment struct {
	Text string `xml:",chardata"`
}

type Conntrack struct {
	Ctstate string `xml:"ctstate"`
}

type Addrtype struct {
	DstType string `xml:"dst-type"`
}

type Actions struct {
	Calls      []Call  `xml:"call"`
	Accept     *string `xml:"ACCEPT,omitempty"`
	Return     *string `xml:"RETURN,omitempty"`
	Drop       *string `xml:"DROP,omitempty"`
	Masquerade *string `xml:"MASQUERADE,omitempty"`
	Reject     *Reject `xml:"REJECT,omitempty"`
}

type Reject struct {
	RejectWith string `xml:"reject-with"`
}

type Call struct {
	Table string `xml:",chardata"`
}

func getIPTablesXML() (io.Reader, error) {
	r, w := io.Pipe()

	iptablesSaveCmd := exec.Command("iptables-save", "-c")
	iptablesXmlCmd := exec.Command("iptables-xml")

	iptablesXmlCmd.Stdin = r

	output, err := iptablesXmlCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error getting stdout pipe: %w", err)
	}

	if err := iptablesXmlCmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting iptables-xml command: %w", err)
	}

	go func() {
		defer w.Close()
		output, err := iptablesSaveCmd.Output()
		if err != nil {
			fmt.Printf("error running iptables-save: %v\n", err)
			return
		}
		w.Write(output)
	}()

	return output, nil
}

func parseIPTablesXML(r io.Reader) (*IptablesRules, error) {
	var iptablesRules IptablesRules
	if err := xml.NewDecoder(r).Decode(&iptablesRules); err != nil {
		return nil, fmt.Errorf("error decoding XML: %w", err)
	}
	return &iptablesRules, nil
}

func iptablesRuleToBackendRule(r Rule) *backend.Rule {
	if r.Conditions != nil && r.Conditions.Comments != nil {
		for _, comment := range r.Conditions.Comments {
			if strings.HasPrefix(strings.Trim(comment.Text, "\""), "netfilter-exporter") {
				tags := backend.ParseRuleAnnotation(comment.Text)
				return &backend.Rule{
					Tags:        tags,
					PacketCount: r.PacketCount,
					ByteCount:   r.ByteCount,
				}
			}
		}
	}

	return nil
}

type ReadXMLFunc func() (io.Reader, error)
type ParseXMLFunc func(io.Reader) (*IptablesRules, error)

type IPTablesBackend struct {
	readXML  ReadXMLFunc
	parseXML ParseXMLFunc
}

func NewIPTablesBackend(readXML ReadXMLFunc, parseXML ParseXMLFunc) *IPTablesBackend {
	return &IPTablesBackend{
		readXML:  readXML,
		parseXML: parseXML,
	}
}

func MakeIPTablesBackend() *IPTablesBackend {
	return NewIPTablesBackend(getIPTablesXML, parseIPTablesXML)
}

func (b IPTablesBackend) GetRules() ([]backend.Rule, error) {
	r, err := b.readXML()
	if err != nil {
		return nil, err
	}

	iptablesRules, err := b.parseXML(r)
	if err != nil {
		return nil, err
	}

	var rules []backend.Rule

	for _, table := range iptablesRules.Tables {
		for _, chain := range table.Chains {
			for _, rule := range chain.Rules {
				convertedRule := iptablesRuleToBackendRule(rule)
				if convertedRule != nil {
					convertedRule.Chain = chain.Name
					convertedRule.Table = table.Name
					rules = append(rules, *convertedRule)
				}
			}
		}
	}

	return rules, nil
}

func (IPTablesBackend) GetName() string {
	return "iptables"
}

var _ backend.FirewallBackend = IPTablesBackend{}
