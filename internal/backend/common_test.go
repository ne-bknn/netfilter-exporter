package backend

import (
    "reflect"
    "testing"
)

func TestParseString(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected map[string]string
    }{
        {
            name:     "Valid input with multiple key-value pairs",
            input:    "netfilter-exporter key1=value1 key2=value2 key3=value3",
            expected: map[string]string{"key1": "value1", "key2": "value2", "key3": "value3"},
        },
        {
            name:     "Valid input with single key-value pair",
            input:    "netfilter-exporter key1=value1",
            expected: map[string]string{"key1": "value1"},
        },
        {
            name:     "Input does not start with netfilter-exporter",
            input:    "other-prefix key1=value1 key2=value2",
            expected: nil,
        },
        {
            name:     "Empty input string",
            input:    "",
            expected: nil,
        },
        {
            name:     "Input with invalid key",
            input:    "netfilter-exporter key1=value1 invalid*key=value2",
            expected: nil,
        },
        {
            name:     "Input with invalid value",
            input:    "netfilter-exporter key1=value1 key2=invalid value",
            expected: nil,
        },
        {
            name:     "Input with missing value",
            input:    "netfilter-exporter key1=value1 key2=",
            expected: nil,
        },
        {
            name:     "Input with missing key",
            input:    "netfilter-exporter =value1",
            expected: nil,
        },
        {
            name:     "Input with no key-value pairs",
            input:    "netfilter-exporter",
            expected: map[string]string{},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ParseRuleAnnotation(tt.input)
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("ParseString(%q) = %v; want %v", tt.input, result, tt.expected)
            }
        })
    }
}

