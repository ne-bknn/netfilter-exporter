package backend

import (
	"reflect"
	"strings"
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
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Input with invalid value",
			input:    "netfilter-exporter key1=value1 key2=invalid/value",
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Input with hanging field",
			input:    "netfilter-exporter key1=value1 key2",
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Input with missing value",
			input:    "netfilter-exporter key1=value1 key2=",
			expected: map[string]string{"key1": "value1"},
		},
		{
			name:     "Input with missing key",
			input:    "netfilter-exporter =value1",
			expected: map[string]string{},
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

func BenchmarkParseRuleAnnotation(b *testing.B) {
	input := "\"netfilter-exporter foo=bar key=value log=forward port=8080 another_key=another_value\""

	for i := 0; i < b.N; i++ {
		ParseRuleAnnotation(input)
	}
}

func FuzzParseRuleAnnotation(f *testing.F) {
	inputs := []string{
		"\"netfilter-exporter foo=bar key=value log=forward port=8080 another_key=another_value\"",
		"\"netfilter-exporter key=value\"",
		"\"invalid-prefix foo=bar\"",
		"\"netfilter-exporter missing-equals-sign\"",
		"\"netfilter-exporter key=value another_key=\"",
		"\"netfilter-exporter key1=value1 key2=value2\"",
		"",
		"random string without any structure",
		"\"netfilter-exporter foo=bar key\"",
	}

	for _, input := range inputs {
		f.Add(input)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := ParseRuleAnnotation(input)

		if strings.HasPrefix(strings.Trim(input, "\""), "netfilter-exporter") && result == nil {
			t.Errorf("Expected non-nil result for input: %s", input)
		}
	})
}
