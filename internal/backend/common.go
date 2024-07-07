package backend

import (
    "regexp"
    "strings"
)

func ParseRuleAnnotation(input string) map[string]string {
    input = strings.Trim(input, "\"")
    if !strings.HasPrefix(input, "netfilter-exporter") {
        return nil
    }

    input = strings.TrimPrefix(input, "netfilter-exporter")

    pairs := strings.Fields(input)

    validKeyValue := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

    result := make(map[string]string)

    for _, pair := range pairs {
        kv := strings.SplitN(pair, "=", 2)
        if len(kv) != 2 {
            // TODO: log parsing error
            continue
        }

        key, value := kv[0], kv[1]

        if !validKeyValue.MatchString(key) || !validKeyValue.MatchString(value) {
            // TODO: log parsing error
            continue
        }

        result[key] = value
    }

    return result
}
