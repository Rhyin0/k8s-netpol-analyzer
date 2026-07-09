package graph

import (
	"fmt"
	"strings"
)

func LabelStr(labels map[string]string) string {
	if app, ok := labels["app"]; ok {
		return app
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func Dedup(edges []Edge) []Edge {
	seen := make(map[string]bool)
	var result []Edge
	for _, e := range edges {
		key := fmt.Sprintf("%s->%s:%s/%d", e.From, e.To, e.Protocol, e.Port)
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}
