package graph

import (
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

// Dedup merges edges with the same (From, To), combining their port ranges.
func Dedup(edges []Edge) []Edge {
	type edgeKey struct{ From, To string }
	merged := make(map[edgeKey]*Edge)
	var order []edgeKey

	for _, e := range edges {
		key := edgeKey{e.From, e.To}
		if existing, ok := merged[key]; ok {
			existing.Ports = mergePortRanges(existing.Ports, e.Ports)
		} else {
			eCopy := e
			merged[key] = &eCopy
			order = append(order, key)
		}
	}

	result := make([]Edge, len(order))
	for i, key := range order {
		result[i] = *merged[key]
	}
	return result
}

func mergePortRanges(a, b []PortRange) []PortRange {
	if hasAllPorts(a) || hasAllPorts(b) {
		return []PortRange{AllPorts}
	}
	seen := make(map[PortRange]bool)
	var result []PortRange
	for _, p := range a {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	for _, p := range b {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}
