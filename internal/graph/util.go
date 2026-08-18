package graph

import (
	"sort"
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

// ParseNodeID inverts LabelStr: it recovers the label constraints a workload
// must satisfy to be the given node. Keeping this next to LabelStr means node
// identity has exactly one definition — callers that observe real workloads
// (Hubble flows) resolve through here rather than reimplementing the mapping.
func ParseNodeID(nodeID string) map[string]string {
	if nodeID == "" {
		return nil
	}
	// LabelStr collapses an "app" label to its bare value, so an ID with no
	// "=" is by construction an app label.
	if !strings.Contains(nodeID, "=") {
		return map[string]string{"app": nodeID}
	}
	out := make(map[string]string)
	for _, part := range strings.Split(nodeID, ",") {
		if k, v, ok := strings.Cut(part, "="); ok {
			out[k] = v
		}
	}
	return out
}

// MatchNodeID reports whether a workload's full label set satisfies nodeID.
// A workload carries many labels beyond those a policy selects on, so this is a
// subset test, not the equality test selectorMatchesPod performs on selectors.
func MatchNodeID(nodeID string, podLabels map[string]string) bool {
	want := ParseNodeID(nodeID)
	if len(want) == 0 {
		return false
	}
	for k, v := range want {
		if podLabels[k] != v {
			return false
		}
	}
	return true
}

// ResolveNodeID maps a workload's label set onto one of the graph's node IDs.
// When several nodes match, the most specific (most constrained) one wins, with
// a lexicographic tiebreak so resolution is deterministic across runs.
func ResolveNodeID(podLabels map[string]string, knownNodes []string) (string, bool) {
	if len(podLabels) == 0 {
		return "", false
	}

	exact := LabelStr(podLabels)
	best, bestSpec := "", -1
	for _, n := range knownNodes {
		if n == exact {
			return n, true
		}
		if !MatchNodeID(n, podLabels) {
			continue
		}
		spec := len(ParseNodeID(n))
		if spec > bestSpec || (spec == bestSpec && n < best) {
			best, bestSpec = n, spec
		}
	}
	return best, best != ""
}

// NodeIDs returns every node in the graph, sorted.
//
// Collected from the isolation map rather than from the edge list: an
// implicit-deny node has no edges at all and would vanish if derived from edges.
func (g *Graph) NodeIDs() []string {
	if g == nil {
		return nil
	}
	ids := make([]string, 0, len(g.Isolation))
	for id := range g.Isolation {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
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
			existing.PolicyRefs = mergeRefs(existing.PolicyRefs, e.PolicyRefs...)
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
