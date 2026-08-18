package graph

import "testing"

func TestResolveNodeIDMatchesAppLabelAmongExtraPodLabels(t *testing.T) {
	known := []string{"checkout", "order-db", "tier=cache,zone=a"}

	// A real pod carries many labels beyond the one the policy selects on.
	podLabels := map[string]string{
		"app":                          "checkout",
		"pod-template-hash":            "7d4b8c",
		"io.kubernetes.pod.namespace":  "shop",
		"app.kubernetes.io/managed-by": "helm",
	}

	got, ok := ResolveNodeID(podLabels, known)
	if !ok || got != "checkout" {
		t.Fatalf("ResolveNodeID = %q, %v; want \"checkout\", true", got, ok)
	}
}

func TestResolveNodeIDMultiLabelNode(t *testing.T) {
	known := []string{"checkout", "tier=cache,zone=a"}

	podLabels := map[string]string{"tier": "cache", "zone": "a", "extra": "x"}
	got, ok := ResolveNodeID(podLabels, known)
	if !ok || got != "tier=cache,zone=a" {
		t.Fatalf("ResolveNodeID = %q, %v; want multi-label node", got, ok)
	}

	// Missing one of the required labels must not match.
	if _, ok := ResolveNodeID(map[string]string{"tier": "cache"}, known); ok {
		t.Fatal("partial label set should not resolve")
	}
}

func TestResolveNodeIDUnknownWorkload(t *testing.T) {
	known := []string{"checkout", "order-db"}
	if got, ok := ResolveNodeID(map[string]string{"app": "grafana"}, known); ok {
		t.Fatalf("unrelated workload resolved to %q", got)
	}
	if _, ok := ResolveNodeID(nil, known); ok {
		t.Fatal("empty label set should not resolve")
	}
}

// Node IDs round-trip through LabelStr, so resolution stays consistent with the
// IDs BuildEdges produces.
func TestParseNodeIDInvertsLabelStr(t *testing.T) {
	for _, labels := range []map[string]string{
		{"app": "checkout"},
		{"tier": "cache"},
	} {
		id := LabelStr(labels)
		if !MatchNodeID(id, labels) {
			t.Fatalf("MatchNodeID(%q, %v) = false", id, labels)
		}
	}
}

func TestNodeIDsIncludesImplicitDenyIsolates(t *testing.T) {
	// "lonely" is selected by a deny-all policy: isolated, zero edges.
	policies := []NetworkPolicy{
		{
			Metadata: Metadata{Name: "deny-all", Namespace: "shop"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "lonely"}},
				PolicyTypes: []string{"Ingress", "Egress"},
			},
		},
	}

	g := NewGraph(policies)
	found := false
	for _, id := range g.NodeIDs() {
		if id == "lonely" {
			found = true
		}
	}
	if !found {
		t.Fatalf("implicit-deny node dropped from NodeIDs: %v", g.NodeIDs())
	}
}
