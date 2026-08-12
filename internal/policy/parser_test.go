package policy

import (
	"testing"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

func TestLoadFromFile(t *testing.T) {
	policies, edges, isolation, allPods, err := LoadFromFile("../../testdata/policies.yaml")
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if len(policies) == 0 {
		t.Fatal("expected policies, got 0")
	}

	if len(edges) == 0 {
		t.Fatal("expected edges, got 0")
	}

	if len(allPods) == 0 {
		t.Fatal("expected pods, got 0")
	}

	if isolation == nil {
		t.Fatal("expected isolation map")
	}

	// nginx-ingress has policyTypes=[Egress] → ingress NOT isolated
	if iso, ok := isolation["nginx-ingress"]; ok {
		if iso.IngressIsolated {
			t.Fatal("nginx-ingress should NOT be ingress-isolated")
		}
		if !iso.EgressIsolated {
			t.Fatal("nginx-ingress should be egress-isolated")
		}
	} else {
		t.Fatal("nginx-ingress not in isolation map")
	}

	// legacy-app has policyTypes=[Ingress, Egress] with no rules → deny-all
	if iso, ok := isolation["legacy-app"]; ok {
		if !iso.IngressIsolated || !iso.EgressIsolated {
			t.Fatal("legacy-app should be isolated in both directions")
		}
	}

	// Check that legacy-app has no edges (deny-all)
	for _, e := range edges {
		if e.From == "legacy-app" || e.To == "legacy-app" {
			t.Fatalf("legacy-app should have no edges, found %s→%s", e.From, e.To)
		}
	}

	// Check that nginx-ingress → web-frontend exists
	found := false
	for _, e := range edges {
		if e.From == "nginx-ingress" && e.To == "web-frontend" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected edge nginx-ingress → web-frontend")
	}

	// Check default-allow gaps include pods with only Egress policyTypes
	gaps := graph.FindDefaultAllowGaps(isolation)
	var ingressGaps []string
	for _, g := range gaps {
		if g.Direction == "Ingress" {
			ingressGaps = append(ingressGaps, g.Pod)
		}
	}
	// nginx-ingress, prometheus, log-collector, data-exporter all have policyTypes=[Egress]
	gapSet := make(map[string]bool)
	for _, g := range ingressGaps {
		gapSet[g] = true
	}
	for _, pod := range []string{"nginx-ingress", "prometheus", "log-collector", "data-exporter"} {
		if !gapSet[pod] {
			t.Errorf("expected %s in ingress gaps (policyTypes=[Egress] → no ingress coverage)", pod)
		}
	}
}
