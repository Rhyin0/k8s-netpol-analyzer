package graph

import (
	"testing"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
)

// policy allowing frontend -> api on 8080 and 9090, both sides explicitly isolated.
func twoPortPolicies() []NetworkPolicy {
	return []NetworkPolicy{
		{
			Metadata: Metadata{Name: "api-ingress", Namespace: "shop"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{{
					From: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "frontend"}}}},
					Ports: []PortRule{
						{Protocol: "TCP", Port: 8080},
						{Protocol: "TCP", Port: 9090},
					},
				}},
			},
		},
	}
}

func findDiffEdge(t *testing.T, d TopologyDiff, port uint32) DiffEdge {
	t.Helper()
	for _, e := range d.Edges {
		if e.Port == port {
			return e
		}
	}
	t.Fatalf("no diff edge for port %d in %+v", port, d.Edges)
	return DiffEdge{}
}

// The headline case: a policy opens two ports, only one carries traffic.
// Matching on the node pair alone would call the whole edge confirmed.
func TestCompareTopologiesFlagsUnusedPortOnUsedPair(t *testing.T) {
	g := NewGraph(twoPortPolicies())

	observed := map[flowstat.EdgeKey]flowstat.EdgeStat{
		{Src: "frontend", Dst: "api", Port: 8080, Proto: "TCP"}: {Forwarded: 42},
	}

	d := CompareTopologies(g, observed, time.Now().Add(-time.Hour), 30*time.Minute)

	if got := findDiffEdge(t, d, 8080); got.Class != ClassConfirmed || got.Forwarded != 42 {
		t.Errorf("port 8080 = %s fwd=%d; want confirmed fwd=42", got.Class, got.Forwarded)
	}
	if got := findDiffEdge(t, d, 9090); got.Class != ClassOverpermissive {
		t.Errorf("port 9090 = %s; want overpermissive", got.Class)
	}
}

func TestCompareTopologiesCarriesPolicyRefs(t *testing.T) {
	g := NewGraph(twoPortPolicies())
	d := CompareTopologies(g, nil, time.Now().Add(-time.Hour), 30*time.Minute)

	e := findDiffEdge(t, d, 9090)
	if len(e.PolicyRefs) != 1 || e.PolicyRefs[0] != "shop/api-ingress" {
		t.Fatalf("PolicyRefs = %v; want [shop/api-ingress]", e.PolicyRefs)
	}
}

func TestCompareTopologiesShortWindowIsInsufficient(t *testing.T) {
	g := NewGraph(twoPortPolicies())

	d := CompareTopologies(g, nil, time.Now().Add(-time.Minute), 30*time.Minute)
	if d.Window.Sufficient {
		t.Error("1m window against a 30m minimum reported as sufficient")
	}

	d = CompareTopologies(g, nil, time.Now().Add(-time.Hour), 30*time.Minute)
	if !d.Window.Sufficient {
		t.Error("1h window against a 30m minimum reported as insufficient")
	}
}

func TestCompareTopologiesUnexpectedDrop(t *testing.T) {
	g := NewGraph(twoPortPolicies())

	observed := map[flowstat.EdgeKey]flowstat.EdgeStat{
		// No policy permits frontend -> api on 5432, and it was dropped.
		{Src: "frontend", Dst: "api", Port: 5432, Proto: "TCP"}: {Dropped: 7},
	}

	d := CompareTopologies(g, observed, time.Now().Add(-time.Hour), 30*time.Minute)

	e := findDiffEdge(t, d, 5432)
	if e.Class != ClassUnexpectedDrop || e.Dropped != 7 {
		t.Fatalf("port 5432 = %s dropped=%d; want unexpected_drop dropped=7", e.Class, e.Dropped)
	}
}

// A default-allow edge permits every port, so it stays over-permissive on the
// wildcard remainder even when some ports are confirmed.
func TestCompareTopologiesWildcardEdge(t *testing.T) {
	policies := []NetworkPolicy{
		{
			Metadata: Metadata{Name: "open", Namespace: "shop"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{{
					From: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "frontend"}}}},
				}},
			},
		},
	}
	g := NewGraph(policies)

	observed := map[flowstat.EdgeKey]flowstat.EdgeStat{
		{Src: "frontend", Dst: "api", Port: 8080, Proto: "TCP"}: {Forwarded: 5},
	}

	d := CompareTopologies(g, observed, time.Now().Add(-time.Hour), 30*time.Minute)

	if got := findDiffEdge(t, d, 8080); got.Class != ClassConfirmed {
		t.Errorf("observed port on wildcard edge = %s; want confirmed", got.Class)
	}
	wildcard := findDiffEdge(t, d, 0)
	if wildcard.Class != ClassOverpermissive || wildcard.PortLabel() != "*/*" {
		t.Errorf("wildcard remainder = %s %s; want overpermissive */*",
			wildcard.Class, wildcard.PortLabel())
	}
}
