package visualise

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

func testPolicies() []graph.NetworkPolicy {
	return []graph.NetworkPolicy{
		{
			Metadata: graph.Metadata{Name: "api-ingress", Namespace: "shop"},
			Spec: graph.Spec{
				PodSelector: graph.PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []graph.IngressRule{{
					From: []graph.Peer{{
						PodSelector: graph.PodSelector{MatchLabels: map[string]string{"app": "frontend"}},
					}},
					Ports: []graph.PortRule{
						{Protocol: "TCP", Port: 8080},
						{Protocol: "TCP", Port: 9090},
					},
				}},
			},
		},
		{
			// Isolated in both directions with no rules: implicit-deny, zero edges.
			Metadata: graph.Metadata{Name: "deny-all", Namespace: "shop"},
			Spec: graph.Spec{
				PodSelector: graph.PodSelector{MatchLabels: map[string]string{"app": "quarantined"}},
				PolicyTypes: []string{"Ingress", "Egress"},
			},
		},
	}
}

func renderWithDiff(t *testing.T) jsonGraph {
	t.Helper()

	g := graph.NewGraph(testPolicies())
	observed := map[flowstat.EdgeKey]flowstat.EdgeStat{
		{Src: "frontend", Dst: "api", Port: 8080, Proto: "TCP"}: {Forwarded: 100},
		// Not permitted anywhere, and dropped.
		{Src: "quarantined", Dst: "api", Port: 5432, Proto: "TCP"}: {Dropped: 3},
	}
	diff := graph.CompareTopologies(g, observed, time.Now().Add(-time.Hour), 30*time.Minute)

	data, err := RenderJSON(g.Edges, nil, g.Isolation, &diff)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	var out jsonGraph
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// Nodes come from the isolation map, so a node with no edges at all still
// appears. Deriving them from the edge list would silently drop it.
func TestRenderJSONKeepsImplicitDenyNode(t *testing.T) {
	out := renderWithDiff(t)
	for _, n := range out.Nodes {
		if n.ID == "quarantined" {
			if n.IngressState != "implicit-deny" {
				t.Errorf("quarantined ingressState = %q; want implicit-deny", n.IngressState)
			}
			return
		}
	}
	t.Fatalf("implicit-deny node missing from export: %+v", out.Nodes)
}

// Unexpected drops have no static edge, so they must be appended rather than
// annotated onto an existing one.
func TestRenderJSONAppendsUnexpectedDropEdge(t *testing.T) {
	out := renderWithDiff(t)
	for _, e := range out.Edges {
		if e.Class == string(graph.ClassUnexpectedDrop) {
			if e.From != "quarantined" || e.To != "api" || e.Dropped != 3 {
				t.Fatalf("unexpected_drop edge = %+v", e)
			}
			return
		}
	}
	t.Fatalf("unexpected_drop edge missing from export: %+v", out.Edges)
}

// A pair with one used and one unused port stays flagged, and says which port.
func TestRenderJSONRollsUpPartiallyUsedEdge(t *testing.T) {
	out := renderWithDiff(t)
	for _, e := range out.Edges {
		if e.From != "frontend" || e.To != "api" {
			continue
		}
		if e.Class != string(graph.ClassOverpermissive) {
			t.Fatalf("class = %q; want overpermissive (9090 never used)", e.Class)
		}
		if e.Forwarded != 100 {
			t.Errorf("forwarded = %d; want 100", e.Forwarded)
		}
		if len(e.UnusedPorts) != 1 || e.UnusedPorts[0] != "TCP/9090" {
			t.Errorf("unusedPorts = %v; want [TCP/9090]", e.UnusedPorts)
		}
		if len(e.PolicyRefs) == 0 {
			t.Error("policyRefs empty; report cannot say which YAML to edit")
		}
		return
	}
	t.Fatal("frontend->api edge missing")
}

func TestRenderJSONWithoutDiffOmitsWindow(t *testing.T) {
	g := graph.NewGraph(testPolicies())
	data, err := RenderJSON(g.Edges, nil, g.Isolation, nil)
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var out jsonGraph
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Window != nil {
		t.Errorf("window = %+v; want nil without a diff", out.Window)
	}
	for _, e := range out.Edges {
		if e.Class != "" {
			t.Errorf("edge %s->%s has class %q without a diff", e.From, e.To, e.Class)
		}
	}
}
