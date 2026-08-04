package graph

import (
	"sort"
	"testing"
)

func TestNormalizePorts(t *testing.T) {
	t.Run("empty ports means all ports", func(t *testing.T) {
		result := normalizePorts(nil)
		if len(result) != 1 || !result[0].IsAllPorts() {
			t.Fatalf("expected [AllPorts], got %v", result)
		}

		result = normalizePorts([]PortRule{})
		if len(result) != 1 || !result[0].IsAllPorts() {
			t.Fatalf("expected [AllPorts] for empty slice, got %v", result)
		}
	})

	t.Run("explicit ports preserved", func(t *testing.T) {
		result := normalizePorts([]PortRule{
			{Protocol: "TCP", Port: 80},
			{Protocol: "TCP", Port: 443},
		})
		if len(result) != 2 {
			t.Fatalf("expected 2 ports, got %d", len(result))
		}
		if result[0].Port != 80 || result[1].Port != 443 {
			t.Fatalf("unexpected ports: %v", result)
		}
	})
}

func TestInferPolicyTypes(t *testing.T) {
	t.Run("explicit policyTypes", func(t *testing.T) {
		p := NetworkPolicy{Spec: Spec{PolicyTypes: []string{"Ingress", "Egress"}}}
		ing, egr := InferPolicyTypes(p)
		if !ing || !egr {
			t.Fatal("expected both true")
		}
	})

	t.Run("explicit egress only", func(t *testing.T) {
		p := NetworkPolicy{Spec: Spec{PolicyTypes: []string{"Egress"}}}
		ing, egr := InferPolicyTypes(p)
		if ing {
			t.Fatal("expected ingress false")
		}
		if !egr {
			t.Fatal("expected egress true")
		}
	})

	t.Run("omitted with egress rules", func(t *testing.T) {
		p := NetworkPolicy{Spec: Spec{
			Egress: []EgressRule{{To: []Peer{{}}}},
		}}
		ing, egr := InferPolicyTypes(p)
		if !ing {
			t.Fatal("expected ingress true (always implied)")
		}
		if !egr {
			t.Fatal("expected egress true (rules present)")
		}
	})

	t.Run("omitted without egress rules", func(t *testing.T) {
		p := NetworkPolicy{Spec: Spec{
			Ingress: []IngressRule{{From: []Peer{{}}}},
		}}
		ing, egr := InferPolicyTypes(p)
		if !ing {
			t.Fatal("expected ingress true")
		}
		if egr {
			t.Fatal("expected egress false (no egress rules)")
		}
	})
}

func TestComputeIsolation(t *testing.T) {
	policies := []NetworkPolicy{
		{
			Metadata: Metadata{Name: "p1"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []string{"Ingress"},
				Ingress:     []IngressRule{{From: []Peer{{}}}},
			},
		},
		{
			Metadata: Metadata{Name: "p2"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress", "Egress"},
			},
		},
	}

	allPods := []string{"web", "api", "db"}
	iso := ComputeIsolation(policies, allPods)

	// web: ingress isolated, egress NOT
	if !iso["web"].IngressIsolated {
		t.Fatal("web should be ingress-isolated")
	}
	if iso["web"].EgressIsolated {
		t.Fatal("web should NOT be egress-isolated")
	}

	// api: both isolated
	if !iso["api"].IngressIsolated || !iso["api"].EgressIsolated {
		t.Fatal("api should be isolated in both directions")
	}

	// db: not isolated at all (no policy selects it)
	if iso["db"].IngressIsolated || iso["db"].EgressIsolated {
		t.Fatal("db should NOT be isolated (no policy selects it)")
	}
}

func TestBuildEdges_DefaultAllow(t *testing.T) {
	// Pod "uncovered" has no policy selecting it → default allow in both directions
	// Pod "web" has ingress-only policy → ingress isolated, egress default-allow
	// Pod "api" has ingress+egress policy → both isolated
	policies := []NetworkPolicy{
		{
			Metadata: Metadata{Name: "web-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 80}},
					},
				},
			},
		},
		{
			Metadata: Metadata{Name: "api-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress", "Egress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "uncovered"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 8080}},
					},
				},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 80}},
					},
				},
			},
		},
	}

	edges, iso := BuildEdges(policies)

	// uncovered is not selected by any policy → both directions default allow
	if iso["uncovered"].IngressIsolated || iso["uncovered"].EgressIsolated {
		t.Fatal("uncovered should not be isolated")
	}

	// Check api → web edge exists (explicit egress + explicit ingress)
	found := findEdge(edges, "api", "web")
	if found == nil {
		t.Fatal("expected edge api → web")
	}
	if found.EgressDefault || found.IngressDefault {
		t.Fatal("api→web should have no default flags")
	}
	if len(found.Ports) != 1 || found.Ports[0].Port != 80 {
		t.Fatalf("expected port 80, got %v", found.Ports)
	}

	// Check uncovered → api edge (uncovered egress default + api ingress allows uncovered)
	found = findEdge(edges, "uncovered", "api")
	if found == nil {
		t.Fatal("expected edge uncovered → api")
	}
	if !found.EgressDefault {
		t.Fatal("uncovered→api should have EgressDefault=true")
	}

	// Check uncovered → web edge (uncovered egress default, web ingress does NOT allow uncovered)
	found = findEdge(edges, "uncovered", "web")
	if found != nil {
		t.Fatal("uncovered → web should NOT exist (web ingress doesn't allow uncovered)")
	}

	// Check web → uncovered (web egress default, uncovered ingress default → both default)
	found = findEdge(edges, "web", "uncovered")
	if found == nil {
		t.Fatal("expected edge web → uncovered (both sides default-allow)")
	}
	if !found.EgressDefault || !found.IngressDefault {
		t.Fatal("web→uncovered should have both default flags")
	}
}

func TestBuildEdges_DenyAll(t *testing.T) {
	policies := []NetworkPolicy{
		{
			Metadata: Metadata{Name: "deny-all"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "isolated"}},
				PolicyTypes: []string{"Ingress", "Egress"},
			},
		},
		{
			Metadata: Metadata{Name: "other-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "other"}},
				PolicyTypes: []string{"Ingress", "Egress"},
				Ingress: []IngressRule{
					{From: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "isolated"}}}}},
				},
				Egress: []EgressRule{
					{To: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "isolated"}}}}},
				},
			},
		},
	}

	edges, iso := BuildEdges(policies)

	if !iso["isolated"].IngressIsolated || !iso["isolated"].EgressIsolated {
		t.Fatal("isolated should be isolated in both directions")
	}

	// isolated → other: isolated has no egress rules allowing other → denied
	if findEdge(edges, "isolated", "other") != nil {
		t.Fatal("isolated → other should not exist")
	}

	// other → isolated: other egress allows isolated, but isolated ingress has no rules → denied
	if findEdge(edges, "other", "isolated") != nil {
		t.Fatal("other → isolated should not exist (isolated has no ingress rules)")
	}
}

func TestBuildEdges_EmptyPorts(t *testing.T) {
	// A rule with no ports field means all ports
	policies := []NetworkPolicy{
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "server"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						From: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "client"}}}},
						// no Ports → all ports
					},
				},
			},
		},
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []string{"Egress"},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "server"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 443}},
					},
				},
			},
		},
	}

	edges, _ := BuildEdges(policies)
	e := findEdge(edges, "client", "server")
	if e == nil {
		t.Fatal("expected edge client → server")
	}
	// Ingress allows all ports, egress allows TCP/443 → effective = TCP/443
	if len(e.Ports) != 1 || e.Ports[0].Port != 443 {
		t.Fatalf("expected TCP/443 after intersection, got %v", e.Ports)
	}
}

func TestBuildEdges_OpenFrom(t *testing.T) {
	// admin-panel style: ingress with no from → allows from all pods
	policies := []NetworkPolicy{
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "admin"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						// no From → all pods
						Ports: []PortRule{{Protocol: "TCP", Port: 9090}},
					},
				},
			},
		},
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "attacker"}},
				PolicyTypes: []string{"Egress"},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "admin"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 9090}},
					},
				},
			},
		},
	}

	edges, _ := BuildEdges(policies)
	e := findEdge(edges, "attacker", "admin")
	if e == nil {
		t.Fatal("expected edge attacker → admin (admin ingress allows from all)")
	}
	if len(e.Ports) != 1 || e.Ports[0].Port != 9090 {
		t.Fatalf("expected port 9090, got %v", e.Ports)
	}
}

func TestBuildEdges_BothSidesRequired(t *testing.T) {
	// prometheus has egress to web, but web's ingress doesn't allow prometheus
	policies := []NetworkPolicy{
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "prometheus"}},
				PolicyTypes: []string{"Egress"},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 9090}},
					},
				},
			},
		},
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "frontend"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 80}},
					},
				},
			},
		},
	}

	edges, _ := BuildEdges(policies)
	if findEdge(edges, "prometheus", "web") != nil {
		t.Fatal("prometheus → web should NOT exist (web ingress doesn't allow prometheus)")
	}
}

func TestBuildEdges_PortIntersection(t *testing.T) {
	policies := []NetworkPolicy{
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "client"}},
				PolicyTypes: []string{"Egress"},
				Egress: []EgressRule{
					{
						To: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "server"}}}},
						Ports: []PortRule{
							{Protocol: "TCP", Port: 80},
							{Protocol: "TCP", Port: 443},
							{Protocol: "TCP", Port: 8080},
						},
					},
				},
			},
		},
		{
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "server"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						From: []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "client"}}}},
						Ports: []PortRule{
							{Protocol: "TCP", Port: 80},
							{Protocol: "TCP", Port: 443},
						},
					},
				},
			},
		},
	}

	edges, _ := BuildEdges(policies)
	e := findEdge(edges, "client", "server")
	if e == nil {
		t.Fatal("expected edge client → server")
	}
	// Intersection: {80, 443, 8080} ∩ {80, 443} = {80, 443}
	if len(e.Ports) != 2 {
		t.Fatalf("expected 2 ports (intersection), got %d: %v", len(e.Ports), e.Ports)
	}
	portSet := make(map[int]bool)
	for _, p := range e.Ports {
		portSet[p.Port] = true
	}
	if !portSet[80] || !portSet[443] {
		t.Fatalf("expected ports 80 and 443, got %v", e.Ports)
	}
}

func TestFindDefaultAllowGaps(t *testing.T) {
	iso := map[string]*PodIsolation{
		"web":       {IngressIsolated: true, EgressIsolated: true},
		"db":        {IngressIsolated: true, EgressIsolated: false},
		"uncovered": {IngressIsolated: false, EgressIsolated: false},
	}

	gaps := FindDefaultAllowGaps(iso)

	var ingressGaps, egressGaps []string
	for _, g := range gaps {
		if g.Direction == "Ingress" {
			ingressGaps = append(ingressGaps, g.Pod)
		} else {
			egressGaps = append(egressGaps, g.Pod)
		}
	}

	sort.Strings(ingressGaps)
	sort.Strings(egressGaps)

	if len(ingressGaps) != 1 || ingressGaps[0] != "uncovered" {
		t.Fatalf("expected ingress gap for [uncovered], got %v", ingressGaps)
	}
	if len(egressGaps) != 2 {
		t.Fatalf("expected 2 egress gaps, got %v", egressGaps)
	}
}

func TestDedup_MergesPorts(t *testing.T) {
	edges := []Edge{
		{From: "a", To: "b", Ports: []PortRange{{Port: 80, Protocol: "TCP"}}},
		{From: "a", To: "b", Ports: []PortRange{{Port: 443, Protocol: "TCP"}}},
		{From: "a", To: "b", Ports: []PortRange{{Port: 80, Protocol: "TCP"}}}, // duplicate
	}

	result := Dedup(edges)
	if len(result) != 1 {
		t.Fatalf("expected 1 deduped edge, got %d", len(result))
	}
	if len(result[0].Ports) != 2 {
		t.Fatalf("expected 2 merged ports, got %d", len(result[0].Ports))
	}
}

func TestDedup_AllPortsAbsorbs(t *testing.T) {
	edges := []Edge{
		{From: "a", To: "b", Ports: []PortRange{{Port: 80, Protocol: "TCP"}}},
		{From: "a", To: "b", Ports: []PortRange{AllPorts}},
	}

	result := Dedup(edges)
	if len(result) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(result))
	}
	if len(result[0].Ports) != 1 || !result[0].Ports[0].IsAllPorts() {
		t.Fatal("AllPorts should absorb specific ports")
	}
}

func TestBuildEdges_RealPolicies(t *testing.T) {
	// Simplified version of the actual policies.yaml test data
	policies := []NetworkPolicy{
		// nginx-ingress: Egress only
		{
			Metadata: Metadata{Name: "nginx-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "nginx-ingress"}},
				PolicyTypes: []string{"Egress"},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web-frontend"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 3000}},
					},
				},
			},
		},
		// web-frontend: Ingress+Egress
		{
			Metadata: Metadata{Name: "web-frontend-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web-frontend"}},
				PolicyTypes: []string{"Ingress", "Egress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "nginx-ingress"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 3000}},
					},
				},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api-gateway"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 8080}},
					},
				},
			},
		},
		// api-gateway: Ingress+Egress
		{
			Metadata: Metadata{Name: "api-gateway-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api-gateway"}},
				PolicyTypes: []string{"Ingress", "Egress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "web-frontend"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 8080}},
					},
				},
				Egress: []EgressRule{
					{
						To:    []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "user-db"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
		// user-db: Ingress only (no egress policy → egress default-allow)
		{
			Metadata: Metadata{Name: "user-db-policy"},
			Spec: Spec{
				PodSelector: PodSelector{MatchLabels: map[string]string{"app": "user-db"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []IngressRule{
					{
						From:  []Peer{{PodSelector: PodSelector{MatchLabels: map[string]string{"app": "api-gateway"}}}},
						Ports: []PortRule{{Protocol: "TCP", Port: 5432}},
					},
				},
			},
		},
	}

	edges, iso := BuildEdges(policies)

	// nginx-ingress: no ingress policy → ingress default-allow (anyone can reach it)
	if iso["nginx-ingress"].IngressIsolated {
		t.Fatal("nginx-ingress should NOT be ingress-isolated (policyTypes=[Egress])")
	}
	if !iso["nginx-ingress"].EgressIsolated {
		t.Fatal("nginx-ingress should be egress-isolated")
	}

	// nginx-ingress → web-frontend: egress allows, ingress allows
	e := findEdge(edges, "nginx-ingress", "web-frontend")
	if e == nil {
		t.Fatal("expected edge nginx-ingress → web-frontend")
	}

	// web-frontend → api-gateway: both explicit
	e = findEdge(edges, "web-frontend", "api-gateway")
	if e == nil {
		t.Fatal("expected edge web-frontend → api-gateway")
	}

	// api-gateway → user-db: both explicit
	e = findEdge(edges, "api-gateway", "user-db")
	if e == nil {
		t.Fatal("expected edge api-gateway → user-db")
	}

	// user-db → nginx-ingress: user-db egress default-allow, nginx-ingress ingress default-allow
	e = findEdge(edges, "user-db", "nginx-ingress")
	if e == nil {
		t.Fatal("expected edge user-db → nginx-ingress (both sides default-allow)")
	}
	if !e.EgressDefault || !e.IngressDefault {
		t.Fatal("user-db→nginx-ingress should have both default flags")
	}

	// user-db → web-frontend: user-db egress default, web-frontend ingress allows only nginx-ingress
	e = findEdge(edges, "user-db", "web-frontend")
	if e != nil {
		t.Fatal("user-db → web-frontend should NOT exist (web-frontend ingress doesn't allow user-db)")
	}

	// user-db → api-gateway: user-db egress default, api-gateway ingress allows only web-frontend
	e = findEdge(edges, "user-db", "api-gateway")
	if e != nil {
		t.Fatal("user-db → api-gateway should NOT exist (api-gateway ingress doesn't allow user-db)")
	}
}

func findEdge(edges []Edge, from, to string) *Edge {
	for i := range edges {
		if edges[i].From == from && edges[i].To == to {
			return &edges[i]
		}
	}
	return nil
}
