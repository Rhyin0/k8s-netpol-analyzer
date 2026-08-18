package hubble

import (
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

func testGraph() *graph.Graph {
	return graph.NewGraph([]graph.NetworkPolicy{
		{
			Metadata: graph.Metadata{Name: "api-ingress", Namespace: "shop"},
			Spec: graph.Spec{
				PodSelector: graph.PodSelector{MatchLabels: map[string]string{"app": "api"}},
				PolicyTypes: []string{"Ingress"},
				Ingress: []graph.IngressRule{{
					From: []graph.Peer{{
						PodSelector: graph.PodSelector{MatchLabels: map[string]string{"app": "frontend"}},
					}},
					Ports: []graph.PortRule{{Protocol: "TCP", Port: 8080}},
				}},
			},
		},
	})
}

func tcpFlow(src, dst *flowpb.Endpoint, port uint32) *flowpb.Flow {
	return &flowpb.Flow{
		Source:      src,
		Destination: dst,
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: port}},
		},
	}
}

func TestToEdgeKeyFromLabels(t *testing.T) {
	f := tcpFlow(
		&flowpb.Endpoint{
			PodName:   "frontend-7d4b8c-x9k2p",
			Namespace: "shop",
			Labels:    []string{"k8s:app=frontend", "k8s:pod-template-hash=7d4b8c"},
		},
		&flowpb.Endpoint{
			PodName:   "api-5f9c-qq11",
			Namespace: "shop",
			Labels:    []string{"k8s:app=api"},
		},
		8080,
	)

	got, ok := toEdgeKey(f, testGraph())
	want := flowstat.EdgeKey{Src: "frontend", Dst: "api", Port: 8080, Proto: "TCP"}
	if !ok || got != want {
		t.Fatalf("toEdgeKey = %+v, %v; want %+v, true", got, ok, want)
	}
}

// Some Hubble deployments emit flows without k8s label metadata.
func TestToEdgeKeyFallsBackToPodName(t *testing.T) {
	f := tcpFlow(
		&flowpb.Endpoint{PodName: "frontend-7d4b8c-x9k2p", Namespace: "shop"},
		&flowpb.Endpoint{PodName: "api-5f9c-qq11", Namespace: "shop"},
		8080,
	)

	got, ok := toEdgeKey(f, testGraph())
	if !ok || got.Src != "frontend" || got.Dst != "api" {
		t.Fatalf("toEdgeKey = %+v, %v; want frontend->api resolved by pod name", got, ok)
	}
}

func TestToEdgeKeyRejectsOffGraphTraffic(t *testing.T) {
	// reserved:world carries no k8s labels and no pod name.
	f := tcpFlow(
		&flowpb.Endpoint{Labels: []string{"reserved:world"}},
		&flowpb.Endpoint{PodName: "api-5f9c-qq11", Labels: []string{"k8s:app=api"}},
		8080,
	)
	if _, ok := toEdgeKey(f, testGraph()); ok {
		t.Fatal("cluster-external source should not resolve to a graph node")
	}

	// A workload no policy mentions.
	f = tcpFlow(
		&flowpb.Endpoint{PodName: "grafana-1", Labels: []string{"k8s:app=grafana"}},
		&flowpb.Endpoint{PodName: "api-5f9c-qq11", Labels: []string{"k8s:app=api"}},
		8080,
	)
	if _, ok := toEdgeKey(f, testGraph()); ok {
		t.Fatal("off-graph workload should not resolve")
	}
}

func TestToEdgeKeyRequiresL4(t *testing.T) {
	f := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Labels: []string{"k8s:app=frontend"}},
		Destination: &flowpb.Endpoint{Labels: []string{"k8s:app=api"}},
	}
	if _, ok := toEdgeKey(f, testGraph()); ok {
		t.Fatal("flow without L4 should not produce an edge key")
	}
}

func TestK8sLabelsStripsSourcePrefix(t *testing.T) {
	got := k8sLabels([]string{
		"k8s:app=api",
		"any:tier=backend",
		"reserved:host",
		"k8s:io.kubernetes.pod.namespace=shop",
	})
	want := map[string]string{
		"app":                         "api",
		"tier":                        "backend",
		"io.kubernetes.pod.namespace": "shop",
	}
	if len(got) != len(want) {
		t.Fatalf("k8sLabels = %v; want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("k8sLabels[%q] = %q; want %q", k, got[k], v)
		}
	}
}
