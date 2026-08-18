package policy

import (
	"os"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a YAML file and returns policies, edges, isolation, and pods state.
func LoadFromFile(path string) ([]graph.NetworkPolicy, []graph.Edge, map[string]*graph.PodIsolation, []string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var policies []graph.NetworkPolicy
	docs := strings.Split(string(data), "---")
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var p graph.NetworkPolicy
		if err := yaml.Unmarshal([]byte(doc), &p); err != nil {
			continue
		}
		policies = append(policies, p)
	}

	allPods := graph.CollectAllPods(policies)
	edges, isolation := graph.BuildEdges(policies)

	return policies, edges, isolation, allPods, nil
}

// LoadGraph reads a YAML file and returns the assembled reachability graph.
func LoadGraph(path string) (*graph.Graph, error) {
	policies, edges, isolation, _, err := LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	return &graph.Graph{Policies: policies, Edges: edges, Isolation: isolation}, nil
}
