package policy

import (
	"os"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a YAML file and returns policies, edges, and isolation state.
func LoadFromFile(path string) ([]graph.NetworkPolicy, []graph.Edge, map[string]*graph.PodIsolation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
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

	edges, isolation := graph.BuildEdges(policies)

	return policies, edges, isolation, nil
}
