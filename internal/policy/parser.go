package policy

import (
	"os"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"gopkg.in/yaml.v3"
)

// LoadFromFile 读取YAML文件，返回策略列表和边
func LoadFromFile(path string) ([]graph.NetworkPolicy, []graph.Edge, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
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

	// 构建边（从 cmd/analyzer/main.go 搬过来的逻辑）
	var edges []graph.Edge
	for _, p := range policies {
		target := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		for _, rule := range p.Spec.Ingress {
			for _, from := range rule.From {
				source := graph.LabelStr(from.PodSelector.MatchLabels)
				for _, port := range rule.Ports {
					edges = append(edges, graph.Edge{
						From:     source,
						To:       target,
						Port:     port.Port,
						Protocol: port.Protocol,
					})
				}
			}
		}
		for _, rule := range p.Spec.Egress {
			for _, to := range rule.To {
				dest := graph.LabelStr(to.PodSelector.MatchLabels)
				for _, port := range rule.Ports {
					edges = append(edges, graph.Edge{
						From:     target,
						To:       dest,
						Port:     port.Port,
						Protocol: port.Protocol,
					})
				}
			}
		}
	}
	edges = graph.Dedup(edges)

	return policies, edges, nil
}
