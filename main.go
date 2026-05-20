package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// NetworkPolicy YAML 结构定义
type NetworkPolicy struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

type Spec struct {
	PodSelector PodSelector   `yaml:"podSelector"`
	PolicyTypes []string      `yaml:"policyTypes"`
	Ingress     []IngressRule `yaml:"ingress"`
	Egress      []EgressRule  `yaml:"egress"`
}

type PodSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

type IngressRule struct {
	From  []Peer     `yaml:"from"`
	Ports []PortRule `yaml:"ports"`
}

type EgressRule struct {
	To    []Peer     `yaml:"to"`
	Ports []PortRule `yaml:"ports"`
}

type Peer struct {
	PodSelector PodSelector `yaml:"podSelector"`
}

type PortRule struct {
	Protocol string `yaml:"protocol"`
	Port     int    `yaml:"port"`
}

// 有向图：表示 Pod 之间的可达性
type Edge struct {
	From     string
	To       string
	Port     int
	Protocol string
}

func main() {
	// 读取 YAML 文件
	data, err := os.ReadFile("testdata/policies.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取文件失败: %v\n", err)
		os.Exit(1)
	}

	// 按 --- 分割多个文档
	docs := strings.Split(string(data), "---")
	var policies []NetworkPolicy

	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}
		var policy NetworkPolicy
		if err := yaml.Unmarshal([]byte(doc), &policy); err != nil {
			fmt.Fprintf(os.Stderr, "解析YAML失败: %v\n", err)
			continue
		}
		policies = append(policies, policy)
	}

	fmt.Printf("解析到 %d 条 NetworkPolicy\n\n", len(policies))

	// 构建可达性边
	var edges []Edge

	for _, p := range policies {
		target := labelStr(p.Spec.PodSelector.MatchLabels)

		// 从 ingress 规则提取：谁能访问我
		for _, rule := range p.Spec.Ingress {
			for _, from := range rule.From {
				source := labelStr(from.PodSelector.MatchLabels)
				for _, port := range rule.Ports {
					edges = append(edges, Edge{
						From:     source,
						To:       target,
						Port:     port.Port,
						Protocol: port.Protocol,
					})
				}
			}
		}

		// 从 egress 规则提取：我能访问谁
		for _, rule := range p.Spec.Egress {
			for _, to := range rule.To {
				dest := labelStr(to.PodSelector.MatchLabels)
				for _, port := range rule.Ports {
					edges = append(edges, Edge{
						From:     target,
						To:       dest,
						Port:     port.Port,
						Protocol: port.Protocol,
					})
				}
			}
		}
	}

	// 去重
	edges = dedup(edges)

	// 输出可达性图
	fmt.Println("=== 可达性图 (有向边) ===")
	for _, e := range edges {
		fmt.Printf("  %s --> %s  [%s/%d]\n", e.From, e.To, e.Protocol, e.Port)
	}

	// 输出邻接表
	fmt.Println("\n=== 邻接表 ===")
	adj := make(map[string][]string)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], fmt.Sprintf("%s:%d", e.To, e.Port))
	}
	for node, neighbors := range adj {
		fmt.Printf("  %s -> %v\n", node, neighbors)
	}

	// 全节点风险分析
	fmt.Println("\n" + strings.Repeat("=", 50))
	risks := AnalyzeAllNodes(edges)
	PrintRiskReport(risks)

	// 策略合规检查
	fmt.Println("\n" + strings.Repeat("=", 50))
	issues := CheckCompliance(policies, edges)
	PrintComplianceReport(issues)

	// 拓扑指标分析
	fmt.Println("\n" + strings.Repeat("=", 50))
	metrics := ComputeTopology(edges)
	PrintTopologyReport(metrics)

	// 导出可视化
	dotFile := "network-topology.dot"
	if err := ExportDOT(edges, risks, dotFile); err != nil {
		fmt.Fprintf(os.Stderr, "导出DOT失败: %v\n", err)
	} else {
		fmt.Printf("\n拓扑图已导出到 %s\n", dotFile)
		fmt.Println("用 Graphviz 渲染: dot -Tpng network-topology.dot -o topology.png")
	}

	// 模拟不同入侵点
	testSources := []string{"api-gateway", "order-service", "redis-cache", "legacy-app"}
	for _, src := range testSources {
		result := SimulateSpread(edges, src)
		PrintSpreadResult(result)
		fmt.Println(strings.Repeat("-", 50))
	}
}

func labelStr(labels map[string]string) string {
	if app, ok := labels["app"]; ok {
		return app
	}
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, ",")
}

func dedup(edges []Edge) []Edge {
	seen := make(map[string]bool)
	var result []Edge
	for _, e := range edges {
		key := fmt.Sprintf("%s->%s:%s/%d", e.From, e.To, e.Protocol, e.Port)
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}
