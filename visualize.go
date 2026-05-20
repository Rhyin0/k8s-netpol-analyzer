package main

import (
	"fmt"
	"os"
	"strings"
)

func ExportDOT(edges []Edge, risks []NodeRisk, filename string) error {
	var sb strings.Builder
	sb.WriteString("digraph K8sNetworkPolicy {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=filled, fontname=\"Arial\"];\n")
	sb.WriteString("  edge [fontname=\"Arial\", fontsize=10];\n\n")

	// 节点风险等级着色
	riskMap := make(map[string]NodeRisk)
	for _, r := range risks {
		riskMap[r.Name] = r
	}

	// 节点分类
	categories := map[string][]string{
		"gateway":  {},
		"service":  {},
		"data":     {},
		"infra":    {},
		"monitor":  {},
		"isolated": {},
	}

	allNodes := make(map[string]bool)
	for _, e := range edges {
		allNodes[e.From] = true
		allNodes[e.To] = true
	}
	// 加上隔离节点
	for _, r := range risks {
		allNodes[r.Name] = true
	}

	for node := range allNodes {
		switch {
		case strings.Contains(node, "nginx") || strings.Contains(node, "gateway") || strings.Contains(node, "frontend"):
			categories["gateway"] = append(categories["gateway"], node)
		case strings.HasSuffix(node, "-db") || strings.Contains(node, "redis") || strings.Contains(node, "elasticsearch"):
			categories["data"] = append(categories["data"], node)
		case strings.Contains(node, "rabbitmq"):
			categories["infra"] = append(categories["infra"], node)
		case strings.Contains(node, "prometheus") || strings.Contains(node, "log-collector"):
			categories["monitor"] = append(categories["monitor"], node)
		case strings.Contains(node, "legacy") || strings.Contains(node, "debug"):
			categories["isolated"] = append(categories["isolated"], node)
		default:
			categories["service"] = append(categories["service"], node)
		}
	}

	// 子图分组
	clusterNames := map[string]string{
		"gateway":  "入口层",
		"service":  "业务服务层",
		"data":     "数据层",
		"infra":    "基础设施",
		"monitor":  "监控",
		"isolated": "隔离区",
	}
	clusterColors := map[string]string{
		"gateway":  "#E8F5E9",
		"service":  "#E3F2FD",
		"data":     "#FFF3E0",
		"infra":    "#F3E5F5",
		"monitor":  "#ECEFF1",
		"isolated": "#FFEBEE",
	}

	i := 0
	for cat, nodes := range categories {
		if len(nodes) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("  subgraph cluster_%d {\n", i))
		sb.WriteString(fmt.Sprintf("    label=\"%s\";\n", clusterNames[cat]))
		sb.WriteString("    style=filled;\n")
		sb.WriteString(fmt.Sprintf("    color=\"%s\";\n", clusterColors[cat]))
		for _, node := range nodes {
			color := nodeColor(riskMap[node])
			sb.WriteString(fmt.Sprintf("    \"%s\" [fillcolor=\"%s\"];\n", node, color))
		}
		sb.WriteString("  }\n\n")
		i++
	}

	// 边
	seen := make(map[string]bool)
	for _, e := range edges {
		key := fmt.Sprintf("%s->%s:%d", e.From, e.To, e.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"%d/%s\"];\n",
			e.From, e.To, e.Port, e.Protocol))
	}

	sb.WriteString("}\n")

	return os.WriteFile(filename, []byte(sb.String()), 0644)
}

func nodeColor(r NodeRisk) string {
	switch {
	case r.SpreadRatio > 70:
		return "#EF5350" // 红
	case r.SpreadRatio > 40:
		return "#FFA726" // 橙
	case r.SpreadRatio > 20:
		return "#FFEE58" // 黄
	case r.InDegree == 0 && r.OutDegree == 0:
		return "#BDBDBD" // 灰：隔离
	default:
		return "#66BB6A" // 绿
	}
}
