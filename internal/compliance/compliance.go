package compliance

import (
	"fmt"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

type ComplianceIssue struct {
	Severity string // HIGH, MEDIUM, LOW
	Node     string
	Rule     string
	Detail   string
}

func CheckCompliance(policies []graph.NetworkPolicy, edges []graph.Edge, isolation map[string]*graph.PodIsolation) []ComplianceIssue {
	var issues []ComplianceIssue

	allNodes := make(map[string]bool)
	for _, e := range edges {
		allNodes[e.From] = true
		allNodes[e.To] = true
	}

	// 检查1: 数据库节点是否有出站规则
	for _, p := range policies {
		name := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		if isDBNode(name) && len(p.Spec.Egress) > 0 {
			var targets []string
			for _, rule := range p.Spec.Egress {
				for _, to := range rule.To {
					targets = append(targets, graph.LabelStr(to.PodSelector.MatchLabels))
				}
			}
			issues = append(issues, ComplianceIssue{
				Severity: "HIGH",
				Node:     name,
				Rule:     "DB_NO_EGRESS",
				Detail:   fmt.Sprintf("数据库节点不应有出站规则，当前出站目标: %s", strings.Join(targets, ", ")),
			})
		}
	}

	// 检查2: 入站规则过于宽松（没有指定 from）
	for _, p := range policies {
		name := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		for _, rule := range p.Spec.Ingress {
			if len(rule.From) == 0 && len(rule.Ports) > 0 {
				var ports []string
				for _, port := range rule.Ports {
					ports = append(ports, fmt.Sprintf("%s/%d", port.Protocol, port.Port))
				}
				issues = append(issues, ComplianceIssue{
					Severity: "HIGH",
					Node:     name,
					Rule:     "OPEN_INGRESS",
					Detail:   fmt.Sprintf("入站规则未限制来源，端口 %s 对所有 Pod 开放", strings.Join(ports, ", ")),
				})
			}
		}
	}

	// 检查3: 出站规则过于宽松（没有指定 to）
	for _, p := range policies {
		name := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		for _, rule := range p.Spec.Egress {
			if len(rule.To) == 0 && len(rule.Ports) > 0 {
				issues = append(issues, ComplianceIssue{
					Severity: "MEDIUM",
					Node:     name,
					Rule:     "OPEN_EGRESS",
					Detail:   "出站规则未限制目标，可访问任意 Pod",
				})
			}
		}
	}

	// 检查4: 高危节点缺少入站限制
	for _, p := range policies {
		name := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		result := graph.SimulateSpread(edges, name)
		totalNodes := len(allNodes)
		ratio := 0.0
		if totalNodes > 1 {
			ratio = float64(len(result.Reachable)) / float64(totalNodes-1) * 100
		}
		if ratio > 50 {
			inCount := 0
			for _, e := range edges {
				if e.To == name {
					inCount++
				}
			}
			if inCount > 3 {
				issues = append(issues, ComplianceIssue{
					Severity: "MEDIUM",
					Node:     name,
					Rule:     "HIGH_RISK_WIDE_ACCESS",
					Detail:   fmt.Sprintf("高危节点(感染率%.1f%%)有 %d 个入站来源，建议收紧访问控制", ratio, inCount),
				})
			}
		}
	}

	// 检查5: 只有 Ingress 策略没有 Egress 策略
	for _, p := range policies {
		name := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
		hasIngress := false
		hasEgress := false
		for _, pt := range p.Spec.PolicyTypes {
			if pt == "Ingress" {
				hasIngress = true
			}
			if pt == "Egress" {
				hasEgress = true
			}
		}
		if hasIngress && !hasEgress && !isDBNode(name) && !isCacheNode(name) && !isSearchEngine(name) {
			issues = append(issues, ComplianceIssue{
				Severity: "LOW",
				Node:     name,
				Rule:     "MISSING_EGRESS_POLICY",
				Detail:   "只定义了入站策略，缺少出站策略，该节点出站流量不受限制",
			})
		}
	}

	// 检查6: Default-Allow 缺口 — 无 Ingress 策略覆盖的 Pod
	if isolation != nil {
		gaps := graph.FindDefaultAllowGaps(isolation)
		for _, g := range gaps {
			if g.Direction == "Ingress" {
				issues = append(issues, ComplianceIssue{
					Severity: "HIGH",
					Node:     g.Pod,
					Rule:     "NO_INGRESS_POLICY",
					Detail:   "该 Pod 没有任何 Ingress 策略覆盖，任何 Pod 都可以访问它（default-allow）",
				})
			}
		}
	}

	// 按严重程度排序
	severityOrder := map[string]int{"HIGH": 0, "MEDIUM": 1, "LOW": 2}
	for i := 0; i < len(issues); i++ {
		for j := i + 1; j < len(issues); j++ {
			if severityOrder[issues[i].Severity] > severityOrder[issues[j].Severity] {
				issues[i], issues[j] = issues[j], issues[i]
			}
		}
	}

	return issues
}

func isDBNode(name string) bool {
	return strings.HasSuffix(name, "-db")
}

func isCacheNode(name string) bool {
	return strings.Contains(name, "redis") || strings.Contains(name, "cache") || strings.Contains(name, "memcached")
}

func isSearchEngine(name string) bool {
	return strings.Contains(name, "elasticsearch") || strings.Contains(name, "solr")
}

func PrintComplianceReport(issues []ComplianceIssue) {
	fmt.Println("\n=== 策略合规检查报告 ===")

	if len(issues) == 0 {
		fmt.Println("  未发现合规问题")
		return
	}

	fmt.Printf("发现 %d 个问题\n\n", len(issues))

	highCount := 0
	medCount := 0
	lowCount := 0

	for _, issue := range issues {
		var icon string
		switch issue.Severity {
		case "HIGH":
			icon = "!"
			highCount++
		case "MEDIUM":
			icon = "~"
			medCount++
		case "LOW":
			icon = "."
			lowCount++
		}
		fmt.Printf("%s [%s] %s\n", icon, issue.Severity, issue.Node)
		fmt.Printf("   规则: %s\n", issue.Rule)
		fmt.Printf("   详情: %s\n\n", issue.Detail)
	}

	fmt.Printf("汇总: HIGH=%d  MEDIUM=%d  LOW=%d\n", highCount, medCount, lowCount)
}
