package graph

import (
	"fmt"
	"sort"
)

// NodeRisk represents the risk assessment result for a node
type NodeRisk struct {
	Name            string
	OutDegree       int     // can directly reach how many nodes
	InDegree        int     // can be reached directly by how many nodes
	SpreadCount     int     // can infect how many nodes after being compromised
	SpreadRatio     float64 // infection rate
	MaxSpreadDepth  int     // maximum propagation depth
	IsCriticalPoint bool    // whether it is a critical point (removing it disconnects the graph)
}

// 分析所有节点的风险
func AnalyzeAllNodes(edges []Edge) []NodeRisk {
	// 收集所有节点
	allNodes := make(map[string]bool)
	outDeg := make(map[string]int)
	inDeg := make(map[string]int)
	// 去重计算度数
	outSeen := make(map[string]map[string]bool)
	inSeen := make(map[string]map[string]bool)

	for _, e := range edges {
		allNodes[e.From] = true
		allNodes[e.To] = true
		if outSeen[e.From] == nil {
			outSeen[e.From] = make(map[string]bool)
		}
		if !outSeen[e.From][e.To] { // 去重
			outSeen[e.From][e.To] = true
			outDeg[e.From]++
		}
		if inSeen[e.To] == nil {
			inSeen[e.To] = make(map[string]bool)
		}
		if !inSeen[e.To][e.From] {
			inSeen[e.To][e.From] = true
			inDeg[e.To]++
		}
	}

	totalNodes := len(allNodes)
	var risks []NodeRisk

	for node := range allNodes {
		// 传播模拟
		result := SimulateSpread(edges, node)
		ratio := 0.0
		if totalNodes > 1 {
			ratio = float64(len(result.Reachable)) / float64(totalNodes-1)
		}

		risks = append(risks, NodeRisk{
			Name:            node,
			OutDegree:       outDeg[node],
			InDegree:        inDeg[node],
			SpreadCount:     len(result.Reachable),
			SpreadRatio:     ratio,
			MaxSpreadDepth:  result.MaxDepth,
			IsCriticalPoint: isCriticalPoint(edges, allNodes, node),
		})
	}

	// 按感染率降序排列
	sort.Slice(risks, func(i, j int) bool {
		return risks[i].SpreadRatio > risks[j].SpreadRatio
	})

	return risks
}

// 判断是否为割点：删除该节点后，剩余可达节点数是否减少
func isCriticalPoint(edges []Edge, allNodes map[string]bool, target string) bool {
	// 构建删除 target 后的边集
	var reduced []Edge
	for _, e := range edges {
		if e.From != target && e.To != target {
			reduced = append(reduced, e)
		}
	}

	// 找剩余节点
	remaining := make([]string, 0)
	for n := range allNodes {
		if n != target {
			remaining = append(remaining, n)
		}
	}

	if len(remaining) == 0 {
		return false
	}

	// 构建无向邻接表（检测连通性）
	undirAdj := make(map[string][]string)
	for _, e := range reduced {
		undirAdj[e.From] = append(undirAdj[e.From], e.To)
		undirAdj[e.To] = append(undirAdj[e.To], e.From)
	}

	// BFS 检测连通分量数
	visited := make(map[string]bool)
	components := 0
	for _, n := range remaining {
		if !visited[n] {
			components++
			queue := []string{n}
			visited[n] = true
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, nb := range undirAdj[cur] {
					if !visited[nb] {
						visited[nb] = true
						queue = append(queue, nb)
					}
				}
			}
		}
	}

	// 删除前的连通分量数
	undirAdjFull := make(map[string][]string)
	for _, e := range edges {
		undirAdjFull[e.From] = append(undirAdjFull[e.From], e.To)
		undirAdjFull[e.To] = append(undirAdjFull[e.To], e.From)
	}
	visitedFull := make(map[string]bool)
	componentsFull := 0
	for n := range allNodes {
		if !visitedFull[n] {
			componentsFull++
			queue := []string{n}
			visitedFull[n] = true
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for _, nb := range undirAdjFull[cur] {
					if !visitedFull[nb] {
						visitedFull[nb] = true
						queue = append(queue, nb)
					}
				}
			}
		}
	}

	return components > componentsFull
}

// 打印风险报告
func PrintRiskReport(risks []NodeRisk) {
	fmt.Println("\n=== 节点风险评估报告 ===")
	fmt.Printf("总节点数: %d\n\n", len(risks))

	fmt.Printf("%-28s %6s %6s %8s %8s %6s %s\n",
		"节点", "入度", "出度", "感染数", "感染率", "深度", "割点")
	fmt.Println(repeatStr("-", 79))

	for _, r := range risks {
		critical := " "
		if r.IsCriticalPoint {
			critical = "YES"
		}
		fmt.Printf("%-28s %6d %6d %8d %7.1f%% %6d %s\n",
			r.Name, r.InDegree, r.OutDegree,
			r.SpreadCount, r.SpreadRatio, r.MaxSpreadDepth, critical)
	}

	// 高危节点
	fmt.Println("\n--- 高危节点 (感染率 > 30%) ---")
	for _, r := range risks {
		if r.SpreadRatio > 30 {
			fmt.Printf("  ⚠ %s: 入侵后可感染 %d 个节点 (%.1f%%)\n",
				r.Name, r.SpreadCount, r.SpreadRatio)
		}
	}

	// 割点
	fmt.Println("\n--- 割点 (删除后网络断裂) ---")
	hasCritical := false
	for _, r := range risks {
		if r.IsCriticalPoint {
			fmt.Printf("  ✂ %s: 入度=%d, 出度=%d\n",
				r.Name, r.InDegree, r.OutDegree)
			hasCritical = true
		}
	}
	if !hasCritical {
		fmt.Println("  无割点")
	}

	// 隔离节点
	fmt.Println("\n--- 隔离节点 (入度=0 且 出度=0) ---")
	for _, r := range risks {
		if r.InDegree == 0 && r.OutDegree == 0 {
			fmt.Printf("  🔒 %s\n", r.Name)
		}
	}
}

func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
