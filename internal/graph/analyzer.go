package graph

import (
	"fmt"
	"strings"
)

type SpreadResult struct {
	Source       string
	Reachable    []ReachableNode
	Unreachable  []string
	MaxDepth     int
	CriticalPath []string
}

type ReachableNode struct {
	Name      string
	Depth     int
	Via       string
	PortLabel string // human-readable port info on the edge used to reach this node
}

// BFS 传播模拟：从 source 出发，沿有向边扩散
func SimulateSpread(edges []Edge, source string) SpreadResult {
	adj := make(map[string][]Edge)
	allNodes := make(map[string]bool)
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e)
		allNodes[e.From] = true
		allNodes[e.To] = true
	}

	visited := make(map[string]bool)
	visited[source] = true
	parent := make(map[string]string)
	parentPortLabel := make(map[string]string)
	depth := make(map[string]int)
	depth[source] = 0
	queue := []string{source}
	var reachable []ReachableNode
	maxDepth := 0

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, e := range adj[current] {
			if !visited[e.To] {
				visited[e.To] = true
				depth[e.To] = depth[current] + 1
				parent[e.To] = current
				parentPortLabel[e.To] = PortsLabel(e.Ports)
				queue = append(queue, e.To)
				reachable = append(reachable, ReachableNode{
					Name:      e.To,
					Depth:     depth[e.To],
					Via:       current,
					PortLabel: PortsLabel(e.Ports),
				})
				if depth[e.To] > maxDepth {
					maxDepth = depth[e.To]
				}
			}
		}
	}

	var unreachable []string
	for node := range allNodes {
		if !visited[node] {
			unreachable = append(unreachable, node)
		}
	}

	var criticalPath []string
	for _, r := range reachable {
		if r.Depth == maxDepth {
			path := []string{r.Name}
			cur := r.Name
			for cur != source {
				cur = parent[cur]
				path = append([]string{cur}, path...)
			}
			if len(path) > len(criticalPath) {
				criticalPath = path
			}
		}
	}

	return SpreadResult{
		Source:       source,
		Reachable:    reachable,
		Unreachable:  unreachable,
		MaxDepth:     maxDepth,
		CriticalPath: criticalPath,
	}
}

func PrintSpreadResult(result SpreadResult) {
	fmt.Printf("\n=== 传播模拟: %s 被入侵 ===\n", result.Source)
	fmt.Printf("可感染节点: %d 个\n", len(result.Reachable))
	fmt.Printf("最大传播深度: %d 跳\n", result.MaxDepth)
	fmt.Printf("关键传播路径: %s\n", strings.Join(result.CriticalPath, " → "))

	fmt.Println("\n按跳数分层:")
	for d := 1; d <= result.MaxDepth; d++ {
		fmt.Printf("  第 %d 跳: ", d)
		var names []string
		for _, r := range result.Reachable {
			if r.Depth == d {
				names = append(names, fmt.Sprintf("%s (via %s [%s])", r.Name, r.Via, r.PortLabel))
			}
		}
		fmt.Println(strings.Join(names, ", "))
	}

	if len(result.Unreachable) > 0 {
		fmt.Printf("\n安全节点 (不可达): %s\n", strings.Join(result.Unreachable, ", "))
	}

	allNodes := len(result.Reachable) + len(result.Unreachable) + 1
	ratio := float64(len(result.Reachable)) / float64(allNodes-1) * 100
	fmt.Printf("\n感染率: %.1f%% (%d/%d)\n", ratio, len(result.Reachable), allNodes-1)
}
