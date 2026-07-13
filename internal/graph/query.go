package graph

import "fmt"

type QueryResult struct {
	Reachable   bool
	Path        []string // A → X → Y → B
	Ports       []int    // 每一跳用的端口
	BlockReason string   // 如果不可达，原因
}

func QueryReachability(edges []Edge, src, dst string) QueryResult {
	// 复用现有BFS
	result := SimulateSpread(edges, src)

	// 检查dst是否在可达列表里
	for _, r := range result.Reachable {
		if r.Name == dst {
			// 回溯路径
			path, ports := tracePath(result, src, dst)
			return QueryResult{
				Reachable: true,
				Path:      path,
				Ports:     ports,
			}
		}
	}

	// 不可达 → 找原因
	reason := findBlockReason(edges, result, src, dst)
	return QueryResult{
		Reachable:   false,
		BlockReason: reason,
	}
}

func tracePath(result SpreadResult, src, dst string) ([]string, []int) {
	// 从BFS结果里重建parent链
	parent := make(map[string]string)
	portUsed := make(map[string]int)
	parent[src] = ""
	for _, r := range result.Reachable {
		parent[r.Name] = r.Via
		portUsed[r.Name] = r.Port
	}

	// 回溯
	var path []string
	var ports []int
	cur := dst
	for cur != src {
		path = append([]string{cur}, path...)
		ports = append([]int{portUsed[cur]}, ports...)
		cur = parent[cur]
	}
	path = append([]string{src}, path...)
	return path, ports
}

func findBlockReason(edges []Edge, result SpreadResult, src, dst string) string {
	// 检查dst是否存在于图中
	exists := false
	for _, e := range edges {
		if e.From == dst || e.To == dst {
			exists = true
			break
		}
	}
	if !exists {
		return fmt.Sprintf("节点 %s 不存在于策略图中（无任何相关NetworkPolicy）", dst)
	}

	// dst存在但不可达 → 没有入站策略允许从src侧过来
	// 检查src能到哪里
	if len(result.Reachable) == 0 {
		return fmt.Sprintf("%s 没有任何出站边（被出站策略完全隔离或无Egress规则）", src)
	}

	return fmt.Sprintf("从 %s 到 %s 不存在策略允许的路径（缺少Ingress/Egress规则）", src, dst)
}
