package graph

import "fmt"

type QueryResult struct {
	Reachable   bool
	Path        []string
	PortLabels  []string // port info at each hop
	BlockReason string
}

func QueryReachability(edges []Edge, src, dst string) QueryResult {
	result := SimulateSpread(edges, src)

	for _, r := range result.Reachable {
		if r.Name == dst {
			path, portLabels := tracePath(result, src, dst)
			return QueryResult{
				Reachable:  true,
				Path:       path,
				PortLabels: portLabels,
			}
		}
	}

	reason := findBlockReason(edges, result, src, dst)
	return QueryResult{
		Reachable:   false,
		BlockReason: reason,
	}
}

func tracePath(result SpreadResult, src, dst string) ([]string, []string) {
	parent := make(map[string]string)
	portLabel := make(map[string]string)
	parent[src] = ""
	for _, r := range result.Reachable {
		parent[r.Name] = r.Via
		portLabel[r.Name] = r.PortLabel
	}

	var path []string
	var labels []string
	cur := dst
	for cur != src {
		path = append([]string{cur}, path...)
		labels = append([]string{portLabel[cur]}, labels...)
		cur = parent[cur]
	}
	path = append([]string{src}, path...)
	return path, labels
}

func findBlockReason(edges []Edge, result SpreadResult, src, dst string) string {
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

	if len(result.Reachable) == 0 {
		return fmt.Sprintf("%s 没有任何出站边（被出站策略完全隔离或无Egress规则）", src)
	}

	return fmt.Sprintf("从 %s 到 %s 不存在策略允许的路径（缺少Ingress/Egress规则）", src, dst)
}
