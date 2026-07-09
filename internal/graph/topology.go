package graph

import (
	"fmt"
	"math"
)

type TopologyMetrics struct {
	NodeCount       int
	EdgeCount       int
	Density         float64 // 图密度
	AvgPathLength   float64 // 平均最短路径长度
	Diameter        int     // 图直径（最长最短路径）
	AvgClusterCoeff float64 // 平均聚类系数
	Components      int     // 连通分量数（无向）
	Reciprocity     float64 // 互惠性：双向边占比
	AvgInDegree     float64
	AvgOutDegree    float64
	MaxInDegree     int
	MaxInNode       string
	MaxOutDegree    int
	MaxOutNode      string
}

func ComputeTopology(edges []Edge) TopologyMetrics {
	// 收集节点，构建邻接表（去重）
	allNodes := make(map[string]bool)
	adjOut := make(map[string]map[string]bool) // 有向：出边
	adjUn := make(map[string]map[string]bool)  // 无向：双向

	for _, e := range edges {
		allNodes[e.From] = true
		allNodes[e.To] = true
		if adjOut[e.From] == nil {
			adjOut[e.From] = make(map[string]bool)
		}
		adjOut[e.From][e.To] = true
		// 无向
		if adjUn[e.From] == nil {
			adjUn[e.From] = make(map[string]bool)
		}
		if adjUn[e.To] == nil {
			adjUn[e.To] = make(map[string]bool)
		}
		adjUn[e.From][e.To] = true
		adjUn[e.To][e.From] = true
	}

	nodes := make([]string, 0, len(allNodes))
	for n := range allNodes {
		nodes = append(nodes, n)
	}

	n := len(nodes)
	uniqueEdges := 0
	for _, targets := range adjOut {
		uniqueEdges += len(targets)
	}

	// 图密度
	density := 0.0
	if n > 1 {
		density = float64(uniqueEdges) / float64(n*(n-1))
	}

	// 度数统计
	inDeg := make(map[string]int)
	outDeg := make(map[string]int)
	for from, targets := range adjOut {
		outDeg[from] = len(targets)
		for to := range targets {
			inDeg[to]++
		}
	}

	totalIn := 0
	totalOut := 0
	maxIn := 0
	maxInNode := ""
	maxOut := 0
	maxOutNode := ""
	for _, node := range nodes {
		totalIn += inDeg[node]
		totalOut += outDeg[node]
		if inDeg[node] > maxIn {
			maxIn = inDeg[node]
			maxInNode = node
		}
		if outDeg[node] > maxOut {
			maxOut = outDeg[node]
			maxOutNode = node
		}
	}

	// BFS 最短路径（有向图）
	dist := make(map[string]map[string]int)
	for _, src := range nodes {
		dist[src] = bfsDistances(adjOut, src, nodes)
	}

	// 平均路径长度和直径
	totalPath := 0
	pathCount := 0
	diameter := 0
	for _, src := range nodes {
		for _, dst := range nodes {
			if src != dst {
				d := dist[src][dst]
				if d > 0 && d < math.MaxInt32 {
					totalPath += d
					pathCount++
					if d > diameter {
						diameter = d
					}
				}
			}
		}
	}
	avgPath := 0.0
	if pathCount > 0 {
		avgPath = float64(totalPath) / float64(pathCount)
	}

	// 聚类系数（基于无向图）
	totalCC := 0.0
	ccCount := 0
	for _, node := range nodes {
		neighbors := adjUn[node]
		k := len(neighbors)
		if k < 2 {
			continue
		}
		// 数邻居之间的连接数
		links := 0
		nbList := make([]string, 0, k)
		for nb := range neighbors {
			nbList = append(nbList, nb)
		}
		for i := 0; i < len(nbList); i++ {
			for j := i + 1; j < len(nbList); j++ {
				if adjUn[nbList[i]][nbList[j]] {
					links++
				}
			}
		}
		cc := 2.0 * float64(links) / float64(k*(k-1))
		totalCC += cc
		ccCount++
	}
	avgCC := 0.0
	if ccCount > 0 {
		avgCC = totalCC / float64(ccCount)
	}

	// 互惠性
	reciprocalCount := 0
	for from, targets := range adjOut {
		for to := range targets {
			if adjOut[to] != nil && adjOut[to][from] {
				reciprocalCount++
			}
		}
	}
	reciprocity := 0.0
	if uniqueEdges > 0 {
		reciprocity = float64(reciprocalCount) / float64(uniqueEdges)
	}

	// 连通分量（无向）
	visited := make(map[string]bool)
	components := 0
	for _, node := range nodes {
		if !visited[node] {
			components++
			queue := []string{node}
			visited[node] = true
			for len(queue) > 0 {
				cur := queue[0]
				queue = queue[1:]
				for nb := range adjUn[cur] {
					if !visited[nb] {
						visited[nb] = true
						queue = append(queue, nb)
					}
				}
			}
		}
	}

	return TopologyMetrics{
		NodeCount:       n,
		EdgeCount:       uniqueEdges,
		Density:         density,
		AvgPathLength:   avgPath,
		Diameter:        diameter,
		AvgClusterCoeff: avgCC,
		Components:      components,
		Reciprocity:     reciprocity,
		AvgInDegree:     float64(totalIn) / float64(n),
		AvgOutDegree:    float64(totalOut) / float64(n),
		MaxInDegree:     maxIn,
		MaxInNode:       maxInNode,
		MaxOutDegree:    maxOut,
		MaxOutNode:      maxOutNode,
	}
}

func bfsDistances(adj map[string]map[string]bool, src string, allNodes []string) map[string]int {
	dist := make(map[string]int)
	for _, n := range allNodes {
		dist[n] = math.MaxInt32
	}
	dist[src] = 0
	queue := []string{src}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for nb := range adj[cur] {
			if dist[nb] == math.MaxInt32 {
				dist[nb] = dist[cur] + 1
				queue = append(queue, nb)
			}
		}
	}
	return dist
}

func PrintTopologyReport(m TopologyMetrics) {
	fmt.Println("\n=== 拓扑指标分析 ===")
	fmt.Printf("节点数:           %d\n", m.NodeCount)
	fmt.Printf("有向边数:         %d\n", m.EdgeCount)
	fmt.Printf("连通分量:         %d\n", m.Components)
	fmt.Printf("图密度:           %.4f\n", m.Density)
	fmt.Printf("互惠性:           %.4f (%.1f%% 的边是双向的)\n", m.Reciprocity, m.Reciprocity*100)
	fmt.Printf("平均最短路径:     %.2f 跳\n", m.AvgPathLength)
	fmt.Printf("图直径:           %d 跳\n", m.Diameter)
	fmt.Printf("平均聚类系数:     %.4f\n", m.AvgClusterCoeff)
	fmt.Printf("平均入度:         %.2f\n", m.AvgInDegree)
	fmt.Printf("平均出度:         %.2f\n", m.AvgOutDegree)
	fmt.Printf("最大入度:         %d (%s)\n", m.MaxInDegree, m.MaxInNode)
	fmt.Printf("最大出度:         %d (%s)\n", m.MaxOutDegree, m.MaxOutNode)

	// 解读
	fmt.Println("\n--- 安全解读 ---")
	if m.Density > 0.3 {
		fmt.Println("  ⚠ 图密度较高，网络策略过于宽松，Pod间连接过多")
	} else if m.Density < 0.05 {
		fmt.Println("  ✅ 图密度低，网络隔离较好")
	} else {
		fmt.Println("  ℹ 图密度适中")
	}

	if m.AvgPathLength > 0 && m.AvgPathLength < 2.5 {
		fmt.Println("  ⚠ 平均路径短，攻击传播速度快")
	} else if m.AvgPathLength >= 2.5 {
		fmt.Println("  ✅ 平均路径较长，有一定纵深防御")
	}

	if m.AvgClusterCoeff > 0.5 {
		fmt.Println("  ⚠ 聚类系数高，存在密集互联的子群，局部入侵易扩散")
	} else {
		fmt.Println("  ✅ 聚类系数较低，Pod间关系较分散")
	}

	if m.Components > 1 {
		fmt.Printf("  ✅ 网络分为 %d 个独立区域，天然隔离\n", m.Components)
	}

	if m.Reciprocity > 0.3 {
		fmt.Printf("  ⚠ 互惠性 %.1f%%，大量双向连接增加了攻击面\n", m.Reciprocity*100)
	}
}
