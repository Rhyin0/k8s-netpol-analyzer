package visualise

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

type jsonNode struct {
	ID              string   `json:"id"`
	IngressState    string   `json:"ingressState"`
	EgressState     string   `json:"egressState"`
	SelectedBy      []string `json:"selectedBy,omitempty"`
	OutDegree       int      `json:"outDegree"`
	InDegree        int      `json:"inDegree"`
	SpreadCount     int      `json:"spreadCount"`
	SpreadRatio     float64  `json:"spreadRatio"`
	MaxSpreadDepth  int      `json:"maxSpreadDepth"`
	IsCriticalPoint bool     `json:"isCriticalPoint"`
}

type jsonEdge struct {
	From           string   `json:"from"`
	To             string   `json:"to"`
	Ports          []string `json:"ports"`
	IngressDefault bool     `json:"ingressDefault"`
	EgressDefault  bool     `json:"egressDefault"`
}

type jsonGraph struct {
	Nodes []jsonNode `json:"nodes"`
	Edges []jsonEdge `json:"edges"`
}

func ExportJSON(edges []graph.Edge, risks []graph.NodeRisk,
	isolation map[string]*graph.PodIsolation,
	filename string) error {
	// collect all nodes
	hasIngress := map[string]bool{}
	hasEgress := map[string]bool{}
	for _, e := range edges {
		hasEgress[e.From] = true
		hasIngress[e.To] = true
	}

	riskByName := map[string]graph.NodeRisk{}
	for _, r := range risks {
		riskByName[r.Name] = r
	}

	// build jsonGraph
	var nodes []jsonNode
	var missingRisk []string
	for name, isoData := range isolation {
		if isoData == nil {
			fmt.Fprintf(os.Stderr,
				"警告: 节点 %s 缺少隔离状态(ComputeIsolation 应覆盖所有 Pod),按未隔离处理\n", name)
			isoData = &graph.PodIsolation{} // using to promise we can continue appending jsonNode
		}

		r, ok := riskByName[name]
		if !ok {
			missingRisk = append(missingRisk, name)
			r = graph.NodeRisk{}
		}

		nodes = append(nodes, jsonNode{
			ID:              name,
			IngressState:    stateOf(isoData.IngressIsolated, hasIngress[name]),
			EgressState:     stateOf(isoData.EgressIsolated, hasEgress[name]),
			SelectedBy:      isoData.SelectedBy,
			OutDegree:       r.OutDegree,
			InDegree:        r.InDegree,
			SpreadCount:     r.SpreadCount,
			SpreadRatio:     r.SpreadRatio,
			MaxSpreadDepth:  r.MaxSpreadDepth,
			IsCriticalPoint: r.IsCriticalPoint,
		})

		sort.Slice(nodes, func(i, j int) bool {
			return nodes[i].ID < nodes[j].ID
		})
	}

	if len(missingRisk) > 0 {
		fmt.Fprintf(os.Stderr, "警告: %d 个节点缺少风险指标: %s\n",
			len(missingRisk), strings.Join(missingRisk, ", "))
	}

	// build edges
	var jsonEdges []jsonEdge
	for _, e := range edges {
		var ports []string
		for _, p := range e.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}

		jsonEdges = append(jsonEdges, jsonEdge{
			From:           e.From,
			To:             e.To,
			Ports:          ports,
			IngressDefault: e.IngressDefault,
			EgressDefault:  e.EgressDefault,
		})
	}

	// output file
	g := jsonGraph{Nodes: nodes, Edges: jsonEdges}

	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化失败: %w", err)
	}
	return os.WriteFile(filename, data, 0644)

}

func stateOf(isolated bool, hasEdge bool) string {
	if !isolated {
		return "default-allow"
	}
	if hasEdge {
		return "explicit"
	}
	return "implicit-deny"
}
