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

	// Populated only when a TopologyDiff is supplied. Class is the roll-up of
	// the per-port verdicts for this node pair; UnusedPorts names the ports
	// that made it over-permissive, so a partially used edge stays actionable.
	Class       string   `json:"class,omitempty"`
	Forwarded   int64    `json:"forwarded,omitempty"`
	Dropped     int64    `json:"dropped,omitempty"`
	PolicyRefs  []string `json:"policyRefs,omitempty"`
	UnusedPorts []string `json:"unusedPorts,omitempty"`
}

type jsonGraph struct {
	Nodes  []jsonNode               `json:"nodes"`
	Edges  []jsonEdge               `json:"edges"`
	Window *graph.ObservationWindow `json:"window,omitempty"`
}

// ExportJSON writes the static topology with no observation overlay.
func ExportJSON(edges []graph.Edge, risks []graph.NodeRisk,
	isolation map[string]*graph.PodIsolation,
	filename string) error {
	return ExportJSONWithDiff(edges, risks, isolation, nil, filename)
}

// ExportJSONWithDiff writes the topology annotated with observed traffic.
func ExportJSONWithDiff(edges []graph.Edge, risks []graph.NodeRisk,
	isolation map[string]*graph.PodIsolation, diff *graph.TopologyDiff,
	filename string) error {

	data, err := RenderJSON(edges, risks, isolation, diff)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// RenderJSON marshals the topology for callers that serve it over HTTP rather
// than writing a file.
func RenderJSON(edges []graph.Edge, risks []graph.NodeRisk,
	isolation map[string]*graph.PodIsolation,
	diff *graph.TopologyDiff) ([]byte, error) {
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
	overlay := rollUpDiff(diff)
	seen := make(map[[2]string]bool, len(edges))

	var jsonEdges []jsonEdge
	for _, e := range edges {
		var ports []string
		for _, p := range e.Ports {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
		}

		pair := [2]string{e.From, e.To}
		seen[pair] = true

		je := jsonEdge{
			From:           e.From,
			To:             e.To,
			Ports:          ports,
			IngressDefault: e.IngressDefault,
			EgressDefault:  e.EgressDefault,
			PolicyRefs:     e.PolicyRefs,
		}
		if o, ok := overlay[pair]; ok {
			je.Class = string(o.class)
			je.Forwarded = o.forwarded
			je.Dropped = o.dropped
			je.UnusedPorts = o.unusedPorts
		}
		jsonEdges = append(jsonEdges, je)
	}

	// Unexpected drops have no static edge by definition, so they must be
	// appended rather than annotated — filtering to known edges would drop the
	// entire class. Both endpoints resolved to graph nodes, so the node list
	// already covers them.
	for pair, o := range overlay {
		if seen[pair] || o.class != graph.ClassUnexpectedDrop {
			continue
		}
		jsonEdges = append(jsonEdges, jsonEdge{
			From:      pair[0],
			To:        pair[1],
			Ports:     o.observedPorts,
			Class:     string(graph.ClassUnexpectedDrop),
			Forwarded: o.forwarded,
			Dropped:   o.dropped,
		})
	}

	sort.Slice(jsonEdges, func(i, j int) bool {
		if jsonEdges[i].From != jsonEdges[j].From {
			return jsonEdges[i].From < jsonEdges[j].From
		}
		return jsonEdges[i].To < jsonEdges[j].To
	})

	g := jsonGraph{Nodes: nodes, Edges: jsonEdges}
	if diff != nil {
		w := diff.Window
		g.Window = &w
	}

	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("序列化失败: %w", err)
	}
	return data, nil
}

type edgeOverlay struct {
	class         graph.EdgeClass
	forwarded     int64
	dropped       int64
	unusedPorts   []string
	observedPorts []string
}

// rollUpDiff collapses the per-port diff onto node pairs, since the graph view
// draws one edge per pair.
//
// Over-permission wins the roll-up: an edge where one port is used and another
// is not is still an edge with a rule worth tightening, and that is the finding
// this tool exists to surface. UnusedPorts records which ports caused it.
func rollUpDiff(diff *graph.TopologyDiff) map[[2]string]*edgeOverlay {
	out := make(map[[2]string]*edgeOverlay)
	if diff == nil {
		return out
	}

	for _, e := range diff.Edges {
		pair := [2]string{e.Src, e.Dst}
		o, ok := out[pair]
		if !ok {
			o = &edgeOverlay{class: e.Class}
			out[pair] = o
		}
		o.forwarded += e.Forwarded
		o.dropped += e.Dropped

		switch e.Class {
		case graph.ClassOverpermissive:
			o.class = graph.ClassOverpermissive
			o.unusedPorts = append(o.unusedPorts, e.PortLabel())
		case graph.ClassConfirmed:
			if o.class != graph.ClassOverpermissive {
				o.class = graph.ClassConfirmed
			}
			o.observedPorts = append(o.observedPorts, e.PortLabel())
		case graph.ClassUnexpectedDrop:
			o.observedPorts = append(o.observedPorts, e.PortLabel())
		}
	}
	return out
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
