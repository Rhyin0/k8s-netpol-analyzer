package graph

// how to analysis .yaml files and build edges + graphs

import (
	"fmt"
	"slices"
	"sort"
	"strings"
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

// PortRange is the normalized internal representation of a port+protocol pair.
// AllPorts is the sentinel for "all ports, all protocols".
type PortRange struct {
	Port     int
	Protocol string
}

var AllPorts = PortRange{Port: 0, Protocol: ""}

func (p PortRange) IsAllPorts() bool {
	return p.Port == 0 && p.Protocol == ""
}

// Graph bundles the parsed policies with everything BuildEdges derives from
// them. The package previously passed edges and the isolation map around as
// separate values; analyses that need both (diffing static reachability against
// observed traffic) take a *Graph instead.
type Graph struct {
	Policies  []NetworkPolicy
	Edges     []Edge
	Isolation map[string]*PodIsolation
}

// NewGraph builds the reachability graph for a policy set.
func NewGraph(policies []NetworkPolicy) *Graph {
	edges, isolation := BuildEdges(policies)
	return &Graph{Policies: policies, Edges: edges, Isolation: isolation}
}

// PodIsolation tracks whether a pod is isolated in each direction by at least one policy.
type PodIsolation struct {
	IngressIsolated bool
	EgressIsolated  bool
	SelectedBy      []string
}

// Edge represents a permitted connectivity path between two pods.
// "Has edge" = traffic can flow. No edge = denied or pods don't exist.
type Edge struct {
	From           string
	To             string
	Ports          []PortRange
	EgressDefault  bool // src has no egress policy coverage → default allow
	IngressDefault bool // dst has no ingress policy coverage → default allow

	// PolicyRefs lists the policies that permit this edge, as "namespace/name".
	// Once a report says an edge is unused, the next question is which YAML to
	// edit — without provenance the finding is not actionable. A default-allow
	// side contributes no ref, since nothing was written to permit it.
	PolicyRefs []string
}

// PolicyRef renders a policy's identity as "namespace/name".
func PolicyRef(p NetworkPolicy) string {
	ns := p.Metadata.Namespace
	if ns == "" {
		ns = "default"
	}
	return ns + "/" + p.Metadata.Name
}

func mergeRefs(dst []string, src ...string) []string {
	for _, s := range src {
		if s == "" {
			continue
		}
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	sort.Strings(dst)
	return dst
}

// PortsLabel returns a human-readable label for the edge's ports.
func PortsLabel(ports []PortRange) string {
	if len(ports) == 0 || (len(ports) == 1 && ports[0].IsAllPorts()) {
		return "*/*"
	}
	seen := make(map[string]bool)
	var parts []string
	for _, p := range ports {
		s := fmt.Sprintf("%s/%d", p.Protocol, p.Port)
		if !seen[s] {
			seen[s] = true
			parts = append(parts, s)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// DefaultAllowGap represents a pod missing policy coverage in a direction.
type DefaultAllowGap struct {
	Pod       string
	Direction string // "Ingress" or "Egress"
}
