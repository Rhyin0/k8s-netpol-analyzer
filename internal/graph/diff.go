package graph

import (
	"sort"
	"strconv"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
)

// EdgeClass is the verdict for one (src, dst, port, proto) tuple after
// comparing statically permitted reachability against observed traffic.
type EdgeClass string

const (
	ClassConfirmed      EdgeClass = "confirmed"       // allow + 有转发
	ClassOverpermissive EdgeClass = "overpermissive"  // allow + 窗口内无观测
	ClassUnexpectedDrop EdgeClass = "unexpected_drop" // 静态图无此边 + 有 DROPPED
)

type DiffEdge struct {
	Src        string    `json:"src"`
	Dst        string    `json:"dst"`
	Port       uint32    `json:"port"`
	Proto      string    `json:"proto"`
	Class      EdgeClass `json:"class"`
	Forwarded  int64     `json:"forwarded"`
	Dropped    int64     `json:"dropped"`
	PolicyRefs []string  `json:"policyRefs"`
}

// ObservationWindow describes how long traffic was watched for.
type ObservationWindow struct {
	Start           time.Time `json:"start"`
	DurationSeconds int64     `json:"durationSeconds"`
	// Sufficient reports whether the window reached the caller's minimum. A
	// short window cannot distinguish "never used" from "not used yet", so
	// over-permission findings below the threshold are not trustworthy and
	// every consumer must surface this.
	Sufficient bool `json:"sufficient"`
}

type TopologyDiff struct {
	Window ObservationWindow `json:"window"`
	Edges  []DiffEdge        `json:"edges"`
}

// CompareTopologies diffs statically permitted edges against observed traffic.
//
// Comparison is per port, not per node pair: a policy opening 1-8080 where only
// 8080 is ever used is the canonical over-permission, and matching on the node
// pair alone would report it as fully confirmed.
func CompareTopologies(g *Graph, observed map[flowstat.EdgeKey]flowstat.EdgeStat,
	start time.Time, minWindow time.Duration) TopologyDiff {

	duration := time.Since(start)
	diff := TopologyDiff{
		Window: ObservationWindow{
			Start:           start,
			DurationSeconds: int64(duration.Seconds()),
			Sufficient:      duration >= minWindow,
		},
	}
	if g == nil {
		return diff
	}

	// Index observations by node pair so a wildcard static edge can find every
	// port actually used between those two nodes.
	byPair := make(map[[2]string][]flowstat.EdgeKey)
	for k := range observed {
		pair := [2]string{k.Src, k.Dst}
		byPair[pair] = append(byPair[pair], k)
	}

	matched := make(map[flowstat.EdgeKey]bool)

	for _, e := range g.Edges {
		for _, key := range expandEdge(e, byPair) {
			stat, seen := observed[key]
			if seen {
				matched[key] = true
			}

			// A wildcard edge expands to the ports observed on it; those are
			// confirmed. It also yields one "*" entry standing for the rest of
			// the range, which stays over-permissive.
			class := ClassOverpermissive
			if stat.Forwarded > 0 {
				class = ClassConfirmed
			}

			diff.Edges = append(diff.Edges, DiffEdge{
				Src:        e.From,
				Dst:        e.To,
				Port:       key.Port,
				Proto:      key.Proto,
				Class:      class,
				Forwarded:  stat.Forwarded,
				Dropped:    stat.Dropped,
				PolicyRefs: e.PolicyRefs,
			})
		}
	}

	// Traffic that was dropped on a path the static graph does not permit.
	// Either the policy is too tight for what the workloads actually do, or
	// something is probing a path it should not.
	for key, stat := range observed {
		if matched[key] || stat.Dropped == 0 {
			continue
		}
		diff.Edges = append(diff.Edges, DiffEdge{
			Src:       key.Src,
			Dst:       key.Dst,
			Port:      key.Port,
			Proto:     key.Proto,
			Class:     ClassUnexpectedDrop,
			Forwarded: stat.Forwarded,
			Dropped:   stat.Dropped,
		})
	}

	sortDiffEdges(diff.Edges)
	return diff
}

// expandEdge lists the observation keys a static edge should be checked
// against. A concrete port yields exactly one key. A wildcard edge yields one
// key per port seen between the pair, plus a "*" placeholder representing the
// remainder of the permitted range that carried no traffic.
func expandEdge(e Edge, byPair map[[2]string][]flowstat.EdgeKey) []flowstat.EdgeKey {
	if !hasAllPorts(e.Ports) {
		keys := make([]flowstat.EdgeKey, 0, len(e.Ports))
		seen := make(map[flowstat.EdgeKey]bool, len(e.Ports))
		for _, p := range e.Ports {
			proto := p.Protocol
			if proto == "" {
				proto = "TCP"
			}
			k := flowstat.EdgeKey{Src: e.From, Dst: e.To, Port: uint32(p.Port), Proto: proto}
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		}
		return keys
	}

	observedOnPair := byPair[[2]string{e.From, e.To}]
	keys := make([]flowstat.EdgeKey, 0, len(observedOnPair)+1)
	keys = append(keys, observedOnPair...)
	// Port 0 / proto "*" is the sentinel for "the rest of the permitted range".
	// It never matches a real observation, so it always classifies as
	// over-permissive — which is exactly right for an unbounded allow rule.
	keys = append(keys, flowstat.EdgeKey{Src: e.From, Dst: e.To, Port: 0, Proto: "*"})
	return keys
}

func sortDiffEdges(edges []DiffEdge) {
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Src != b.Src {
			return a.Src < b.Src
		}
		if a.Dst != b.Dst {
			return a.Dst < b.Dst
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.Port < b.Port
	})
}

// ByClass groups the diff's edges by verdict.
func (d TopologyDiff) ByClass(c EdgeClass) []DiffEdge {
	var out []DiffEdge
	for _, e := range d.Edges {
		if e.Class == c {
			out = append(out, e)
		}
	}
	return out
}

// PortLabel renders a diff edge's port, expanding the wildcard sentinel.
func (e DiffEdge) PortLabel() string {
	if e.Proto == "*" {
		return "*/*"
	}
	return e.Proto + "/" + strconv.FormatUint(uint64(e.Port), 10)
}
