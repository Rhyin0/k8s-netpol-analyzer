package hubble

import (
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
)

// toEdgeKey maps an observed flow onto an edge of the static policy graph.
//
// It reports false when either endpoint cannot be tied to a graph node —
// cluster-external traffic, host/reserved identities, or workloads no policy
// mentions. Those flows are still counted in the ring buffer; they just have no
// static edge to be compared against.
func toEdgeKey(f *flowpb.Flow, g *graph.Graph) (flowstat.EdgeKey, bool) {
	if f == nil || g == nil {
		return flowstat.EdgeKey{}, false
	}

	src, dst := f.GetSource(), f.GetDestination()
	if src == nil || dst == nil {
		return flowstat.EdgeKey{}, false
	}

	known := g.NodeIDs()
	srcID, ok := resolveEndpoint(src, known)
	if !ok {
		return flowstat.EdgeKey{}, false
	}
	dstID, ok := resolveEndpoint(dst, known)
	if !ok {
		return flowstat.EdgeKey{}, false
	}

	port, proto, ok := l4Info(f)
	if !ok {
		return flowstat.EdgeKey{}, false
	}

	return flowstat.EdgeKey{Src: srcID, Dst: dstID, Port: port, Proto: proto}, true
}

// resolveEndpoint turns a flow endpoint into a static graph node ID.
func resolveEndpoint(ep *flowpb.Endpoint, known []string) (string, bool) {
	if id, ok := graph.ResolveNodeID(k8sLabels(ep.GetLabels()), known); ok {
		return id, true
	}
	// Some Hubble deployments emit flows without k8s label metadata. A
	// Deployment names its pods "<workload>-<replicaset>-<suffix>", so fall
	// back to matching the longest node ID that prefixes the pod name.
	return matchPodName(ep.GetPodName(), known)
}

// k8sLabels parses Cilium's "<source>:<key>=<value>" label strings into a map.
// Source-less identity labels such as "reserved:host" carry no "=" and are
// dropped, which is what makes host and world traffic fail to resolve.
func k8sLabels(raw []string) map[string]string {
	out := make(map[string]string, len(raw))
	for _, l := range raw {
		if i := strings.Index(l, ":"); i >= 0 && !strings.Contains(l[:i], "=") {
			l = l[i+1:]
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			out[k] = v
		}
	}
	return out
}

func matchPodName(podName string, known []string) (string, bool) {
	if podName == "" {
		return "", false
	}
	best := ""
	for _, n := range known {
		if n != podName && !strings.HasPrefix(podName, n+"-") {
			continue
		}
		if len(n) > len(best) {
			best = n
		}
	}
	return best, best != ""
}

// l4Info extracts the destination port and transport protocol from a flow.
func l4Info(f *flowpb.Flow) (uint32, string, bool) {
	l4 := f.GetL4()
	if l4 == nil {
		return 0, "", false
	}
	if tcp := l4.GetTCP(); tcp != nil {
		return tcp.GetDestinationPort(), "TCP", true
	}
	if udp := l4.GetUDP(); udp != nil {
		return udp.GetDestinationPort(), "UDP", true
	}
	return 0, "", false
}
