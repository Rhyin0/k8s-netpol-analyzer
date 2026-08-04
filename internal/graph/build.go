package graph

import (
	"fmt"
	"sort"
)

func normalizePorts(ports []PortRule) []PortRange {
	if len(ports) == 0 {
		return []PortRange{AllPorts}
	}
	result := make([]PortRange, len(ports))
	for i, p := range ports {
		result[i] = PortRange{Port: p.Port, Protocol: p.Protocol}
	}
	return result
}

// InferPolicyTypes returns the effective policy types for a policy.
// When policyTypes is omitted: Ingress is always implied; Egress only if egress rules exist.
func InferPolicyTypes(p NetworkPolicy) (hasIngress, hasEgress bool) {
	if len(p.Spec.PolicyTypes) > 0 {
		for _, pt := range p.Spec.PolicyTypes {
			switch pt {
			case "Ingress":
				hasIngress = true
			case "Egress":
				hasEgress = true
			}
		}
		return
	}
	hasIngress = true
	hasEgress = len(p.Spec.Egress) > 0
	return
}

func selectorMatchesPod(sel PodSelector, pod string) bool {
	if len(sel.MatchLabels) == 0 {
		return true
	}
	return LabelStr(sel.MatchLabels) == pod
}

func peerMatchesPod(peers []Peer, pod string) bool {
	if len(peers) == 0 {
		return true
	}
	for _, peer := range peers {
		if selectorMatchesPod(peer.PodSelector, pod) {
			return true
		}
	}
	return false
}

// CollectAllPods returns every unique pod identifier mentioned in any policy.
func CollectAllPods(policies []NetworkPolicy) []string {
	seen := make(map[string]bool)
	for _, p := range policies {
		name := LabelStr(p.Spec.PodSelector.MatchLabels)
		if name != "" {
			seen[name] = true
		}
		for _, rule := range p.Spec.Ingress {
			for _, from := range rule.From {
				name := LabelStr(from.PodSelector.MatchLabels)
				if name != "" {
					seen[name] = true
				}
			}
		}
		for _, rule := range p.Spec.Egress {
			for _, to := range rule.To {
				name := LabelStr(to.PodSelector.MatchLabels)
				if name != "" {
					seen[name] = true
				}
			}
		}
	}
	pods := make([]string, 0, len(seen))
	for pod := range seen {
		pods = append(pods, pod)
	}
	sort.Strings(pods)
	return pods
}

// ComputeIsolation determines per-pod isolation state from all policies.
func ComputeIsolation(policies []NetworkPolicy, allPods []string) map[string]*PodIsolation {
	iso := make(map[string]*PodIsolation, len(allPods))
	for _, pod := range allPods {
		iso[pod] = &PodIsolation{}
	}

	for _, p := range policies {
		hasIngress, hasEgress := InferPolicyTypes(p)
		for _, pod := range allPods {
			if !selectorMatchesPod(p.Spec.PodSelector, pod) {
				continue
			}
			pi := iso[pod]
			if hasIngress {
				pi.IngressIsolated = true
			}
			if hasEgress {
				pi.EgressIsolated = true
			}
			pi.SelectedBy = append(pi.SelectedBy, p.Metadata.Name)
		}
	}

	return iso
}

// BuildEdges constructs the reachability graph from policies.
// An edge A→B exists iff:
//   - A's egress side permits traffic to B (not isolated, or explicit rule allows)
//   - AND B's ingress side permits traffic from A (same logic)
func BuildEdges(policies []NetworkPolicy) ([]Edge, map[string]*PodIsolation) {
	allPods := CollectAllPods(policies)
	iso := ComputeIsolation(policies, allPods)

	var edges []Edge
	for _, src := range allPods {
		for _, dst := range allPods {
			if src == dst {
				continue
			}
			if edge, ok := tryBuildEdge(src, dst, iso, policies); ok {
				edges = append(edges, edge)
			}
		}
	}

	return Dedup(edges), iso
}

func tryBuildEdge(src, dst string, iso map[string]*PodIsolation,
	policies []NetworkPolicy) (Edge, bool) {

	srcIso := iso[src]
	dstIso := iso[dst]

	egressDefault := !srcIso.EgressIsolated
	var egressPorts []PortRange
	if !egressDefault {
		var ok bool
		egressPorts, ok = checkEgressAllow(src, dst, policies)
		if !ok {
			return Edge{}, false
		}
	}

	ingressDefault := !dstIso.IngressIsolated
	var ingressPorts []PortRange
	if !ingressDefault {
		var ok bool
		ingressPorts, ok = checkIngressAllow(src, dst, policies)
		if !ok {
			return Edge{}, false
		}
	}

	ports := effectivePorts(egressDefault, egressPorts, ingressDefault, ingressPorts)
	if len(ports) == 0 {
		return Edge{}, false
	}

	return Edge{
		From:           src,
		To:             dst,
		Ports:          ports,
		EgressDefault:  egressDefault,
		IngressDefault: ingressDefault,
	}, true
}

func checkEgressAllow(src, dst string, policies []NetworkPolicy) ([]PortRange, bool) {
	var allowed []PortRange
	for _, p := range policies {
		if !selectorMatchesPod(p.Spec.PodSelector, src) {
			continue
		}
		_, hasEgress := InferPolicyTypes(p)
		if !hasEgress {
			continue
		}
		for _, rule := range p.Spec.Egress {
			if peerMatchesPod(rule.To, dst) {
				allowed = append(allowed, normalizePorts(rule.Ports)...)
			}
		}
	}
	if len(allowed) > 0 {
		return allowed, true
	}
	return nil, false
}

func checkIngressAllow(src, dst string, policies []NetworkPolicy) ([]PortRange, bool) {
	var allowed []PortRange
	for _, p := range policies {
		if !selectorMatchesPod(p.Spec.PodSelector, dst) {
			continue
		}
		hasIngress, _ := InferPolicyTypes(p)
		if !hasIngress {
			continue
		}
		for _, rule := range p.Spec.Ingress {
			if peerMatchesPod(rule.From, src) {
				allowed = append(allowed, normalizePorts(rule.Ports)...)
			}
		}
	}
	if len(allowed) > 0 {
		return allowed, true
	}
	return nil, false
}

func effectivePorts(egressDefault bool, egressPorts []PortRange,
	ingressDefault bool, ingressPorts []PortRange) []PortRange {
	if egressDefault && ingressDefault {
		return []PortRange{AllPorts}
	}
	if egressDefault {
		return ingressPorts
	}
	if ingressDefault {
		return egressPorts
	}
	return intersectPorts(egressPorts, ingressPorts)
}

func intersectPorts(a, b []PortRange) []PortRange {
	aHasAll := hasAllPorts(a)
	bHasAll := hasAllPorts(b)
	if aHasAll && bHasAll {
		return []PortRange{AllPorts}
	}
	if aHasAll {
		return b
	}
	if bHasAll {
		return a
	}
	bSet := make(map[PortRange]bool, len(b))
	for _, p := range b {
		bSet[p] = true
	}
	var result []PortRange
	for _, p := range a {
		if bSet[p] {
			result = append(result, p)
		}
	}
	return result
}

func hasAllPorts(ports []PortRange) bool {
	for _, p := range ports {
		if p.IsAllPorts() {
			return true
		}
	}
	return false
}

// FindDefaultAllowGaps returns pods lacking policy coverage in each direction.
func FindDefaultAllowGaps(isolation map[string]*PodIsolation) []DefaultAllowGap {
	var gaps []DefaultAllowGap
	for pod, iso := range isolation {
		if !iso.IngressIsolated {
			gaps = append(gaps, DefaultAllowGap{Pod: pod, Direction: "Ingress"})
		}
		if !iso.EgressIsolated {
			gaps = append(gaps, DefaultAllowGap{Pod: pod, Direction: "Egress"})
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].Direction != gaps[j].Direction {
			return gaps[i].Direction < gaps[j].Direction
		}
		return gaps[i].Pod < gaps[j].Pod
	})
	return gaps
}

// PrintDefaultAllowReport prints a summary of pods missing ingress policy coverage.
func PrintDefaultAllowReport(gaps []DefaultAllowGap) {
	fmt.Println("\n=== Default-Allow 缺口报告 ===")

	var ingressGaps, egressGaps []string
	for _, g := range gaps {
		if g.Direction == "Ingress" {
			ingressGaps = append(ingressGaps, g.Pod)
		} else {
			egressGaps = append(egressGaps, g.Pod)
		}
	}

	if len(ingressGaps) == 0 && len(egressGaps) == 0 {
		fmt.Println("  所有 Pod 均有完整的策略覆盖")
		return
	}

	if len(ingressGaps) > 0 {
		fmt.Printf("\n无 Ingress 策略覆盖（任何 Pod 都能访问）: %d 个\n", len(ingressGaps))
		for _, pod := range ingressGaps {
			fmt.Printf("  ⚠ %s\n", pod)
		}
	}

	if len(egressGaps) > 0 {
		fmt.Printf("\n无 Egress 策略覆盖（可访问任何 Pod）: %d 个\n", len(egressGaps))
		for _, pod := range egressGaps {
			fmt.Printf("  ⚠ %s\n", pod)
		}
	}
}
