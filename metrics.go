package main

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics 定义所有 Prometheus 指标
type Metrics struct {
	flowTotal       *prometheus.CounterVec
	podConnectionsIn  *prometheus.GaugeVec
	podConnectionsOut *prometheus.GaugeVec
	spreadReachable   *prometheus.GaugeVec
	spreadMaxDepth    *prometheus.GaugeVec
	spreadInfection   *prometheus.GaugeVec
	overpermissionEdges prometheus.Gauge
	droppedAttempts     prometheus.Gauge

	collector *FlowCollector
}

func NewMetrics(collector *FlowCollector) *Metrics {
	m := &Metrics{
		flowTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "netpol_flow_total",
				Help: "每对 Pod 之间的流量总数",
			},
			[]string{"src", "dst", "port", "verdict"},
		),
		podConnectionsIn: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netpol_pod_connections_in",
				Help: "每个 Pod 的入连接数",
			},
			[]string{"pod"},
		),
		podConnectionsOut: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netpol_pod_connections_out",
				Help: "每个 Pod 的出连接数",
			},
			[]string{"pod"},
		),
		spreadReachable: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netpol_spread_reachable",
				Help: "从某入侵点出发可感染的节点数",
			},
			[]string{"source"},
		),
		spreadMaxDepth: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netpol_spread_max_depth",
				Help: "从某入侵点出发的最大传播深度",
			},
			[]string{"source"},
		),
		spreadInfection: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "netpol_spread_infection_rate",
				Help: "从某入侵点出发的感染率",
			},
			[]string{"source"},
		),
		overpermissionEdges: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "netpol_policy_overpermission_edges",
				Help: "策略允许但从未发生的边数",
			},
		),
		droppedAttempts: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "netpol_policy_dropped_attempts",
				Help: "被拒绝的连接尝试总数",
			},
		),
		collector: collector,
	}

	prometheus.MustRegister(
		m.flowTotal,
		m.podConnectionsIn,
		m.podConnectionsOut,
		m.spreadReachable,
		m.spreadMaxDepth,
		m.spreadInfection,
		m.overpermissionEdges,
		m.droppedAttempts,
	)

	return m
}

// UpdateFromLiveEdges 根据实时流量拓扑更新 Prometheus 指标
func (m *Metrics) UpdateFromLiveEdges(liveEdges []LiveEdge) {
	// 统计每个 Pod 的入度和出度
	inCount := make(map[string]float64)
	outCount := make(map[string]float64)
	var totalDropped float64

	for _, e := range liveEdges {
		outCount[e.From]++
		inCount[e.To]++
		totalDropped += float64(e.Dropped)
	}

	for pod, count := range inCount {
		m.podConnectionsIn.WithLabelValues(pod).Set(count)
	}
	for pod, count := range outCount {
		m.podConnectionsOut.WithLabelValues(pod).Set(count)
	}
	m.droppedAttempts.Set(totalDropped)
}

// UpdateSpreadMetrics 用 BFS 传播模拟结果更新指标
func (m *Metrics) UpdateSpreadMetrics(liveEdges []LiveEdge) {
	// 将 LiveEdge 转为 Edge 格式以复用现有的 SimulateSpread
	var edges []Edge
	for _, le := range liveEdges {
		edges = append(edges, Edge{
			From:     le.From,
			To:       le.To,
			Port:     int(le.Port),
			Protocol: le.Protocol,
		})
	}

	// 收集所有节点
	allNodes := make(map[string]bool)
	for _, e := range edges {
		allNodes[e.From] = true
		allNodes[e.To] = true
	}

	// 对每个节点做传播模拟
	for node := range allNodes {
		result := SimulateSpread(edges, node)
		m.spreadReachable.WithLabelValues(node).Set(float64(len(result.Reachable)))
		m.spreadMaxDepth.WithLabelValues(node).Set(float64(result.MaxDepth))

		total := len(result.Reachable) + len(result.Unreachable)
		if total > 0 {
			rate := float64(len(result.Reachable)) / float64(total)
			m.spreadInfection.WithLabelValues(node).Set(rate)
		}
	}
}

// StartMetricsServer 启动 HTTP server 暴露 /metrics
func StartMetricsServer(port int) {
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("Prometheus 指标服务启动在 %s/metrics\n", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Printf("指标服务启动失败: %v\n", err)
	}
}
