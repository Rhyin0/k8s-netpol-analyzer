package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/hubble"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/metrics"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/policy"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/visualise"
)

func main() {
	fmt.Println("=== K8s NetworkPolicy Analyzer v2 ===")
	fmt.Println()

	// ========== Phase 1: 静态分析 ==========

	policies, staticEdges, isolation, allPods, err := policy.LoadFromFile("testdata/policies.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取策略文件失败（跳过静态分析）: %v\n", err)
	}

	if err == nil {
		fmt.Printf("解析到 %d 条 NetworkPolicy\n\n", len(policies))

		fmt.Println("=== 策略拓扑（静态）===")
		for _, e := range staticEdges {
			defaultInfo := ""
			if e.EgressDefault || e.IngressDefault {
				var parts []string
				if e.EgressDefault {
					parts = append(parts, "egress-default")
				}
				if e.IngressDefault {
					parts = append(parts, "ingress-default")
				}
				defaultInfo = " (" + strings.Join(parts, ",") + ")"
			}
			fmt.Printf("  %s --> %s [%s]%s\n", e.From, e.To, graph.PortsLabel(e.Ports), defaultInfo)
		}
		fmt.Println()

		// Default-Allow 缺口报告
		if isolation != nil {
			gaps := graph.FindDefaultAllowGaps(isolation)
			graph.PrintDefaultAllowReport(gaps)
		}

		// Graph output
		risks := graph.AnalyzeAllNodes(allPods, staticEdges)
		dotFile := "network-topology.dot"
		if err := visualise.ExportDOT(staticEdges, risks, dotFile); err != nil {
			fmt.Fprintf(os.Stderr, "导出 DOT 文件失败: %v\n", err)
		} else {
			fmt.Printf("已导出静态拓扑 DOT 文件: %s\n", dotFile)
		}

		// JSON output
		jsonFile := "web/network-topology.json"
		if err := visualise.ExportJSON(staticEdges, risks, isolation, jsonFile); err != nil {
			fmt.Fprintf(os.Stderr, "导出 JSON 文件失败: %v\n", err)
		} else {
			fmt.Printf("已导出静态拓扑 JSON 文件: %s\n", jsonFile)
		}
	}

	// ========== Phase 2: 动态流量采集 ==========

	hubbleAddr := "localhost:4245"
	if addr := os.Getenv("HUBBLE_ADDR"); addr != "" {
		hubbleAddr = addr
	}

	namespace := os.Getenv("WATCH_NAMESPACE")

	collector := hubble.NewFlowCollector(hubbleAddr, namespace, 4095)

	m := metrics.NewMetrics(collector)

	go metrics.StartMetricsServer(9090)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动流量采集失败: %v\n", err)
		os.Exit(1)
	}

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				liveEdges := collector.GetLiveEdges()
				m.UpdateFromLiveEdges(liveEdges)
				m.UpdateSpreadMetrics(liveEdges)

				fmt.Printf("\n[%s] 已采集 %d 条 Flow，发现 %d 条实时边\n",
					time.Now().Format("15:04:05"),
					collector.GetFlowCount(),
					len(liveEdges))

				if len(liveEdges) > 0 {
					fmt.Println("  实时流量拓扑:")
					for _, e := range liveEdges {
						fmt.Printf("    %s --> %s [%s/%d] 次数:%d 拒绝:%d\n",
							e.From, e.To, e.Protocol, e.Port, e.Count, e.Dropped)
					}
				}

				if len(staticEdges) > 0 && len(liveEdges) > 0 {
					compareTopologies(staticEdges, liveEdges)
				}
			}
		}
	}()

	fmt.Println()
	fmt.Println("程序已启动，正在采集流量数据...")
	fmt.Println("  Prometheus 指标: http://localhost:9090/metrics")
	fmt.Println("  按 Ctrl+C 退出")
	fmt.Println()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n正在关闭...")
	cancel()
	time.Sleep(1 * time.Second)
	fmt.Println("已退出")
}

func compareTopologies(staticEdges []graph.Edge, liveEdges []hubble.LiveEdge) {
	liveSet := make(map[string]bool)
	for _, e := range liveEdges {
		key := fmt.Sprintf("%s->%s", e.From, e.To)
		liveSet[key] = true
	}

	var overpermitted []string
	for _, e := range staticEdges {
		key := fmt.Sprintf("%s->%s", e.From, e.To)
		if !liveSet[key] {
			overpermitted = append(overpermitted, fmt.Sprintf("%s->%s [%s]", e.From, e.To, graph.PortsLabel(e.Ports)))
		}
	}

	if len(overpermitted) > 0 {
		fmt.Printf("  过度授权（策略允许但从未发生）: %d 条\n", len(overpermitted))
		for _, edge := range overpermitted {
			fmt.Printf("    ! %s\n", edge)
		}
	}
}
