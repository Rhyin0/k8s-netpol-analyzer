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
	"gopkg.in/yaml.v3"
)

func main() {
	fmt.Println("=== K8s NetworkPolicy Analyzer v2 ===")
	fmt.Println()

	// ========== Phase 1: 静态分析（保留原有功能）==========

	// 读取 YAML 文件
	data, err := os.ReadFile("testdata/policies.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取策略文件失败（跳过静态分析）: %v\n", err)
	}

	var policies []graph.NetworkPolicy
	var staticEdges []graph.Edge

	if err == nil {
		docs := strings.Split(string(data), "---")
		for _, doc := range docs {
			doc = strings.TrimSpace(doc)
			if doc == "" {
				continue
			}
			var policy graph.NetworkPolicy
			if err := yaml.Unmarshal([]byte(doc), &policy); err != nil {
				fmt.Fprintf(os.Stderr, "解析YAML失败: %v\n", err)
				continue
			}
			policies = append(policies, policy)
		}

		fmt.Printf("解析到 %d 条 NetworkPolicy\n\n", len(policies))

		// 构建静态可达性边
		for _, p := range policies {
			target := graph.LabelStr(p.Spec.PodSelector.MatchLabels)
			for _, rule := range p.Spec.Ingress {
				for _, from := range rule.From {
					source := graph.LabelStr(from.PodSelector.MatchLabels)
					for _, port := range rule.Ports {
						staticEdges = append(staticEdges, graph.Edge{
							From:     source,
							To:       target,
							Port:     port.Port,
							Protocol: port.Protocol,
						})
					}
				}
			}
			for _, rule := range p.Spec.Egress {
				for _, to := range rule.To {
					dest := graph.LabelStr(to.PodSelector.MatchLabels)
					for _, port := range rule.Ports {
						staticEdges = append(staticEdges, graph.Edge{
							From:     target,
							To:       dest,
							Port:     port.Port,
							Protocol: port.Protocol,
						})
					}
				}
			}
		}
		staticEdges = graph.Dedup(staticEdges)

		fmt.Println("=== 策略拓扑（静态）===")
		for _, e := range staticEdges {
			fmt.Printf("  %s --> %s [%s/%d]\n", e.From, e.To, e.Protocol, e.Port)
		}
		fmt.Println()
	}

	// ========== Phase 2: 动态流量采集 ==========

	// Hubble Relay 地址（通过 port-forward 暴露到本地）
	hubbleAddr := "localhost:4245"
	if addr := os.Getenv("HUBBLE_ADDR"); addr != "" {
		hubbleAddr = addr
	}

	// 创建 FlowCollector
	collector := hubble.NewFlowCollector(hubbleAddr)

	// 创建 Prometheus 指标
	m := metrics.NewMetrics(collector)
	// using m

	// 启动 Prometheus HTTP server（goroutine）
	go metrics.StartMetricsServer(9090)

	// 启动 Hubble 流量采集（goroutine）
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动流量采集失败: %v\n", err)
		os.Exit(1)
	}

	// 定期更新指标
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

				// 打印实时状态
				fmt.Printf("\n[%s] 已采集 %d 条 Flow，发现 %d 条实时边\n",
					time.Now().Format("15:04:05"),
					collector.GetFlowCount(),
					len(liveEdges))

				// 显示实时流量拓扑
				if len(liveEdges) > 0 {
					fmt.Println("  实时流量拓扑:")
					for _, e := range liveEdges {
						fmt.Printf("    %s --> %s [%s/%d] 次数:%d 拒绝:%d\n",
							e.From, e.To, e.Protocol, e.Port, e.Count, e.Dropped)
					}
				}

				// 对比静态策略和实际流量
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

	// 等待退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n正在关闭...")
	cancel()
	time.Sleep(1 * time.Second)
	fmt.Println("已退出")
}

// compareTopologies 对比静态策略拓扑和实际流量拓扑
func compareTopologies(staticEdges []graph.Edge, liveEdges []hubble.LiveEdge) {
	// 构建实际流量的 key 集合
	liveSet := make(map[string]bool)
	for _, e := range liveEdges {
		// 用 from->to 作为 key（不含端口，因为端口可能不完全匹配）
		key := fmt.Sprintf("%s->%s", e.From, e.To)
		liveSet[key] = true
	}

	// 找出策略允许但从未发生的边
	var overpermitted []string
	for _, e := range staticEdges {
		key := fmt.Sprintf("%s->%s", e.From, e.To)
		if !liveSet[key] {
			overpermitted = append(overpermitted, fmt.Sprintf("%s->%s:%d", e.From, e.To, e.Port))
		}
	}

	if len(overpermitted) > 0 {
		fmt.Printf("  过度授权（策略允许但从未发生）: %d 条\n", len(overpermitted))
		for _, edge := range overpermitted {
			fmt.Printf("    ⚠ %s\n", edge)
		}
	}
}
