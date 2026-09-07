// Command analyzer analyses Kubernetes NetworkPolicies statically and compares
// the result against the traffic Hubble actually observes.
//
// It runs in one of two modes, selected by -collect:
//
//	-collect 0   (default) 服务模式：导出静态拓扑，持续采集流量，在 :9090 上
//	                       提供 web 视图与 Prometheus 指标，每 10 秒打印一次差集摘要。
//	-collect 30m           报告模式：采集指定时长后打印完整的过度授权报告并退出。
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/hubble"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/metrics"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/policy"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/visualise"
)

const (
	// httpPort 上同时服务 web 视图、/api/diff 和 /metrics。
	httpPort = 9090
	// flowBufSize 是 Hubble ring buffer 的容量。
	flowBufSize = 4095
	// tickInterval 是服务模式下打印实时拓扑的间隔。
	tickInterval = 10 * time.Second

	dotFile  = "network-topology.dot"
	jsonFile = "web/network-topology.json"
)

// ANSI colours, suppressed when stdout is not a terminal or NO_COLOR is set.
var (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	yellow = "\033[33m"
	red    = "\033[31m"
	grey   = "\033[90m"
)

func main() {
	// 参数一律走 flag；环境变量只作为默认值，显式传入的 flag 优先。
	// 这样既保留了 Helm chart 里 HUBBLE_ADDR 之类的既有配置方式，
	// 又让命令行成为唯一需要记住的接口。
	file := flag.String("f", "testdata/policies.yaml", "policy file path")
	hubbleAddr := flag.String("hubble", envStr("HUBBLE_ADDR", "localhost:4245"), "Hubble relay address")
	namespace := flag.String("n", os.Getenv("WATCH_NAMESPACE"), "only watch this namespace (default: all)")
	collect := flag.Duration("collect", 0,
		"how long to collect flows before reporting; 0 keeps running and serves the web view on :9090")
	minWindow := flag.Duration("min-window", envDuration("DIFF_MIN_WINDOW", 30*time.Minute),
		"minimum window for an over-permission finding to be trustworthy")
	flag.Parse()

	if noColor() {
		reset, bold, dim, green, yellow, red, grey = "", "", "", "", "", "", ""
	}

	serve := *collect <= 0

	fmt.Println("=== K8s NetworkPolicy Analyzer v2 ===")
	fmt.Println()

	// ========== Phase 1: 静态分析 ==========

	var (
		g     *graph.Graph
		risks []graph.NodeRisk
	)

	policies, staticEdges, isolation, allPods, err := policy.LoadFromFile(*file)
	if err != nil {
		// 服务模式下静态分析只是一半的工作，缺了它照样可以采集流量；
		// 报告模式没有静态图就无从比对，直接退出。
		if !serve {
			fmt.Fprintf(os.Stderr, "加载策略失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "读取策略文件失败（跳过静态分析）: %v\n", err)
	} else {
		g = &graph.Graph{Policies: policies, Edges: staticEdges, Isolation: isolation}
		fmt.Printf("解析到 %d 条 NetworkPolicy，%d 个节点，%d 条静态边\n\n",
			len(policies), len(g.NodeIDs()), len(staticEdges))
		if serve {
			risks = analyseStatic(g, allPods)
		}
	}

	// ========== Phase 2: 动态流量采集 ==========

	// 累计观测表：ring buffer 会淘汰旧记录，差集分析不能用它判断
	// 「这条边有没有流量」，否则低频边会被高频流量冲刷成「无流量」。
	tracker := flowstat.NewTracker()
	collector := hubble.NewFlowCollector(*hubbleAddr, *namespace, flowBufSize)
	if g != nil {
		collector.AttachTracker(g, tracker)
	}

	if serve {
		runServe(collector, tracker, g, risks, *minWindow)
		return
	}
	runReport(collector, tracker, g, *hubbleAddr, *collect, *minWindow)
}

// analyseStatic 打印静态拓扑与 default-allow 缺口，并导出 DOT/JSON 供 web 视图使用。
func analyseStatic(g *graph.Graph, allPods []string) []graph.NodeRisk {
	fmt.Println("=== 策略拓扑（静态）===")
	for _, e := range g.Edges {
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
	if g.Isolation != nil {
		graph.PrintDefaultAllowReport(graph.FindDefaultAllowGaps(g.Isolation))
	}

	risks := graph.AnalyzeAllNodes(allPods, g.Edges)

	// Graph output
	if err := visualise.ExportDOT(g.Edges, risks, dotFile); err != nil {
		fmt.Fprintf(os.Stderr, "导出 DOT 文件失败: %v\n", err)
	} else {
		fmt.Printf("已导出静态拓扑 DOT 文件: %s\n", dotFile)
	}

	// JSON output
	if err := visualise.ExportJSON(g.Edges, risks, g.Isolation, jsonFile); err != nil {
		fmt.Fprintf(os.Stderr, "导出 JSON 文件失败: %v\n", err)
	} else {
		fmt.Printf("已导出静态拓扑 JSON 文件: %s\n", jsonFile)
	}

	return risks
}

// runServe 持续采集流量，在 httpPort 上提供 web 视图、/api/diff 与 Prometheus 指标，
// 并周期性打印实时拓扑和差集摘要，直到收到中断信号。
func runServe(collector *hubble.FlowCollector, tracker *flowstat.Tracker,
	g *graph.Graph, risks []graph.NodeRisk, minWindow time.Duration) {

	m := metrics.NewMetrics(collector)

	http.HandleFunc("/api/diff", func(w http.ResponseWriter, r *http.Request) {
		if g == nil {
			http.Error(w, "静态策略未加载", http.StatusServiceUnavailable)
			return
		}
		observed, start := tracker.Snapshot()
		diff := graph.CompareTopologies(g, observed, start, minWindow)

		data, derr := visualise.RenderJSON(g.Edges, risks, g.Isolation, &diff)
		if derr != nil {
			http.Error(w, derr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})
	http.Handle("/", http.FileServer(http.Dir("web")))

	go metrics.StartMetricsServer(httpPort)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动流量采集失败: %v\n", err)
		os.Exit(1)
	}

	go func() {
		ticker := time.NewTicker(tickInterval)
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

				if g != nil {
					observed, start := tracker.Snapshot()
					printDiffSummary(graph.CompareTopologies(g, observed, start, minWindow))
				}
			}
		}
	}()

	fmt.Println()
	fmt.Println("程序已启动，正在采集流量数据...")
	fmt.Printf("  Web 拓扑视图: http://localhost:%d/topology.html\n", httpPort)
	fmt.Printf("  Prometheus 指标: http://localhost:%d/metrics\n", httpPort)
	fmt.Println("  按 Ctrl+C 退出")
	fmt.Println()

	<-waitSignal()

	fmt.Println("\n正在关闭...")
	cancel()
	time.Sleep(1 * time.Second)
	fmt.Println("已退出")
}

// runReport 采集固定时长的流量后打印一次完整的过度授权报告。
func runReport(collector *hubble.FlowCollector, tracker *flowstat.Tracker,
	g *graph.Graph, hubbleAddr string, collect, minWindow time.Duration) {

	ctx, cancel := context.WithTimeout(context.Background(), collect)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动流量采集失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("正在从 %s 采集流量，持续 %s（Ctrl+C 提前结束）...\n\n", hubbleAddr, collect)

	select {
	case <-ctx.Done():
	case <-waitSignal():
		fmt.Println("\n提前结束采集。")
		cancel()
	}

	observed, start := tracker.Snapshot()
	diff := graph.CompareTopologies(g, observed, start, minWindow)

	fmt.Printf("采集到 %d 条 Flow，映射到 %d 条观测边\n", collector.GetFlowCount(), len(observed))
	report(diff, minWindow)
}

// printDiffSummary 是服务模式下的紧凑摘要，每个采集周期打印一次。
func printDiffSummary(d graph.TopologyDiff) {
	over := d.ByClass(graph.ClassOverpermissive)
	drops := d.ByClass(graph.ClassUnexpectedDrop)

	fmt.Printf("  差集: 确认 %d / 过度授权 %d / 意外拒绝 %d\n",
		len(d.ByClass(graph.ClassConfirmed)), len(over), len(drops))

	if !d.Window.Sufficient {
		fmt.Printf("  ⚠ 观测窗口仅 %ds，尚不足以判定过度授权\n", d.Window.DurationSeconds)
	}

	for _, e := range over {
		refs := ""
		if len(e.PolicyRefs) > 0 {
			refs = " ← " + strings.Join(e.PolicyRefs, ", ")
		}
		fmt.Printf("    ! %s → %s [%s]%s\n", e.Src, e.Dst, e.PortLabel(), refs)
	}
	for _, e := range drops {
		fmt.Printf("    ✗ %s → %s [%s] 拒绝:%d\n", e.Src, e.Dst, e.PortLabel(), e.Dropped)
	}
}

// report 是报告模式下的完整分类报告。
func report(d graph.TopologyDiff, minWindow time.Duration) {
	window := time.Duration(d.Window.DurationSeconds) * time.Second

	if !d.Window.Sufficient {
		fmt.Printf("\n%s%s⚠  观测窗口仅 %s，低于可信阈值 %s。%s\n",
			bold, yellow, window.Round(time.Second), minWindow, reset)
		fmt.Printf("%s   低频流量（定时任务、故障转移路径）可能尚未发生，\n", yellow)
		fmt.Printf("   下面的「过度授权」结论不可作为删除策略的依据。%s\n", reset)
	}

	confirmed := d.ByClass(graph.ClassConfirmed)
	over := d.ByClass(graph.ClassOverpermissive)
	drops := d.ByClass(graph.ClassUnexpectedDrop)

	fmt.Printf("\n%s观测窗口%s: %s 起，持续 %s\n",
		bold, reset, d.Window.Start.Format("2006-01-02 15:04:05"), window.Round(time.Second))

	// ---- confirmed ----
	fmt.Printf("\n%s%s✅ 已确认使用%s (%d)\n", bold, green, reset, len(confirmed))
	if len(confirmed) == 0 {
		fmt.Printf("%s   窗口内没有任何策略允许的边发生过流量。%s\n", grey, reset)
	}
	for _, e := range confirmed {
		fmt.Printf("   %s%s → %s%s [%s] 转发:%d",
			green, e.Src, e.Dst, reset, e.PortLabel(), e.Forwarded)
		if e.Dropped > 0 {
			fmt.Printf(" 拒绝:%d", e.Dropped)
		}
		fmt.Println()
	}

	// ---- overpermissive ----
	fmt.Printf("\n%s%s⚠️  过度授权%s (%d) %s— 策略允许但窗口内无流量%s\n",
		bold, yellow, reset, len(over), dim, reset)
	if len(over) == 0 {
		fmt.Printf("%s   没有发现多余的授权。%s\n", grey, reset)
	}
	for _, e := range over {
		fmt.Printf("   %s%s → %s%s [%s]\n", yellow, e.Src, e.Dst, reset, e.PortLabel())
		if len(e.PolicyRefs) > 0 {
			fmt.Printf("      %s来源策略: %s%s\n", dim, strings.Join(e.PolicyRefs, ", "), reset)
		} else {
			fmt.Printf("      %s来源: 无策略覆盖（default-allow），需新增策略而非修改%s\n", dim, reset)
		}
	}

	// ---- unexpected drops ----
	fmt.Printf("\n%s%s🚫 意外拒绝%s (%d) %s— 静态图无此边但观测到 DROPPED%s\n",
		bold, red, reset, len(drops), dim, reset)
	if len(drops) == 0 {
		fmt.Printf("%s   没有被策略拦截的意外流量。%s\n", grey, reset)
	}
	for _, e := range drops {
		fmt.Printf("   %s%s → %s%s [%s] 拒绝:%d\n",
			red, e.Src, e.Dst, reset, e.PortLabel(), e.Dropped)
	}

	fmt.Printf("\n%s小结%s: 确认 %d / 过度授权 %d / 意外拒绝 %d\n",
		bold, reset, len(confirmed), len(over), len(drops))
	if !d.Window.Sufficient {
		fmt.Printf("%s窗口不足，结论仅供参考。%s\n", yellow, reset)
	}
}

func waitSignal() <-chan os.Signal {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	return sigCh
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func noColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return true
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return true
	}
	return fi.Mode()&os.ModeCharDevice == 0
}
