// Command diff collects live traffic from Hubble for a while, then reports
// which statically permitted edges were actually used.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/flowstat"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/hubble"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/policy"
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
	file := flag.String("f", "testdata/policies.yaml", "policy file path")
	hubbleAddr := flag.String("hubble", "localhost:4245", "Hubble relay address")
	collect := flag.Duration("collect", 60*time.Second, "how long to collect flows")
	minWindow := flag.Duration("min-window", 30*time.Minute,
		"minimum window for an over-permission finding to be trustworthy")
	namespace := flag.String("n", "", "only watch this namespace (default: all)")
	flag.Parse()

	if noColor() {
		reset, bold, dim, green, yellow, red, grey = "", "", "", "", "", "", ""
	}

	g, err := policy.LoadGraph(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载策略失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("解析到 %d 条 NetworkPolicy，%d 个节点，%d 条静态边\n",
		len(g.Policies), len(g.NodeIDs()), len(g.Edges))

	tracker := flowstat.NewTracker()
	collector := hubble.NewFlowCollector(*hubbleAddr, *namespace, 4095)
	collector.AttachTracker(g, tracker)

	ctx, cancel := context.WithTimeout(context.Background(), *collect)
	defer cancel()

	if err := collector.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "启动流量采集失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("正在从 %s 采集流量，持续 %s（Ctrl+C 提前结束）...\n\n", *hubbleAddr, *collect)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-ctx.Done():
	case <-sigCh:
		fmt.Println("\n提前结束采集。")
		cancel()
	}

	observed, start := tracker.Snapshot()
	diff := graph.CompareTopologies(g, observed, start, *minWindow)

	fmt.Printf("采集到 %d 条 Flow，映射到 %d 条观测边\n", collector.GetFlowCount(), len(observed))
	report(diff, *minWindow)
}

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
