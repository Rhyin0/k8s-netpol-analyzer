// cmd/query/main.go
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Rhyin0/k8s-netpol-analyzer/internal/graph"
	"github.com/Rhyin0/k8s-netpol-analyzer/internal/policy"
)

func main() {
	src := flag.String("src", "", "source pod label (e.g. frontend)")
	dst := flag.String("dst", "", "destination pod label (e.g. order-db)")
	file := flag.String("f", "testdata/policies.yaml", "policy file path")
	flag.Parse()

	if *src == "" || *dst == "" {
		fmt.Fprintln(os.Stderr, "用法: query -src <pod> -dst <pod> [-f <policy.yaml>]")
		flag.Usage()
		os.Exit(1)
	}

	_, edges, err := policy.LoadFromFile(*file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载策略失败: %v\n", err)
		os.Exit(1)
	}

	result := graph.QueryReachability(edges, *src, *dst)

	if result.Reachable {
		fmt.Printf("✅ 可达: %s\n", strings.Join(result.Path, " → "))
		for i, port := range result.Ports {
			fmt.Printf("   %s → %s [port %d]\n",
				result.Path[i], result.Path[i+1], port)
		}
	} else {
		fmt.Printf("❌ 不可达: %s → %s\n", *src, *dst)
		fmt.Printf("   原因: %s\n", result.BlockReason)
	}
}
