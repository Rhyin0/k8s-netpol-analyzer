package main

import (
	"flag"
	"fmt"
)

func main() {
	src := flag.String("src", "", "source pod (namespace/name)")
	dst := flag.String("dst", "", "destination pod (namespace/name)")
	flag.Parse()

	if *src == "" || *dst == "" {
		flag.Usage()
		return
	}

	fmt.Printf("checking: %s → %s\n", *src, *dst)
	// TODO: 加载策略，构建图，BFS查询
}
