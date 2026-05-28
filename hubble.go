package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// FlowRecord 表示一条从 Hubble 采集到的流量记录
type FlowRecord struct {
	Timestamp    time.Time
	SrcPod       string
	DstPod       string
	SrcNamespace string
	DstNamespace string
	DstPort      uint32
	Protocol     string
	Verdict      string // FORWARDED 或 DROPPED
}

// FlowCollector 持续从 Hubble 采集流量数据
type FlowCollector struct {
	mu         sync.RWMutex
	flows      []FlowRecord
	edges      map[string]*LiveEdge // 实时流量拓扑
	hubbleAddr string
}

// LiveEdge 表示实际观测到的一条流量边
type LiveEdge struct {
	From     string
	To       string
	Port     uint32
	Protocol string
	Count    int64 // 观测到的次数
	LastSeen time.Time
	Dropped  int64 // 被拒绝的次数
}

func NewFlowCollector(hubbleAddr string) *FlowCollector {
	return &FlowCollector{
		hubbleAddr: hubbleAddr,
		edges:      make(map[string]*LiveEdge),
	}
}

// Start 启动一个 goroutine 持续从 Hubble 接收 Flow
func (fc *FlowCollector) Start(ctx context.Context) error {
	conn, err := grpc.NewClient(
		fc.hubbleAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("连接 Hubble 失败: %v", err)
	}

	client := observerpb.NewObserverClient(conn)

	go func() {
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				fc.observe(ctx, client)
				// 如果连接断了，等几秒重试
				time.Sleep(5 * time.Second)
				fmt.Println("重新连接 Hubble...")
			}
		}
	}()

	return nil
}

// observe 执行一次 GetFlows 流式接收
func (fc *FlowCollector) observe(ctx context.Context, client observerpb.ObserverClient) {
	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Follow: true, // 持续接收新的 Flow
	})
	if err != nil {
		fmt.Printf("GetFlows 失败: %v\n", err)
		return
	}

	fmt.Println("已连接 Hubble，开始接收 Flow 数据...")

	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Printf("接收 Flow 失败: %v\n", err)
			return
		}

		flow := resp.GetFlow()
		if flow == nil {
			continue
		}

		// 提取源和目标信息
		src := flow.GetSource()
		dst := flow.GetDestination()
		if src == nil || dst == nil {
			continue
		}

		// 只关注 demo namespace 的业务 Pod
		srcNs := src.GetNamespace()
		dstNs := dst.GetNamespace()
		srcPod := src.GetPodName()
		dstPod := dst.GetPodName()
		if srcPod == "" || dstPod == "" {
			continue
		}
		if srcNs != "demo" || dstNs != "demo" {
			continue
		}

		// 获取目标端口
		var dstPort uint32
		l4 := flow.GetL4()
		if l4 != nil {
			if tcp := l4.GetTCP(); tcp != nil {
				dstPort = tcp.GetDestinationPort()
			} else if udp := l4.GetUDP(); udp != nil {
				dstPort = udp.GetDestinationPort()
			}
		}

		// 获取协议
		protocol := "TCP"
		if l4 != nil && l4.GetUDP() != nil {
			protocol = "UDP"
		}

		// 获取判决结果
		verdict := flow.GetVerdict().String()

		record := FlowRecord{
			Timestamp:    flow.GetTime().AsTime(),
			SrcPod:       srcPod,
			DstPod:       dstPod,
			SrcNamespace: src.GetNamespace(),
			DstNamespace: dst.GetNamespace(),
			DstPort:      dstPort,
			Protocol:     protocol,
			Verdict:      verdict,
		}

		fc.mu.Lock()
		fc.flows = append(fc.flows, record)
		fc.updateEdge(record)
		fc.mu.Unlock()
	}
}

// updateEdge 根据新的 FlowRecord 更新实时流量拓扑
func (fc *FlowCollector) updateEdge(record FlowRecord) {
	key := fmt.Sprintf("%s->%s:%d", record.SrcPod, record.DstPod, record.DstPort)

	edge, exists := fc.edges[key]
	if !exists {
		edge = &LiveEdge{
			From:     record.SrcPod,
			To:       record.DstPod,
			Port:     record.DstPort,
			Protocol: record.Protocol,
		}
		fc.edges[key] = edge
	}

	if record.Verdict == "FORWARDED" {
		edge.Count++
	} else {
		edge.Dropped++
	}
	edge.LastSeen = record.Timestamp
}

// GetLiveEdges 返回当前的实时流量拓扑
func (fc *FlowCollector) GetLiveEdges() []LiveEdge {
	fc.mu.RLock()
	defer fc.mu.RUnlock()

	result := make([]LiveEdge, 0, len(fc.edges))
	for _, e := range fc.edges {
		result = append(result, *e)
	}
	return result
}

// GetFlowCount 返回已采集的 Flow 总数
func (fc *FlowCollector) GetFlowCount() int {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return len(fc.flows)
}
