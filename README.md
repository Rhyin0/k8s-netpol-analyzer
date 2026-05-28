# K8s NetworkPolicy Analyzer

A real-time Kubernetes network security analysis tool that combines static NetworkPolicy analysis with dynamic traffic observation. It connects to Cilium/Hubble to collect live flow data, performs BFS-based attack propagation simulation, compares policy-permitted topology against actual traffic patterns, and exposes metrics to Prometheus for Grafana visualization.

## Architecture

```
                    Kind Cluster (Docker Desktop)
┌──────────────────────────────────────────────────────────┐
│                                                          │
│   demo namespace              Cilium + Hubble            │
│  ┌──────────────────┐    ┌─────────────────────────┐     │
│  │ frontend          │    │ Cilium CNI               │     │
│  │ api-server        │───▶│  enforce policies        │     │
│  │ order-service     │    │  route traffic            │     │
│  │ database          │    │                           │     │
│  │ redis-cache       │    │ Hubble                    │     │
│  │ NetworkPolicy     │    │  observe every flow       │     │
│  └──────────────────┘    │  Hubble Relay (:4245)     │     │
│                           └────────────┬────────────┘     │
│   monitoring namespace                 │                  │
│  ┌──────────────────┐                  │ gRPC stream      │
│  │ Prometheus        │                  │ (port-forward)   │
│  │  pull /metrics    │                  │                  │
│  │ Grafana (:3000)   │                  │                  │
│  │  query & display  │                  │                  │
│  └───────┬──────────┘                  │                  │
└──────────┼──────────────────────────────┼──────────────────┘
           │ pull /metrics                │
           │ (ServiceMonitor)             │
           ▼                              ▼
    ┌─────────────────────────────────────────────┐
    │         Go Program (local machine)           │
    │                                               │
    │  gRPC client ──▶ receive Flows                │
    │  analyze: BFS propagation, topology metrics   │
    │  compare: policy topology vs live traffic     │
    │  HTTP server ──▶ :9090/metrics                │
    └─────────────────────────────────────────────┘
```

## Features

**Static analysis (Phase 1)**
- Parse NetworkPolicy YAML files and build a directed reachability graph
- BFS-based attack propagation simulation from any entry point
- Critical path detection (longest attack chain)
- Articulation point (cut vertex) detection
- Policy compliance checking
- Topology metrics (density, clustering coefficient)
- Graphviz visualization export

**Dynamic analysis (Phase 2)**
- Real-time flow collection from Cilium/Hubble via gRPC
- Live traffic topology construction
- Policy vs actual traffic comparison (overpermission detection)
- Dropped connection attempt tracking
- Prometheus metrics exposure for Grafana dashboards
- Namespace-level filtering (demo namespace only)

## Prerequisites

- Docker Desktop
- Go 1.21+
- kubectl
- Kind
- Cilium CLI
- Hubble CLI
- Helm (for Prometheus + Grafana)

## Quick Start

### 1. Create the Kind cluster

```bash
kind create cluster --config kind-config.yaml --name netpol-lab
```

### 2. Install Cilium with Hubble

```bash
cilium install --set hubble.relay.enabled=true --set hubble.ui.enabled=true
cilium status --wait
```

### 3. Deploy test applications and policies

```bash
kubectl apply -f test-apps.yaml
kubectl apply -f test-services.yaml
kubectl apply -f test-netpol.yaml
```

### 4. Install Prometheus and Grafana

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install monitoring prometheus-community/kube-prometheus-stack \
  --namespace monitoring --create-namespace \
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false
```

### 5. Configure Prometheus scraping

Find the host IP from inside the cluster:

```bash
kubectl run tmp --rm -it --image=alpine --restart=Never -- nslookup host.docker.internal
```

Update the IP in `netpol-scrape.yaml`, then apply:

```bash
kubectl apply -f netpol-scrape.yaml
```

### 6. Start port-forwards (each in a separate terminal)

```bash
# Terminal 1: Hubble Relay
cilium hubble port-forward

# Terminal 2: Grafana
kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80
```

### 7. Run the analyzer

```bash
go run .
```

The program will:
- Parse static policies from `testdata/policies.yaml`
- Connect to Hubble Relay and start collecting live flows
- Expose Prometheus metrics at `http://localhost:9090/metrics`
- Print real-time traffic topology and policy comparison every 10 seconds

### 8. Generate traffic

```bash
kubectl exec -n demo frontend -- wget -qO- --timeout=2 api-server.demo.svc.cluster.local
kubectl exec -n demo api-server -- wget -qO- --timeout=2 order-service.demo.svc.cluster.local
kubectl exec -n demo order-service -- wget -qO- --timeout=2 database.demo.svc.cluster.local
kubectl exec -n demo api-server -- wget -qO- --timeout=2 redis-cache.demo.svc.cluster.local
```

### 9. View the dashboard

Open `http://localhost:3000` (admin / admin123) and view the NetPol Analyzer dashboard.

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `netpol_pod_connections_in` | Gauge | Inbound connection count per pod |
| `netpol_pod_connections_out` | Gauge | Outbound connection count per pod |
| `netpol_spread_reachable` | Gauge | Reachable nodes from a given entry point |
| `netpol_spread_max_depth` | Gauge | Max propagation depth from entry point |
| `netpol_spread_infection_rate` | Gauge | Infection rate from entry point (0-1) |
| `netpol_policy_overpermission_edges` | Gauge | Policy-allowed but never-observed edges |
| `netpol_policy_dropped_attempts` | Gauge | Total dropped connection attempts |

## Grafana Dashboard Panels

- **Pod out connections** — time series of outbound connections per pod
- **Infection rate** — gauge showing BFS infection rate per entry point
- **Max spread depth** — bar chart of propagation depth per node
- **Dropped attempts** — stat panel showing total rejected connections

## Project Structure

```
k8s-netpol-analyzer/
├── main.go              # Entry point: static analysis + dynamic service
├── hubble.go            # Hubble gRPC client, flow collection
├── metrics.go           # Prometheus metrics definition and HTTP server
├── types.go             # Shared type definitions (Edge, NetworkPolicy)
├── analyzer.go          # BFS propagation simulation
├── critical.go          # Articulation point detection
├── compliance.go        # Policy compliance checking
├── topology.go          # Topology metrics (density, clustering)
├── visualize.go         # Graphviz DOT export
├── testdata/            # Sample NetworkPolicy YAML files
├── kind-config.yaml     # Kind cluster configuration
├── test-apps.yaml       # Test pod definitions
├── test-services.yaml   # Test service definitions
├── test-netpol.yaml     # NetworkPolicy rules for demo namespace
└── netpol-scrape.yaml   # Prometheus ServiceMonitor configuration
```

## NetworkPolicy Test Topology

```
frontend ──▶ api-server ──▶ order-service ──▶ database
                  │
                  └──▶ redis-cache
```

- frontend can only reach api-server
- api-server can reach order-service and redis-cache
- order-service can reach database
- database and redis-cache have no outbound access
- All pods are allowed DNS (UDP 53) egress

## Future Work

- Containerize the Go program and deploy as a pod in the cluster
- Add anomaly detection based on traffic pattern changes
- Implement ML-based policy optimization suggestions
- Export Grafana dashboard as JSON for version control
- Add support for multiple namespaces
