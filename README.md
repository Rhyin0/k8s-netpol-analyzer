# K8s NetworkPolicy Analyzer

Static and runtime analysis of Kubernetes NetworkPolicy.

A misconfigured selector produces connection timeouts rather than errors,
and a pod not selected by any policy is default-allow — neither condition
is surfaced by the API.

The tool answers three questions:

- Which paths does a policy change cut off? (static, pre-apply)
- Which pods have no policy coverage? (static)
- Which allow rules have never matched real traffic? (runtime, via Hubble)

Static analysis parses NetworkPolicy YAML into a directed reachability graph
with correct upstream semantics. Runtime analysis streams flows from
Cilium/Hubble and diffs observed traffic against what policy permits.

## What it catches

**Uncovered pods (silent default-allow)**

[NO_INGRESS_POLICY] demo/redis-cache
No policy selects this pod — reachable from all 5 pods in namespace
Suggested: add an ingress policy or an explicit deny-all


**Over-permissive rules (never used)**

[OVERPERMISSION] demo/api-policy
allow frontend -> api-server:9090 (0 flows observed)
Policy permits 7 edges; live traffic uses 4


**Blast radius**

$ analyzer --entry frontend
Reachable: 4/5 pods (infection rate 0.80)
Max depth: 3 (frontend -> api-server -> order-service -> database)
Articulation point: api-server (removing it isolates 3 pods)


**Reachability with reason**

$ query -src nginx-ingress -dst user-db
BLOCKED at hop 2
nginx-ingress -> api-gateway OK (TCP/8080)
api-gateway -> user-db DENIED: user-db ingress isolated,
no rule matches source labels app=gateway

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
- Correct NetworkPolicy semantics: per-pod per-direction isolation tracking
  - Pods not selected by any policy get **default-allow** (not implicit deny)
  - Both egress (source) and ingress (destination) sides checked for every edge
  - Asymmetric `policyTypes` inference: omitted = always Ingress; Egress only if egress rules exist
  - Empty/omitted `ports` field correctly treated as "all ports"
  - Empty `from`/`to` in rules means "all pods"
- Default-allow gap detection: reports pods lacking ingress/egress policy coverage
- BFS-based attack propagation simulation from any entry point
- Critical path detection (longest attack chain)
- Articulation point (cut vertex) detection
- Policy compliance checking (including NO_INGRESS_POLICY for uncovered pods)
- Graphviz visualization export (dashed red edges for default-allow paths)
- Reachability query CLI: check if pod A can reach pod B with path and port details

**Dynamic analysis (Phase 2)**
- Real-time flow collection from Cilium/Hubble via gRPC
- Live traffic topology construction
- Policy vs actual traffic comparison (overpermission detection)
- Dropped connection attempt tracking
- Prometheus metrics exposure for Grafana dashboards
- Namespace-level filtering (demo namespace only)

## Prerequisites

- Docker Desktop
- Go 1.26+
- kubectl
- Kind
- Cilium CLI
- Hubble CLI
- Helm (for Prometheus + Grafana)

## Quick Start

### Can do One-click deployment
```bash
.\deploy.ps1
```

### 1. Create the Kind cluster

```bash
kind create cluster --config kind-config.yaml --name netpol-lab
```

### 2. Install Cilium with Hubble

```bash
cilium install --set hubble.relay.enabled=true --set hubble.ui.enabled=true
cilium status --wait
```

If you are using an VPN, you can manually pull the image in advance and then load it into Kind:
```bash
docker pull quay.io/cilium/cilium:v1.xx.x
kind load docker-image <image> --name netpol-lab
```
Using this to find your cilium version:
```bash
helm list -n kube-system
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
go run ./cmd/analyzer
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

## Reachability Query

Check if a source pod can reach a destination pod:

```bash
go run ./cmd/query -src nginx-ingress -dst user-db -f testdata/policies.yaml
```

Output shows the full path with port details at each hop, or the reason traffic is blocked.

## Project Structure

```
k8s-netpol-analyzer/
├── cmd/
│   ├── analyzer/main.go     # Entry point: static analysis + dynamic service
│   └── query/main.go        # CLI reachability query tool
├── internal/
│   ├── graph/
│   │   ├── types.go         # Core types: Edge, PortRange, PodIsolation
│   │   ├── build.go         # Edge building with both-sides validation
│   │   ├── build_test.go    # 13 unit tests for edge semantics
│   │   ├── util.go          # LabelStr, Dedup with port merging
│   │   ├── analyzer.go      # BFS propagation simulation
│   │   ├── query.go         # Reachability query with path tracing
│   │   └── critical.go      # Articulation point detection, risk report
│   ├── policy/
│   │   ├── parser.go        # YAML parsing, returns edges + isolation map
│   │   └── parser_test.go   # Integration test against policies.yaml
│   ├── compliance/
│   │   └── compliance.go    # Policy compliance checking (6 rules)
│   ├── hubble/
│   │   └── collector.go     # Hubble gRPC client, flow collection
│   ├── metrics/
│   │   └── metrics.go       # Prometheus metrics + HTTP server
│   └── visualise/
│       └── visualize.go     # Graphviz DOT export
├── testdata/                 # Sample NetworkPolicy YAML files (22 policies)
├── kind-config.yaml          # Kind cluster configuration
├── test-apps.yaml            # Test pod definitions
├── test-services.yaml        # Test service definitions
├── test-netpol.yaml          # NetworkPolicy rules for demo namespace
└── netpol-scrape.yaml        # Prometheus ServiceMonitor configuration
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

## NetworkPolicy Semantics

The analyzer implements correct Kubernetes NetworkPolicy semantics:

| Scenario | Ingress | Egress |
|----------|---------|--------|
| No policy selects pod | Default allow (all traffic) | Default allow (all traffic) |
| Policy selects pod with `policyTypes: [Ingress]` | Isolated (only matching rules) | Default allow |
| Policy selects pod with `policyTypes: [Egress]` | Default allow | Isolated (only matching rules) |
| Policy with no rules (deny-all) | All denied | All denied |
| Rule with empty `from`/`to` | All pods match | All pods match |
| Rule with empty `ports` | All ports allowed | All ports allowed |

An edge A→B exists only when **both** sides permit the connection:
- A's egress side allows traffic to B (default-allow or explicit rule)
- **AND** B's ingress side allows traffic from A (default-allow or explicit rule)

When both sides have explicit port constraints, the effective ports are the **intersection**.

## Topology Visualization

![topology](docs/topology.png)

Node borders distinguish between three isolation states: solid blue (explicitly authorized), dashed orange (inbound allowed by default, without policy control), and gray (fully isolated). A dashed border indicates that the connection exists due to a default allow rule rather than being explicitly approved by a policy.


![spread](docs/spread.png)

Click any node to view lateral movement paths; color intensity corresponds to the BFS propagation level.

## Future Work

[] Containerize the Go program and deploy as a pod in the cluster
[] Add anomaly detection based on traffic pattern changes
[] Implement ML-based policy optimization suggestions
[x] Export Grafana dashboard as JSON for version control
[] Add support for multiple namespaces

[] Add hubble_test.go
[] Change language(in graph) to English
[] Update generated graph's struct