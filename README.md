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

#### Basic, continue:
```bash
kubectl -n demo exec deploy/<client> -- \
  sh -c 'while true; do wget -qO- --timeout=2 http://<target>:80 >/dev/null; sleep 1; done' &
```
#### Be denied:
```bash
kubectl -n demo exec deploy/<client> -- \
  sh -c 'while true; do wget -qO- --timeout=2 http://<被禁止的target>:80 >/dev/null 2>&1; sleep 2; done' &
```
#### High frequency & Low Frequency:
```bash
# high
kubectl -n demo exec deploy/<clientA> -- \
  sh -c 'while true; do wget -qO- --timeout=1 http://<target>; sleep 0.2; done' &

# low
kubectl -n demo exec deploy/<clientB> -- \
  sh -c 'while true; do wget -qO- --timeout=2 http://<target>; sleep 5; done' &
```

#### Out of Clusters:
```bash
kubectl -n demo exec deploy/<client> -- \
  sh -c 'while true; do wget -qO- --timeout=3 http://1.1.1.1 >/dev/null 2>&1; sleep 3; done' &
```

#### See ports diff:
```bash
kubectl -n demo exec deploy/<client> -- \
  sh -c 'while true; do nc -z -w2 <target> 5432; sleep 2; done' &
```

#### Others:
```bash
kubectl exec -n demo frontend -- wget -qO- --timeout=2 api-server.demo.svc.cluster.local
kubectl exec -n demo api-server -- wget -qO- --timeout=2 order-service.demo.svc.cluster.local
kubectl exec -n demo order-service -- wget -qO- --timeout=2 database.demo.svc.cluster.local
kubectl exec -n demo api-server -- wget -qO- --timeout=2 redis-cache.demo.svc.cluster.local
```

### 9. View the dashboard

Open `http://localhost:3000` (admin / admin123) and view the NetPol Analyzer dashboard.

### 10. Frontend Static Topoloty Visualiztion
cd D:\projects\k8s-netpol-analyzer\web
python -m http.server 8000

open http://localhost:8000/topology.html in web server

If you need a new JSON, do these follows:
cd D:\projects\k8s-netpol-analyzer
go run ./cmd/analyzer

### 11. CLI query
default: /testdata/policies.yaml

examples:
.\query -src frontend -dst database -f .\testdata\test-netpol.yaml
or
.\query -src frontend -dst database -f testdata/test-netpol.yaml

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

## Over-Permission Analysis

Static analysis answers "what *could* talk to what". Hubble answers "what *did*". The difference is over-permission: rules that grant access nothing uses.

```bash
go run ./cmd/diff -f testdata/policies.yaml -collect 30m -min-window 30m
```

| Flag | Default | Meaning |
|---|---|---|
| `-f` | `testdata/policies.yaml` | Policy file |
| `-hubble` | `localhost:4245` | Hubble relay address |
| `-collect` | `60s` | How long to collect flows |
| `-min-window` | `30m` | Minimum window for a finding to be trustworthy |
| `-n` | *(all)* | Restrict to one namespace |

Every permitted `(src, dst, port, proto)` tuple lands in one of three classes:

- **`confirmed`** — permitted and observed forwarding.
- **`overpermissive`** — permitted, but no traffic in the window.
- **`unexpected_drop`** — *not* permitted, but traffic was observed being dropped. Either the policy is tighter than what the workloads actually do, or something is probing a path it should not.

Findings name their source policies as `namespace/name`, so "this edge is unused" comes with the answer to "which YAML do I edit".

### Comparison is per port, not per node pair

The most common form of over-permission is a rule opening a port range where only one port is ever used. Matching on the node pair alone reports such an edge as fully confirmed and misses the finding entirely, so ports are part of the comparison key. An edge with one used and one unused port is reported as over-permissive, and names the unused port.

A rule with no `ports:` (or a default-allow edge) permits everything, so it stays over-permissive even when some traffic confirms it — there is no bound to satisfy.

### Why observation is tracked separately from the ring buffer

`internal/flowstat` keeps an append-only table of observed edges, independent of the Hubble ring buffer. The ring buffer evicts old records, so a low-frequency edge — a nightly batch job reaching a database — gets flushed out by high-volume traffic and would then look like it never happened. Deriving "was this edge ever used?" from the ring buffer produces false over-permission findings. The ring buffer keeps flow detail and is allowed to forget; the tracker keeps one counter per edge and never does.

### Trust the window before trusting the finding

A short window cannot distinguish "never used" from "not used yet". Every report carries `window.sufficient`, and the CLI, the API and the web view all warn when the collection period is below `-min-window`. **Do not delete a policy based on an insufficient window** — set `-collect` to span at least one full cycle of your periodic workloads.

### Node identity

Observed flows are mapped onto graph nodes through the same `LabelStr` definition the policy parser uses, via its inverse (`graph.ResolveNodeID`). Resolution prefers the pod's Kubernetes labels and falls back to matching the pod-name prefix when Hubble ships flows without label metadata. Endpoints that resolve to nothing — cluster-external traffic, host identities, workloads no policy mentions — are excluded rather than guessed at.

### Web view

`cmd/analyzer` serves the topology and a live diff on port 9090:

```bash
go run ./cmd/analyzer          # then open http://localhost:9090/topology.html
```

- `GET /api/diff` — topology JSON with per-edge `class`, `forwarded`, `dropped`, `policyRefs`, `unusedPorts`, plus the observation window.
- Confirmed edges render solid green with width scaled by `log10(forwarded)`; over-permissive edges grey dashed; unexpected drops red dotted.
- Clicking an edge shows its unused ports and source policies.
- `DIFF_MIN_WINDOW` (e.g. `1h`) overrides the sufficiency threshold.

Cytoscape is vendored under `web/vendor/` — in-cluster deployments generally have no CDN egress.

## Project Structure

```
k8s-netpol-analyzer/
├── cmd/
│   ├── analyzer/main.go     # Entry point: static analysis + dynamic service + /api/diff
│   ├── diff/main.go         # CLI over-permission report
│   └── query/main.go        # CLI reachability query tool
├── internal/
│   ├── graph/
│   │   ├── types.go         # Core types: Graph, Edge, PortRange, PodIsolation
│   │   ├── build.go         # Edge building with both-sides validation + policy refs
│   │   ├── build_test.go    # 13 unit tests for edge semantics
│   │   ├── diff.go          # CompareTopologies: static vs observed
│   │   ├── util.go          # LabelStr and its inverse, Dedup with port merging
│   │   ├── analyzer.go      # BFS propagation simulation
│   │   ├── query.go         # Reachability query with path tracing
│   │   └── critical.go      # Articulation point detection, risk report
│   ├── flowstat/
│   │   └── tracker.go       # Append-only observed-edge table (no internal deps)
│   ├── policy/
│   │   ├── parser.go        # YAML parsing, returns edges + isolation map
│   │   └── parser_test.go   # Integration test against policies.yaml
│   ├── compliance/
│   │   └── compliance.go    # Policy compliance checking (6 rules)
│   ├── hubble/
│   │   ├── hubble.go        # Hubble gRPC client, flow collection
│   │   └── edgekey.go       # Flow -> graph node resolution
│   ├── metrics/
│   │   └── metrics.go       # Prometheus metrics + HTTP server
│   └── visualise/
│       ├── visualize.go     # Graphviz DOT export
│       └── json.go          # JSON export with diff overlay
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

监控集成默认关闭，装了 kube-prometheus-stack 后用 --set serviceMonitor.enabled=true 开启

## Attention
1. The clusters cannot be stopped in desktop, or the status about k8s will not recover fully. Please delete and reconstruct clusters for each time.
2. Monitoring integration is disabled by default; after installing kube-prometheus-stack, enable it using `--set serviceMonitor.enabled=true`.

## Future Work

[] Containerize the Go program and deploy as a pod in the cluster
[] Add anomaly detection based on traffic pattern changes
[] Implement ML-based policy optimization suggestions
[x] Export Grafana dashboard as JSON for version control
[] Add support for multiple namespaces

[] Add hubble_test.go
[] Change language(in graph) to English
[] Update generated graph's struct