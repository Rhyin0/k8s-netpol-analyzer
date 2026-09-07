# -*- coding: utf-8 -*-
"""Generate docs/architecture.svg — hand-laid-out project architecture diagram.

Usage:  python3 docs/gen_architecture.py
PNG（docs/architecture.png）由该 SVG 光栅化得到，可用任意工具导出。
"""
import html
import os

W, H = 2170, 1450
FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Hiragino Sans GB','Noto Sans SC','Microsoft YaHei',sans-serif"
MONO = "'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace"

INK = "#0f172a"
MUTED = "#475569"
LINE = "#64748b"
BUILD = "#94a3b8"

C_APP = ("#dbeafe", "#2563eb")      # 构建程序的文件
C_CLU = ("#ffedd5", "#ea580c")      # 构建集群的文件
C_IN = ("#ede9fe", "#7c3aed")       # 分析输入
C_RUN = ("#dcfce7", "#16a34a")      # 运行时业务组件
C_OBS = ("#fef9c3", "#ca8a04")      # 可观测组件
C_K8S = ("#e2e8f0", "#475569")      # k8s 基础设施
C_PANEL = ("#ffffff", "#cbd5e1")

out = []
def add(s): out.append(s)

def esc(s): return html.escape(s, quote=True)

def tw(s, fs):
    w = 0.0
    for ch in s:
        w += fs * (1.0 if ord(ch) > 0x2E80 else 0.55)
    return w

def rect(x, y, w, h, fill, stroke, dash=None, rx=6, sw=1.2, op=1.0):
    d = f' stroke-dasharray="{dash}"' if dash else ''
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
        f'fill-opacity="{op}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

def text(x, y, s, fs=12.5, fill=INK, anchor="middle", weight="normal", family=FONT):
    add(f'<text x="{x}" y="{y}" font-family="{family}" font-size="{fs}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{esc(s)}</text>')

def box(x, y, w, lines, fill, stroke, fs=12.5, dash=None, lead=16.5, pad=9, bold_first=False):
    h = pad * 2 + lead * len(lines) - (lead - fs)
    rect(x, y, w, h, fill, stroke, dash=dash)
    ty = y + pad + fs - 1
    for i, ln in enumerate(lines):
        text(x + w / 2, ty + i * lead, ln, fs=fs,
             weight=("bold" if (bold_first and i == 0) else "normal"),
             fill=INK if (bold_first and i == 0) else INK)
    return h

def panel(x, y, w, h, title, stroke="#94a3b8", fill="#f8fafc", dash=None, tfs=15):
    rect(x, y, w, h, fill, stroke, dash=dash, rx=10, sw=1.6)
    text(x + 14, y + 24, title, fs=tfs, weight="bold", anchor="start", fill="#1e293b")

def label(x, y, s, fs=11, fill=MUTED, anchor="middle"):
    lines = s.split("\n")
    wmax = max(tw(l, fs) for l in lines)
    hh = len(lines) * (fs + 3) + 4
    if anchor == "middle":
        rx = x - wmax / 2 - 4
    elif anchor == "start":
        rx = x - 4
    else:
        rx = x - wmax - 4
    add(f'<rect x="{rx:.1f}" y="{y - fs - 2:.1f}" width="{wmax + 8:.1f}" height="{hh:.1f}" '
        f'rx="3" fill="#ffffff" fill-opacity="0.93"/>')
    for i, l in enumerate(lines):
        text(x, y + i * (fs + 3), l, fs=fs, fill=fill, anchor=anchor)

def arrow(points, color=LINE, dashed=False, sw=1.6, head=True, back=False):
    pts = " ".join(f"{p[0]},{p[1]}" for p in points)
    d = ' stroke-dasharray="6 4"' if dashed else ''
    marker = ' marker-end="url(#ah)"' if head else ''
    if color == BUILD:
        marker = ' marker-end="url(#ahb)"' if head else ''
    if back:
        marker += ' marker-start="url(#ah)"'
    add(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="{sw}" '
        f'stroke-linejoin="round" stroke-linecap="round"{d}{marker}/>')

# ---------------------------------------------------------------- canvas
add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
add('<defs>')
add(f'<marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
    f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{LINE}"/></marker>')
add(f'<marker id="ahb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
    f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{BUILD}"/></marker>')
add('</defs>')
rect(0, 0, W, H, "#ffffff", "#ffffff", rx=0, sw=0)
text(W / 2, 34, "k8s-netpol-analyzer · 项目整体架构 / Project Architecture", fs=22, weight="bold")
text(W / 2, 54, "源码文件 → 构建产物 → 集群内节点位置 → 运行时数据流（① … ⑩）与端口暴露",
     fs=13, fill=MUTED)

# ================================================================ 1. REPO
panel(16, 70, 320, 1352, "① 源码仓库 Repository")

panel(24, 100, 304, 400, "A · 构建【程序】的文件", stroke=C_APP[1], fill="#f1f7ff", tfs=13)
BX, BW = 34, 284
y = 130
h = box(BX, y, BW, ["cmd/analyzer/main.go", "cmd/query/main.go"], *C_APP); y += h + 8
h = box(BX, y, BW, ["internal/policy · internal/graph",
                    "internal/hubble · internal/flowstat",
                    "internal/metrics · internal/compliance",
                    "internal/visualise"], *C_APP); y += h + 8
h = box(BX, y, BW, ["web/topology.html", "web/vendor/cytoscape.min.js"], *C_APP); y += h + 8
h = box(BX, y, BW, ["go.mod · go.sum"], *C_APP); y += h + 8
A5_Y = y
h = box(BX, y, BW, ["Dockerfile", "多阶段构建 · EXPOSE 9090"], *C_APP); y += h + 8
h = box(BX, y, BW, [".github/workflows/ci.yml", "gofmt · vet · build · test"], *C_APP)

IMG_Y = 512
IMG_H = box(24, IMG_Y, 304, ["🐳  netpol-analyzer:latest",
                             "docker build → docker save",
                             "kind load image-archive"], *C_RUN, bold_first=True)

panel(24, 588, 304, 430, "B · 构建【测试集群】的文件", stroke=C_CLU[1], fill="#fff8f1", tfs=13)
y = 618
B1_Y = y
h = box(BX, y, BW, ["deploy/kind-config.yaml",
                    "1 control-plane + 1 worker",
                    "disableDefaultCNI: true"], *C_CLU); y += h + 7
B2_Y = y
h = box(BX, y, BW, ["deploy/setup.sh · deploy/deploy.ps1", "一键编排（不直接产出资源）"], *C_CLU); y += h + 7
B3_Y = y
h = box(BX, y, BW, ["testdata/test-apps.yaml", "testdata/test-services.yaml"], *C_CLU); y += h + 7
B4_Y = y
h = box(BX, y, BW, ["testdata/test-netpol.yaml", "testdata/analyzer-netpol.yaml"], *C_CLU); y += h + 7
B5_Y = y
h = box(BX, y, BW, ["deploy/helm-chart/",
                    "deployment · service",
                    "servicemonitor · grafana-dashboard"], *C_CLU, fs=11.5); y += h + 7
B6_Y = y
h = box(BX, y, BW, ["testdata/netpol-scrape.yaml", "testdata/netpol-metrics.yaml"], *C_CLU); y += h + 7
B7_Y = y
h = box(BX, y, BW, ["grafana-dashboard.json"], *C_CLU)

C1_Y = 1034
C1_H = box(24, C1_Y, 304, ["testdata/policies.yaml  (22 policies)",
                           "静态分析输入：宿主机 -f 参数",
                           "或镜像内 /app/testdata"], *C_IN)

# legend
LG_Y = 1116
panel(24, LG_Y, 304, 296, "图例 Legend", stroke="#cbd5e1", fill="#ffffff", tfs=13)
ly = LG_Y + 44
for fill, stroke, txt in [(C_APP[0], C_APP[1], "构建程序的文件"),
                          (C_CLU[0], C_CLU[1], "构建测试集群的文件"),
                          (C_IN[0], C_IN[1], "静态分析输入数据"),
                          (C_RUN[0], C_RUN[1], "运行时业务组件 / analyzer"),
                          (C_OBS[0], C_OBS[1], "可观测组件 Hubble·Prom·Grafana"),
                          (C_K8S[0], C_K8S[1], "Kubernetes / Cilium 基础设施")]:
    rect(38, ly - 11, 26, 15, fill, stroke, rx=3)
    text(74, ly, txt, fs=11.5, anchor="start", fill=MUTED)
    ly += 25
ly += 6
arrow([(40, ly - 4), (66, ly - 4)], color=LINE)
text(74, ly, "运行时数据流（编号 ① … ⑩）", fs=11.5, anchor="start", fill=MUTED)
ly += 24
arrow([(40, ly - 4), (66, ly - 4)], color=BUILD, dashed=True)
text(74, ly, "构建 / 部署 / 配置关系", fs=11.5, anchor="start", fill=MUTED)
ly += 24
text(38, ly, "端口标注形式  容器端口 → Service 端口", fs=11, anchor="start", fill=MUTED)
ly += 18
text(38, ly, "虚线边框 = 可选组件（集群内模式）", fs=11, anchor="start", fill=MUTED)

# ================================================================ 2. CLUSTER
panel(476, 70, 1164, 1352, "② Kind 集群  netpol-lab  （Docker Desktop 中的两个容器节点）",
      stroke="#7c3aed", fill="#fbfaff")

# --- row 1: physical nodes
panel(520, 106, 1090, 194, "物理节点层 · Kind node = docker 容器（cilium-agent 以 DaemonSet 落在每个节点）",
      stroke="#94a3b8", fill="#f1f5f9", tfs=12)
panel(536, 136, 540, 152, "Node 1 · netpol-lab-control-plane", stroke=C_K8S[1], fill="#ffffff", tfs=12)
box(552, 168, 240, ["kube-apiserver · etcd", "scheduler · controller-mgr"], *C_K8S, fs=11.5)
K2X, K2Y = 812, 168
box(K2X, K2Y, 248, ["cilium-agent (DaemonSet)", "eBPF datapath · 策略执行点"], *C_K8S, fs=11.5)
text(806, 276, "kube-system 组件默认落在此节点", fs=11, fill=MUTED)

panel(1096, 136, 498, 152, "Node 2 · netpol-lab-worker", stroke=C_K8S[1], fill="#ffffff", tfs=12)
K3X, K3Y = 1112, 168
box(K3X, K3Y, 248, ["cilium-agent (DaemonSet)", "eBPF datapath · 策略执行点"], *C_K8S, fs=11.5)
text(1360, 276, "demo / monitoring 的 Pod 主要调度到此节点", fs=11, fill=MUTED)

# --- row 2: kube-system
panel(520, 320, 1090, 150, "namespace: kube-system", stroke="#94a3b8", fill="#fffdf3", tfs=12)
box(552, 366, 240, ["cilium-operator"], *C_OBS)
box(820, 366, 200, ["hubble-ui（可选）"], *C_OBS)
HRX, HRY, HRW = 1230, 352, 360
HRH = box(HRX, HRY, HRW, ["Hubble Relay", "Deployment · container :4245",
                          "Service hubble-relay :80", "汇聚全集群 flow"], *C_OBS, bold_first=True)

# --- row 3: demo
panel(520, 490, 1090, 430, "namespace: demo   —   被分析对象 + analyzer 自身", stroke="#94a3b8",
      fill="#f4fdf7", tfs=12)
POD = dict(fs=12)
FE = (552, 600, 130); API = (722, 600, 130); ORD = (892, 600, 130); DB = (1062, 600, 120)
RDS = (722, 682, 130)
for (x, yy, w), name in [(FE, "frontend"), (API, "api-server"), (ORD, "order-service"),
                         (DB, "database"), (RDS, "redis-cache")]:
    box(x, yy, w, [name], *C_RUN, fs=12)
NPX, NPY = 552, 762
NPH = box(NPX, NPY, 300, ["NetworkPolicy ×N", "apiserver 下发 → cilium-agent 在 eBPF 执行"],
          *C_RUN, fs=11)
SMX, SMY = 552, 846
SMH = box(SMX, SMY, 300, ["ServiceMonitor netpol-analyzer",
                          "selector app=netpol-analyzer",
                          "port=metrics · interval=10s"], *C_OBS, fs=11)
ESX, ESY, ESW = 900, 750, 340
ESH = box(ESX, ESY, ESW, ["Service netpol-analyzer-external（headless）",
                          "+ 手写 Endpoints 192.168.65.254:9090",
                          "把宿主机进程伪装成集群内端点"], *C_OBS, fs=11)
PODX, PODY, PODW = 1300, 560, 290
PODH = box(PODX, PODY, PODW, ["analyzer Pod（集群内模式 · 可选）",
                              "container :9090", "env HUBBLE_ADDR"], *C_RUN, fs=11, dash="5 4")
ASX, ASY, ASW = 1300, 656, 290
ASH = box(ASX, ASY, ASW, ["Service analyzer-analyzer",
                          "port 9090 → targetPort metrics"], *C_RUN, fs=11)

# --- row 4: monitoring
panel(520, 940, 1090, 240, "namespace: monitoring   —   kube-prometheus-stack", stroke="#94a3b8",
      fill="#fffdf3", tfs=12)
POX, POY = 552, 1000
POH = box(POX, POY, 300, ["prometheus-operator", "把 ServiceMonitor 编译成", "scrape 配置"], *C_OBS, fs=11)
PRX, PRY, PRW = 912, 1000, 300
PRH = box(PRX, PRY, PRW, ["Prometheus", "svc prometheus-operated :9090", "每 10s 主动抓取"],
          *C_OBS, fs=11, bold_first=True)
GRX, GRY, GRW = 1290, 1000, 300
GRH = box(GRX, GRY, GRW, ["Grafana", "container :3000 → Service :80"], *C_OBS, fs=11, bold_first=True)
CMX, CMY = 1290, 1090
CMH = box(CMX, CMY, 300, ["ConfigMap  grafana_dashboard=1", "netpol-analyzer.json"], *C_OBS, fs=11)

# --- steps block
panel(520, 1200, 1090, 210, "数据流分步 Data flow", stroke="#cbd5e1", fill="#ffffff", tfs=12)
steps_l = [
    "①  demo Pod 之间产生业务流量 TCP/80（含被策略拒绝的探测）",
    "②  流量经所在 node 的 cilium-agent eBPF datapath，逐包判定 FORWARDED / DROPPED",
    "③  各节点 cilium-agent 把 flow 事件上报 Hubble Relay（gRPC :4244）",
    "④  analyzer 以 gRPC 订阅 Observer.GetFlows(Follow=true)",
    "      集群内 → hubble-relay.kube-system.svc:80",
    "      宿主机 → cilium hubble port-forward → localhost:4245",
    "⑤  flow 写入 ring buffer(4095) + flowstat 只增观测表",
    "      → CompareTopologies 求静态策略图与观测图的差集",
]
steps_r = [
    "⑥  Prometheus 按 ServiceMonitor 每 10s GET :9090/metrics",
    "      集群内走 Service analyzer-analyzer；宿主机走手写 Endpoints",
    "⑦  Grafana sidecar 自动挂载 ConfigMap 里的仪表盘 JSON",
    "⑧  Grafana 以 PromQL 查询 Prometheus 数据源",
    "⑨  kubectl port-forward svc/monitoring-grafana 3000:80",
    "      → 浏览器 localhost:3000",
    "⑩  analyzer 同一个 :9090 端口同时服务 /metrics、",
    "      /topology.html 与 /api/diff（页面优先取 /api/diff）",
]
sy = 1248
for st in steps_l:
    text(536, sy, st, fs=11.5, anchor="start", fill=INK); sy += 20
sy = 1248
for st in steps_r:
    text(1090, sy, st, fs=11.5, anchor="start", fill=INK); sy += 20

# ================================================================ 3. HOST
panel(1700, 70, 454, 700, "③ 开发机 / Docker Desktop 宿主机", stroke="#0ea5e9", fill="#f7fdff")
HX, HW = 1716, 422
BRY = 106
BRH = box(HX, BRY, HW, ["🌐 Browser", "localhost:3000  Grafana（admin/admin123）",
                        "localhost:9090  topology.html + /api/diff"], *C_RUN, fs=11, bold_first=True)
PFGY = 200
PFGH = box(HX, PFGY, HW, ["kubectl port-forward -n monitoring",
                          "svc/monitoring-grafana 3000:80"], *C_K8S, fs=11)
PFHY = 276
PFHH = box(HX, PFHY, HW, ["cilium hubble port-forward", "→ localhost:4245"], *C_K8S, fs=11)
LOY = 352
LOH = box(HX, LOY, HW, ["analyzer 进程（宿主机模式）",
                        "go run ./cmd/analyzer  ·  HTTP listen :9090",
                        "-f testdata/policies.yaml"], *C_RUN, fs=11, bold_first=True)
COY = 452
COH = box(HX, COY, HW, ["ring buffer 4095（保留明细，可淘汰）",
                        "flowstat 只增观测表（永不淘汰）",
                        "CompareTopologies：confirmed / overpermissive / unexpected_drop"],
          *C_RUN, fs=10.5)
OUY = 552
OUH = box(HX, OUY, HW, ["network-topology.dot", "web/network-topology.json"], *C_RUN, fs=11)
QRY_ = 628
QRH = box(HX, QRY_, HW, ["query CLI", "go run ./cmd/query -src .. -dst .. -f .."], *C_RUN, fs=11)

# ---- ports table
panel(1700, 792, 454, 630, "端口与暴露方式 Ports & exposure", stroke="#0ea5e9", fill="#ffffff")
rows = [
    ("cilium-agent", "4244", "仅集群内 · 上报 flow"),
    ("hubble-relay", "4245 → svc :80", "cilium hubble port-forward"),
    ("", "", "→ localhost:4245（gRPC）"),
    ("analyzer Pod", "9090 (metrics)", "svc analyzer-analyzer:9090"),
    ("", "", "ServiceMonitor 抓取"),
    ("analyzer 宿主机", "localhost:9090", "headless svc + 手写 Endpoints"),
    ("", "", "192.168.65.254:9090"),
    ("Prometheus", "9090", "prometheus-operated:9090"),
    ("Grafana", "3000 → svc :80", "port-forward 3000 → 浏览器"),
    ("demo 业务 Pod", "80", "仅集群内，产生被观测流量"),
]
ty = 832
text(1716, ty, "组件", fs=11.5, anchor="start", weight="bold")
text(1866, ty, "端口", fs=11.5, anchor="start", weight="bold")
text(1996, ty, "暴露方式", fs=11.5, anchor="start", weight="bold")
add(f'<line x1="1716" y1="{ty+8}" x2="2142" y2="{ty+8}" stroke="#cbd5e1" stroke-width="1"/>')
ty += 26
for a, b, c in rows:
    text(1716, ty, a, fs=10.5, anchor="start", fill=INK)
    text(1866, ty, b, fs=10.5, anchor="start", fill=MUTED, family=MONO)
    text(1996, ty, c, fs=10.5, anchor="start", fill=MUTED)
    ty += 20

ty += 14
text(1716, ty, "暴露给 Prometheus 的指标", fs=12, anchor="start", weight="bold"); ty += 8
add(f'<line x1="1716" y1="{ty}" x2="2142" y2="{ty}" stroke="#cbd5e1" stroke-width="1"/>'); ty += 22
metrics = [
    "netpol_flow_total{src,dst,port,verdict}",
    "netpol_pod_connections_in{pod}",
    "netpol_pod_connections_out{pod}",
    "netpol_spread_reachable{source}",
    "netpol_spread_max_depth{source}",
    "netpol_spread_infection_rate{source}",
    "netpol_policy_overpermission_edges",
    "netpol_policy_dropped_attempts",
]
for m in metrics:
    text(1716, ty, m, fs=10.5, anchor="start", fill=MUTED, family=MONO); ty += 19

ty += 12
text(1716, ty, "两种部署形态", fs=12, anchor="start", weight="bold"); ty += 8
add(f'<line x1="1716" y1="{ty}" x2="2142" y2="{ty}" stroke="#cbd5e1" stroke-width="1"/>'); ty += 22
for s in ["宿主机模式：go run + port-forward + netpol-scrape.yaml",
          "集群内模式：Helm chart + hubble-relay.kube-system.svc:80",
          "values.yaml 中 serviceMonitor/monitoring 默认 false，",
          "装好 kube-prometheus-stack 后需 --set 打开"]:
    text(1716, ty, s, fs=10.5, anchor="start", fill=MUTED); ty += 19

# ================================================================ arrows: build
def barrow(pts, lab=None, lx=None, ly_=None):
    arrow(pts, color=BUILD, dashed=True, sw=1.5)
    if lab:
        label(lx, ly_, lab, fs=10.5, fill="#64748b")

barrow([(324, B1_Y + 30), (356, B1_Y + 30), (356, 190), (520, 190)],
       "kind create cluster\n--config kind-config.yaml", 438, 164)
barrow([(328, IMG_Y + IMG_H / 2), (452, IMG_Y + IMG_H / 2), (452, 552), (520, 552)],
       "kind load image-archive\n+ helm → analyzer Pod", 468, 508)
barrow([(324, B3_Y + 22), (372, B3_Y + 22), (372, 618), (520, 618)],
       "kubectl apply\n5 Pod + 5 Service", 402, 596)
barrow([(328, C1_Y + C1_H / 2), (410, C1_Y + C1_H / 2), (410, 700), (520, 700)],
       "静态策略输入\n（-f / 镜像内 /app/testdata）", 452, 684)
barrow([(324, B4_Y + 22), (424, B4_Y + 22), (424, 792), (552, 792)],
       "kubectl apply\nNetworkPolicy", 470, 764)
barrow([(324, B5_Y + 30), (392, B5_Y + 30), (392, 868), (552, 868)],
       "helm upgrade --install analyzer -n demo\nDeployment · Service · ServiceMonitor", 484, 842)
barrow([(324, B6_Y + 22), (440, B6_Y + 22), (440, 908), (520, 908)],
       "kubectl apply\n外部 Endpoints", 462, 936)
barrow([(324, B7_Y + 14), (466, B7_Y + 14), (466, 1186), (1360, 1186), (1360, CMY + CMH)],
       "仪表盘 JSON 嵌入 ConfigMap", 900, 1180)

# ================================================================ arrows: runtime
# ① pod chain
arrow([(FE[0] + FE[2], 619), (API[0], 619)]); label(704, 592, "① TCP/80", fs=10.5)
arrow([(API[0] + API[2], 619), (ORD[0], 619)]); label(874, 592, "①", fs=10.5)
arrow([(ORD[0] + ORD[2], 619), (DB[0], 619)]); label(1044, 592, "①", fs=10.5)
arrow([(787, 638), (787, 682)]); label(800, 668, "①", fs=10.5, anchor="start")
arrow([(FE[0] + 40, 638), (FE[0] + 40, 726), (1122, 726), (1122, 640)],
      color="#dc2626", dashed=True)
label(880, 742, "① 被策略拒绝的探测  verdict=DROPPED", fs=10.5, fill="#dc2626")

# ② pods -> cilium-agent (eBPF datapath)
arrow([(787, 600), (787, 536), (1180, 536), (1180, 300), (1180, 232)])
label(980, 556, "② 每个数据包经过所在 node 的 eBPF datapath（策略执行点 + flow 产生点）", fs=10.5)

# ③ agents -> hubble relay
arrow([(1270, K3Y + 44), (1270, HRY)])
label(1282, 324, "③ gRPC :4244", fs=10.5, anchor="start")
arrow([(936, K2Y + 44), (936, 332), (1340, 332), (1340, HRY)])
label(1090, 326, "③", fs=10.5)

# ④ relay -> analyzer pod / host
arrow([(1445, HRY + HRH), (1445, PODY)])
label(1458, 494, "④ Observer.GetFlows\nFollow=true", fs=10.5, anchor="start")
arrow([(HRX + HRW, HRY + 40), (1650, HRY + 40), (1650, PFHY + 26), (HX, PFHY + 26)])
label(1618, HRY + 28, "④", fs=10.5, anchor="end")
arrow([(HX + 60, PFHY + PFHH), (HX + 60, LOY)])

# ⑤ local pipeline
arrow([(HX + 211, LOY + LOH), (HX + 211, COY)]); label(HX + 226, COY - 8, "⑤", fs=10.5, anchor="start")
arrow([(HX + 211, COY + COH), (HX + 211, OUY)])

# analyzer pod -> its Service
arrow([(1445, ASY), (1445, PODY + PODH)])

# ⑥ prometheus scrape
arrow([(1150, PRY), (1150, 930), (1445, 930), (1445, ASY + ASH)])
label(1270, 924, "⑥ scrape GET :9090/metrics 每 10s（集群内路径）", fs=10.5)
arrow([(1030, PRY), (1030, ESY + ESH)])
label(1040, 962, "⑥ 宿主机路径", fs=10.5, anchor="start")
arrow([(ESX + ESW, ESY + 42), (1662, ESY + 42), (1662, LOY + 30), (HX, LOY + 30)])
label(1460, ESY + 34, "192.168.65.254:9090", fs=10.5)

# ServiceMonitor -> operator -> prometheus
arrow([(702, SMY + SMH), (702, POY)], dashed=True, color=BUILD)
label(714, 930, "被 operator 读取", fs=10.5, anchor="start")
arrow([(POX + 300, POY + 32), (PRX, POY + 32)], dashed=True, color=BUILD)

# ⑦ configmap -> grafana
arrow([(1440, CMY), (1440, GRY + GRH)]); label(1452, CMY - 8, "⑦ sidecar", fs=10.5, anchor="start")
# ⑧ grafana -> prometheus
arrow([(GRX, GRY + 32), (PRX + PRW, GRY + 32)]); label(1250, GRY + 22, "⑧ PromQL", fs=10.5)
# ⑨ grafana -> port-forward -> browser
arrow([(GRX + GRW, GRY + 20), (1674, GRY + 20), (1674, PFGY + 26), (HX, PFGY + 26)])
label(1636, GRY + 10, "⑨", fs=10.5, anchor="end")
arrow([(HX + 375, PFGY), (HX + 375, BRY + BRH)])
# ⑩ analyzer -> browser
arrow([(PODX + PODW, PODY + 20), (1686, PODY + 20), (1686, BRY + 28), (HX, BRY + 28)])
label(1560, PODY + 10, "⑩ :9090", fs=10.5)
arrow([(HX + 110, LOY), (HX + 110, BRY + BRH)])
label(HX + 122, 344, "⑩", fs=10.5, anchor="start")

# scheduling relation note
label(1090, 484, "▲ Pod 调度关系：demo / monitoring 的 Pod 落在 worker 节点，kube-system 组件默认落在 control-plane 节点",
      fs=10.5, fill="#7c3aed")

add('</svg>')

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "architecture.svg")
with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("wrote", OUT)
