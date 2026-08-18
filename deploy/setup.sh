# setup.sh
#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="netpol-lab"
CILIUM_VERSION="v1.19.5"

echo "=== Creating Kind cluster ==="
kind create cluster --config kind-config.yaml --name "$CLUSTER_NAME"

load_image() {
    local img=$1
    local tar="/tmp/$(echo "$img" | tr '/:' '__').tar"
    docker pull "$img"
    docker save "$img" -o "$tar"
    kind load image-archive "$tar" --name "$CLUSTER_NAME"
    rm -f "$tar"
}

for img in \
    "quay.io/cilium/cilium:${CILIUM_VERSION}" \
    "quay.io/cilium/operator-generic:${CILIUM_VERSION}" \
    "quay.io/cilium/hubble-relay:${CILIUM_VERSION}"
do
    load_image "$img"
done

kind create cluster --config kind-config.yaml --name netpol-lab
cilium install --set hubble.relay.enabled=true --set hubble.ui.enabled=true
   # 坑:重建集群后必须重装 cilium,否则连着旧 API Server IP
cilium status --wait

# when reload cluster, u need to reload the images, otherwise cilium will not work

cd /mnt/d/projects/k8s-netpol-analyzer
kubectl apply -f ./testdata/test-apps.yaml
kubectl apply -f ./testdata/test-services.yaml
kubectl apply -f ./testdata/test-netpol.yaml
kubectl apply -f ./testdata/analyzer-netpol.yaml

# grep -r "HUBBLE_ADDR" ./deploy/helm-chart/
# grep -A3 "hubble:" ./deploy/helm-chart/values.yaml

# check if the required commands are available
for cmd in docker kind kubectl helm cilium; do
    command -v "$cmd" >/dev/null || { echo "缺少 $cmd"; exit 1; }
done

docker build -t netpol-analyzer:latest .
docker save netpol-analyzer:latest -o analyzer.tar
kind load image-archive analyzer.tar --name netpol-lab
   # 坑:用 image-archive,不用 kind load docker-image


helm upgrade --install analyzer ./deploy/helm-chart -n demo --create-namespace \
     --set serviceMonitor.enabled=false --set grafana.dashboardEnabled=false
   # Attention: monitoring 相关资源依赖 kube-prometheus-stack

   # helm install analyzer ./deploy/helm-chart -n demo --create-namespace
