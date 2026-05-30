# deploy.ps1
Write-Host "=== Creating Kind cluster ==="
kind create cluster --config kind-config.yaml --name netpol-lab

Write-Host "=== Installing Cilium + Hubble ==="
cilium install --set hubble.relay.enabled=true --set hubble.ui.enabled=true
cilium status --wait

Write-Host "=== Deploying test environment ==="
kubectl apply -f test-apps.yaml
kubectl apply -f test-services.yaml
kubectl apply -f test-netpol.yaml
kubectl apply -f analyzer-netpol.yaml

Write-Host "=== Installing Prometheus + Grafana ==="
helm install monitoring prometheus-community/kube-prometheus-stack `
  --namespace monitoring --create-namespace `
  --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false `
  --set grafana.adminPassword=admin

Write-Host "=== Building and deploying analyzer ==="
docker build -t netpol-analyzer:latest .
kind load docker-image netpol-analyzer:latest --name netpol-lab
helm install analyzer ./helm-chart -n demo --create-namespace

Write-Host "=== Waiting for pods ==="
kubectl wait --for=condition=ready pod -l app=netpol-analyzer -n demo --timeout=120s

Write-Host "=== Done! ==="
Write-Host "Grafana: kubectl port-forward -n monitoring svc/monitoring-grafana 3000:80"
Write-Host "Login: admin / admin"