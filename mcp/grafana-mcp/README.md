
kubectl create namespace grafana-mcp

read -rsp 'Grafana Service-Account-Token: ' GRAFANA_MCP_TOKEN
echo
printf '%s' "$GRAFANA_MCP_TOKEN" |
  kubectl -n grafana-mcp create secret generic grafana-mcp-credentials \
    --from-file=token=/dev/stdin
unset GRAFANA_MCP_TOKEN

helm repo add grafana-community https://grafana-community.github.io/helm-charts
helm repo update

helm upgrade --install grafana-mcp grafana-community/grafana-mcp \
  --namespace grafana-mcp \
  --values values.yaml

kubectl -n grafana-mcp get pods,svc,ingress

# Durch die tatsächliche Traefik-IP ersetzen
TRAEFIK_IP='192.168.1.42'

curl --noproxy '*' --resolve "grafana-mcp.rke2-cluster1.berger.ph:80:${TRAEFIK_IP}" --connect-timeout 4 --max-time 5 -i http://grafana-mcp.rke2-cluster1.berger.ph/mcp




