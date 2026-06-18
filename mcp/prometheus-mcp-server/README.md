k create ns proemtheus-mcp-server

helm install prometheus-mcp-server \
  oci://ghcr.io/pab1it0/charts/prometheus-mcp-server \
  -f values.yaml -n proemtheus-mcp-server