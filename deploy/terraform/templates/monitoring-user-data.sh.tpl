#!/bin/bash
# Monitoring stack bootstrap.
set -euo pipefail

# Install Docker
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io
systemctl enable --now docker

# Prometheus
cat > /etc/prometheus.yml << 'PROM_EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: providapt
    static_configs:
      - targets:
%{ for ip in split(" ", providapt_ips) ~}
          - ${ip}:8080
%{ endfor ~}
    metrics_path: /metrics

  - job_name: node
    static_configs:
      - targets:
%{ for ip in split(" ", providapt_ips) ~}
          - ${ip}:9100
%{ endfor ~}
PROM_EOF

docker rm -f prometheus 2>/dev/null || true
docker run -d \
  --name prometheus \
  --restart unless-stopped \
  --network host \
  -v /etc/prometheus.yml:/etc/prometheus/prometheus.yml:ro \
  prom/prometheus:v2.54.1 \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus

# Grafana
mkdir -p /var/lib/grafana

docker rm -f grafana 2>/dev/null || true
docker run -d \
  --name grafana \
  --restart unless-stopped \
  --network host \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  -e GF_INSTALL_PLUGINS=grafana-piechart-panel \
  -v /var/lib/grafana:/var/lib/grafana \
  grafana/grafana:11.2.0

echo "Monitoring stack bootstrap complete"
echo "Prometheus: http://$(curl -s http://checkip.amazonaws.com):9090"
echo "Grafana:    http://$(curl -s http://checkip.amazonaws.com):3000"
