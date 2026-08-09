# Quick Start

This guide gives operators a short path from a fresh Linux host to the first dashboard, alert list, and provenance trace.

## 1. Verify the Host

```bash
uname -r
test -r /sys/kernel/btf/vmlinux && echo "BTF available"
make verify-env
```

Recommended baseline:

- Linux kernel 5.8 or later; 5.11 or later for BPF LSM.
- `clang`, `llvm-strip`, `libbpf`, and `bpftool` installed.
- Go 1.25 or later for source builds.
- PostgreSQL configured for production deployments.

## 2. Install or Build

For local evaluation:

```bash
make install-deps
make build-ebpf
make build-userspace
sudo make install-local
```

For release packages, use the release artifact matching the target distribution:

```bash
sudo apt install ./providapt_<version>_amd64.deb
sudo rpm -Uvh ./providapt-<version>.x86_64.rpm
```

## 3. Configure

Start from the local or production template:

```bash
sudo mkdir -p /etc/providapt
sudo cp examples/config/providapt.local.toml /etc/providapt/providapt.toml
providaptctl -config-check -config /etc/providapt/providapt.toml
```

For production, replace every customer-specific value in `examples/config/providapt.production.yaml`, including API keys, TLS paths, CORS origins, SIEM token, and upgrade signatures.

## 4. Start the Services

```bash
sudo systemctl enable --now providapt.service
sudo systemctl status providapt.service --no-pager
```

If running without systemd:

```bash
sudo providaptd -config /etc/providapt/providapt.toml
```

## 5. Open the Console

Open the control-plane dashboard:

```text
http://<server>:18080/
```

Use the dashboard to check:

- control-plane health and version status
- fleet agent status
- policy draft and publish state
- delivery health and SIEM queue status
- alert workflow and investigation entry points

## 6. Confirm Data Flow

Generate a simple event:

```bash
curl -fsS https://example.com >/tmp/providapt-quickstart.out
cat /tmp/providapt-quickstart.out >/dev/null
rm -f /tmp/providapt-quickstart.out
```

Check API state:

```bash
curl -s http://localhost:18080/api/v1/status
curl -s http://localhost:18080/api/v1/alerts
curl -s http://localhost:18080/api/v1/graph/export
```

## 7. View a Provenance Trace

From the dashboard:

1. Open `Alert Workflow`.
2. Select an alert or investigation candidate.
3. Click `Trace SVG` or `Download Markdown`.
4. Use graph filters to focus on process, file, network, or host nodes.

From the API:

```bash
curl "http://localhost:18080/api/v1/investigation/report?pid=<pid>&direction=backward&depth=5"
```

## 8. Stop and Clean Up

```bash
sudo systemctl stop providapt.service
sudo rm -rf /var/log/providapt /var/lib/providapt
```
