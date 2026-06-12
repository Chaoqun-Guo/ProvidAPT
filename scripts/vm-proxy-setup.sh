#!/usr/bin/env bash
# ── vm-proxy-setup.sh ─────────────────────────────────────────────
# ProvidAPT Linux VM proxy configuration
#
# Run this script ON the Linux VM (192.168.150.131, user: camflow)
# to configure outbound network access through the Windows host proxy.
#
# Usage:
#   scp scripts/vm-proxy-setup.sh camflow@192.168.150.131:~/
#   ssh camflow@192.168.150.131 "bash ~/vm-proxy-setup.sh"
#
# Prerequisites:
#   - Windows host proxy at http://127.0.0.1:7890 must listen on
#     0.0.0.0 (not just 127.0.0.1) so the VM can reach it.
#   - VM can reach the host at 192.168.150.1 (VirtualBox NAT gateway)
#     or 10.0.2.2 (default VirtualBox NAT).
# ──────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Detect host gateway ──────────────────────────────────────────
# Try common VirtualBox NAT gateway addresses
HOST_IP=""
for ip in 192.168.150.1 10.0.2.2 172.16.150.1; do
    if ping -c 1 -W 1 "$ip" &>/dev/null; then
        HOST_IP="$ip"
        break
    fi
done

if [ -z "$HOST_IP" ]; then
    # Fallback: use the default gateway
    HOST_IP=$(ip route | awk '/default/ {print $3; exit}')
    if [ -z "$HOST_IP" ]; then
        echo "ERROR: Cannot detect host gateway. Set PROXY_HOST manually."
        exit 1
    fi
fi

PROXY_PORT="${PROXY_PORT:-7890}"
PROXY_URL="http://${HOST_IP}:${PROXY_PORT}"
echo "==> Host proxy detected at: ${PROXY_URL}"

# ── 1. Shell environment proxy ──────────────────────────────────
cat > /etc/profile.d/proxy.sh <<'PROXYEOF'
#!/usr/bin/env bash
export HTTP_PROXY="__PROXY_URL__"
export HTTPS_PROXY="__PROXY_URL__"
export http_proxy="__PROXY_URL__"
export https_proxy="__PROXY_URL__"
export NO_PROXY="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,.local"
export no_proxy="localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,.local"
PROXYEOF
sed -i "s|__PROXY_URL__|${PROXY_URL}|g" /etc/profile.d/proxy.sh
chmod +x /etc/profile.d/proxy.sh
echo "==> Shell proxy configured in /etc/profile.d/proxy.sh"

# ── 2. Go proxy ──────────────────────────────────────────────────
# Configure Go to use the host proxy AND a fallback direct proxy
go env -w GOPROXY="https://proxy.golang.org,direct"
go env -w GOFLAGS="-count=1"
echo "==> Go proxy configured (GOPROXY=https://proxy.golang.org,direct)"
echo "    NOTE: Go will use HTTP_PROXY for outbound requests."

# ── 3. DNF/YUM proxy ────────────────────────────────────────────
if command -v dnf &>/dev/null; then
    cat > /etc/dnf/dnf.conf <<'DNFPROXY'
[main]
proxy=__PROXY_URL__
DNFPROXY
    sed -i "s|__PROXY_URL__|${PROXY_URL}|g" /etc/dnf/dnf.conf
    echo "==> DNF proxy configured"
fi

# ── 4. Git proxy ─────────────────────────────────────────────────
sudo -u "$USER" git config --global http.proxy "${PROXY_URL}" 2>/dev/null || true
sudo -u camflow git config --global http.proxy "${PROXY_URL}" 2>/dev/null || true
echo "==> Git proxy configured"

# ── 5. Verify connectivity ──────────────────────────────────────
echo "==> Testing proxy connectivity..."
if curl -s --proxy "${PROXY_URL}" --max-time 5 https://proxy.golang.org/ >/dev/null 2>&1; then
    echo "OK: Go proxy reachable via ${PROXY_URL}"
else
    echo "WARNING: Cannot reach Go proxy via ${PROXY_URL}"
    echo "  Check that:"
    echo "  1. Windows proxy is running on port ${PROXY_PORT}"
    echo "  2. Proxy is listening on 0.0.0.0 (not 127.0.0.1)"
    echo "  3. Windows firewall allows inbound on port ${PROXY_PORT}"
    echo ""
    echo "  To fix Windows proxy binding:"
    echo "    - If using Clash/Clash Verge: Settings -> Allow LAN"
    echo "    - Or manually: netsh interface portproxy add v4tov4 ..."
fi

echo ""
echo "==> Proxy setup complete."
echo "    Log out and back in, or run:  source /etc/profile.d/proxy.sh"
echo "    Then test: curl -I https://google.com"
