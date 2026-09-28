#!/usr/bin/env bash
# Installs server-monitor to /opt/server-monitor and starts it as a systemd service.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo ./install.sh"; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/server-monitor

echo "Installing packages (python3-venv, smartmontools)..."
apt-get update -qq
apt-get install -y -qq python3-venv smartmontools >/dev/null

echo "Copying files to $DEST..."
mkdir -p "$DEST" /var/lib/server-monitor
cp -r "$SRC"/app.py "$SRC"/collectors.py "$SRC"/alerts.py "$SRC"/requirements.txt "$SRC"/static "$DEST"/

echo "Creating Python environment..."
[[ -d "$DEST/venv" ]] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

[[ -f /etc/server-monitor.env ]] || cp "$SRC/server-monitor.env" /etc/server-monitor.env
cp "$SRC/server-monitor.service" /etc/systemd/system/server-monitor.service
systemctl daemon-reload
systemctl enable --now server-monitor
systemctl restart server-monitor

PORT=$(grep -E '^PORT=' /etc/server-monitor.env | cut -d= -f2); PORT=${PORT:-8088}
echo
echo "Done. Open http://$(hostname -I | awk '{print $1}'):$PORT"
command -v tailscale >/dev/null && echo "Over Tailscale: http://$(tailscale ip -4 2>/dev/null | head -1):$PORT"
echo "Settings: /etc/server-monitor.env  (then: sudo systemctl restart server-monitor)"
