#!/usr/bin/env bash
# Installs Monitorr to /opt/monitorr and starts it as a systemd service.
#   sudo ./install.sh           the full app, with its own login
#   sudo ./install.sh --agent   an agent that another Monitorr (the hub) watches; prints its token
set -euo pipefail
AGENT=0; [[ ${1:-} == --agent ]] && AGENT=1
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo ./install.sh"; exit 1; }

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/monitorr
ENV=/etc/monitorr.env

# Upgrading from the old "server-monitor" name: keep its settings and history.
if [[ -f /etc/systemd/system/server-monitor.service ]]; then
  echo "Migrating from server-monitor..."
  systemctl disable --now server-monitor 2>/dev/null || true
  rm -f /etc/systemd/system/server-monitor.service
  [[ -f $ENV || ! -f /etc/server-monitor.env ]] || mv /etc/server-monitor.env "$ENV"
  [[ -d /var/lib/monitorr || ! -d /var/lib/server-monitor ]] || mv /var/lib/server-monitor /var/lib/monitorr
fi

echo "Installing packages (python3-venv, smartmontools, ping)..."
apt-get update -qq
apt-get install -y -qq python3-venv smartmontools iputils-ping >/dev/null

echo "Copying files to $DEST..."
mkdir -p "$DEST" /var/lib/monitorr
cp -r "$SRC"/app.py "$SRC"/collectors.py "$SRC"/alerts.py "$SRC"/auth.py "$SRC"/remote.py "$SRC"/checks.py "$SRC"/dockerops.py "$SRC"/security.py "$SRC"/requirements.txt "$SRC"/static "$DEST"/

echo "Creating Python environment..."
[[ -d "$DEST/venv" ]] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

[[ -f $ENV ]] || cp "$SRC/monitorr.env" "$ENV"
chmod 600 "$ENV"
grep -q '^AUTH_PASSWORD_HASH=' "$ENV" || printf '\nAUTH_USER=admin\nAUTH_PASSWORD_HASH=\n' >> "$ENV"
grep -q '^AGENT_TOKEN=' "$ENV" || printf '\nAGENT_TOKEN=\n' >> "$ENV"
if [[ $AGENT == 1 ]] && grep -q '^AGENT_TOKEN=$' "$ENV"; then
  sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$("$DEST/venv/bin/python" "$DEST/app.py" --new-token)|" "$ENV"
fi
if [[ $AGENT == 0 ]] && grep -q '^AUTH_PASSWORD_HASH=$' "$ENV" && ! grep -qiE '^AUTH_DISABLED=(1|true|yes)' "$ENV"; then
  echo
  echo "Choose a password for the Monitorr login (user: $(grep -E '^AUTH_USER=' "$ENV" | cut -d= -f2 || echo admin))."
  HASH=$("$DEST/venv/bin/python" "$DEST/app.py" --hash-password)
  sed -i "s|^AUTH_PASSWORD_HASH=.*|AUTH_PASSWORD_HASH=$HASH|" "$ENV"
fi

cp "$SRC/monitorr.service" /etc/systemd/system/monitorr.service
systemctl daemon-reload
systemctl enable --now monitorr
systemctl restart monitorr

PORT=$(grep -E '^PORT=' "$ENV" | cut -d= -f2); PORT=${PORT:-8088}
if [[ $AGENT == 1 ]]; then
  IP=$(command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null | head -1 || true)
  echo
  echo "Agent running. In your Monitorr hub, click \"Add server\" and enter:"
  echo "  Address: http://${IP:-$(hostname -I | awk '{print $1}')}:$PORT"
  echo "  Token:   $(grep -E '^AGENT_TOKEN=' "$ENV" | cut -d= -f2)"
  echo "The hub must be able to reach that address (Tailscale is easiest). Settings: $ENV"
  exit 0
fi
echo
echo "Done. Open http://$(hostname -I | awk '{print $1}'):$PORT"
command -v tailscale >/dev/null && echo "Over Tailscale: http://$(tailscale ip -4 2>/dev/null | head -1):$PORT"
echo "Settings: $ENV  (then: sudo systemctl restart monitorr)"
