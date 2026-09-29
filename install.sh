#!/usr/bin/env bash
# Installs Monitorr to /opt/monitorr as systemd services.
#   sudo ./install.sh           this server: the web interface (monitorr, unprivileged user) and
#                               its agent (monitorr-agent, root, reached only over a local socket)
#   sudo ./install.sh --agent   only the agent, for a server another Monitorr watches; prints the
#                               address and pairing code to paste into that hub
set -euo pipefail
AGENT=0; [[ ${1:-} == --agent ]] && AGENT=1
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo ./install.sh"; exit 1; }
umask 077

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/monitorr
ENV=/etc/monitorr.env
PY="$DEST/venv/bin/python"

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

# The web interface runs as this unprivileged user; only the agent runs as root.
id monitorr >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin monitorr

echo "Copying files to $DEST..."
mkdir -p "$DEST" /var/lib/monitorr
chmod 755 "$DEST"
cp -r "$SRC"/{app,hub,agent,common,collectors,alerts,auth,remote,checks,dockerops,security,tlsutil,netguard}.py \
      "$SRC"/requirements.txt "$SRC"/static "$DEST"/
chmod -R go+rX "$DEST"   # readable by the monitorr user, writable by root only

echo "Creating Python environment..."
[[ -d "$DEST/venv" ]] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q --require-hashes -r "$DEST/requirements.txt"   # exact, verified versions
chmod -R go+rX "$DEST/venv"

# ---------- settings ----------
[[ -f $ENV ]] || cp "$SRC/monitorr.env" "$ENV"
chown root:root "$ENV"; chmod 600 "$ENV"      # systemd reads it as root before dropping privileges
setting() { grep -E "^$1=" "$ENV" | head -1 | cut -d= -f2-; }
set_setting() { grep -q "^$1=" "$ENV" && sed -i "s|^$1=.*|$1=$2|" "$ENV" || printf '%s=%s\n' "$1" "$2" >> "$ENV"; }
if grep -qE '^AUTH_DISABLED=' "$ENV"; then
  sed -i 's/^AUTH_DISABLED=/# removed, Monitorr always asks for a password: AUTH_DISABLED=/' "$ENV"
fi
[[ -n "$(setting AGENT_TOKEN)" ]] || set_setting AGENT_TOKEN "$("$PY" "$DEST/app.py" --new-token)"
if [[ $AGENT == 0 && -z "$(setting AUTH_PASSWORD_HASH)" ]]; then
  echo
  echo "Choose a password for signing in to Monitorr (user: $(setting AUTH_USER || echo admin))."
  set_setting AUTH_PASSWORD_HASH "$("$PY" "$DEST/app.py" --hash-password)"
fi

# ---------- services ----------
GID=$(id -g monitorr)
if [[ $AGENT == 1 ]]; then LISTEN=tcp; else LISTEN=unix:/run/monitorr/agent.sock; fi

cat > /etc/systemd/system/monitorr-agent.service <<EOF
[Unit]
Description=Monitorr agent (collects this server's data)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Environment=ROLE=agent AGENT_LISTEN=$LISTEN AGENT_SOCKET_GROUP=$GID DB_PATH=/var/lib/monitorr/metrics.db
EnvironmentFile=$ENV
WorkingDirectory=$DEST
ExecStart=$PY $DEST/app.py agent
User=root
Group=monitorr
RuntimeDirectory=monitorr
RuntimeDirectoryMode=0750
UMask=0077
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
PrivateTmp=yes
Restart=on-failure
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
EOF

if [[ $AGENT == 0 ]]; then
  cat > /etc/systemd/system/monitorr.service <<EOF
[Unit]
Description=Monitorr web interface
After=network-online.target monitorr-agent.service
Wants=network-online.target monitorr-agent.service

[Service]
Environment=ROLE=hub HUB_DB=/var/lib/monitorr-hub/hub.db LOCAL_AGENT=unix:/run/monitorr/agent.sock
EnvironmentFile=$ENV
WorkingDirectory=$DEST
ExecStart=$PY $DEST/app.py hub
User=monitorr
Group=monitorr
StateDirectory=monitorr-hub
StateDirectoryMode=0700
UMask=0077
# no privileges at all, and a read-only view of the system
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
else
  # an agent-only server has no web interface of its own
  systemctl disable --now monitorr 2>/dev/null || true
  rm -f /etc/systemd/system/monitorr.service
fi

systemctl daemon-reload
systemctl enable monitorr-agent >/dev/null 2>&1
systemctl restart monitorr-agent
if [[ $AGENT == 0 ]]; then
  systemctl enable monitorr >/dev/null 2>&1
  systemctl restart monitorr
fi

PORT=$(setting PORT); PORT=${PORT:-8088}
IP=$(command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null | head -1 || true)
IP=${IP:-$(hostname -I | awk '{print $1}')}
echo
if [[ $AGENT == 1 ]]; then
  echo "Agent running. In your Monitorr hub, click \"Add server\" and enter:"
  echo "  Address:      https://$IP:$PORT"
  echo "  Pairing code: $(cd "$DEST" && set -a && . "$ENV" && set +a && DB_PATH=/var/lib/monitorr/metrics.db "$PY" app.py --pairing-code)"
  echo "The hub must be able to reach that address (Tailscale is easiest). Settings: $ENV"
  exit 0
fi
SCHEME=http; [[ "$(setting TLS)" == auto ]] && SCHEME=https
echo "Done. Open $SCHEME://$IP:$PORT and sign in as $(setting AUTH_USER || echo admin)."
echo "Settings: $ENV  (then: sudo systemctl restart monitorr-agent monitorr)"
