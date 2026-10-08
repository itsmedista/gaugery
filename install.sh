#!/usr/bin/env bash
# Installs Gaugery to /opt/gaugery as systemd services.
#   sudo ./install.sh                 this server: the web interface (gaugery, unprivileged user) and
#                                     its agent (gaugery-agent, root, reached only over a local socket)
#   sudo ./install.sh --agent         only the agent, for a server another Gaugery watches; prints the
#                                     address and pairing code to paste into that hub
#   sudo ./install.sh --reconfigure   answer the setup questions again (also with --agent)
#
# The first install asks a few questions and writes the answers to /etc/gaugery.env. Later runs
# (updates) keep your settings. Without a terminal (automation), the suggested answers are used.
set -euo pipefail
AGENT=0 RECONFIGURE=0
for arg in "$@"; do
  case $arg in
    --agent) AGENT=1 ;;
    --reconfigure) RECONFIGURE=1 ;;
    *) echo "Unknown option: $arg (use --agent and/or --reconfigure)"; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "Run with sudo: sudo ./install.sh"; exit 1; }
umask 077

SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/gaugery
ENV=/etc/gaugery.env
PY="$DEST/venv/bin/python"

setting() { [[ -f $ENV ]] && grep -E "^$1=" "$ENV" | head -1 | cut -d= -f2- || true; }
# Values are checked by the questions below, so they never contain "|", "&", "\" or newlines.
set_setting() { grep -q "^$1=" "$ENV" && sed -i "s|^$1=.*|$1=$2|" "$ENV" || printf '%s=%s\n' "$1" "$2" >> "$ENV"; }

# Upgrading from the old "server-monitor" name: keep its settings and history.
if [[ -f /etc/systemd/system/server-monitor.service ]]; then
  echo "Migrating from server-monitor..."
  systemctl disable --now server-monitor 2>/dev/null || true
  rm -f /etc/systemd/system/server-monitor.service
  [[ -f $ENV || ! -f /etc/server-monitor.env ]] || mv /etc/server-monitor.env "$ENV"
  [[ -d /var/lib/gaugery || ! -d /var/lib/server-monitor ]] || mv /var/lib/server-monitor /var/lib/gaugery
fi

# Upgrading from the "Monitorr" name: same settings, history, sign-in, paired servers and checks.
if [[ -f /etc/systemd/system/monitorr-agent.service || -f /etc/systemd/system/monitorr.service ]]; then
  echo "Migrating from Monitorr to Gaugery..."
  systemctl disable --now monitorr monitorr-agent 2>/dev/null || true
  rm -f /etc/systemd/system/monitorr.service /etc/systemd/system/monitorr-agent.service
  [[ -f $ENV || ! -f /etc/monitorr.env ]] || mv /etc/monitorr.env "$ENV"
  [[ -d /var/lib/gaugery || ! -d /var/lib/monitorr ]] || mv /var/lib/monitorr /var/lib/gaugery
  [[ -d /var/lib/gaugery-hub || ! -d /var/lib/monitorr-hub ]] || mv /var/lib/monitorr-hub /var/lib/gaugery-hub
  # same user ID under the new name, so everything it owns stays its own
  if id monitorr >/dev/null 2>&1 && ! id gaugery >/dev/null 2>&1; then
    usermod -l gaugery monitorr && groupmod -n gaugery monitorr
  fi
  rm -rf /opt/monitorr   # the program only; it's installed again below, to /opt/gaugery
fi

# ---------- questions (first install, or --reconfigure) ----------
INTERACTIVE=0; [[ -t 0 && -t 1 ]] && INTERACTIVE=1
ASK=0; [[ ! -f $ENV || $RECONFIGURE == 1 ]] && ASK=1
declare -A ANSWER=()

# ask VAR "question" default regex: repeats until the answer matches; Enter takes the default
ask() {
  local var=$1 question=$2 default=$3 re=$4 value
  if [[ $INTERACTIVE == 0 ]]; then [[ $default == none ]] && default=""; printf -v "$var" '%s' "$default"; return; fi
  while true; do
    read -r -p "  $question [${default:-none}]: " value || value=""
    value=${value:-$default}
    [[ $value == none ]] && value=""
    if [[ -z $value || $value =~ $re ]]; then printf -v "$var" '%s' "$value"; return; fi
    echo "    That doesn't look right. Try again (Enter for the suggestion)."
  done
}
yes_no() {  # yes_no "question" y|n -> returns 0 for yes
  local ans; ask ans "$1 (y/n)" "$2" '^([yY]([eE][sS])?|[nN][oO]?)$'
  [[ ${ans:-n} =~ ^[yY] ]]
}
names_re='^(all|[A-Za-z0-9][A-Za-z0-9_.-]*(,[A-Za-z0-9][A-Za-z0-9_.-]*)*)$'

if [[ $ASK == 1 ]]; then
  TS_IP=$(command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null | head -1 || true)
  LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo
  echo "Gaugery setup. Press Enter to take the suggestion in brackets."
  [[ $INTERACTIVE == 0 ]] && echo "  (no terminal: using the suggestions)"
  echo
  if [[ $AGENT == 1 ]]; then
    echo "Which network should the agent listen on? Your main Gaugery must reach it there."
    [[ -n $TS_IP ]] && echo "  1) Tailscale only ($TS_IP): recommended"
    echo "  2) All networks (LAN: ${LAN_IP:-every address of this machine})"
    ask where "Choose" "$([[ -n $TS_IP ]] && echo 1 || echo 2)" '^[12]$'
    [[ $where == 1 && -z $TS_IP ]] && where=2
    ANSWER[HOST]=$([[ $where == 1 ]] && echo "$TS_IP" || echo 0.0.0.0)
  else
    echo "Where should you be able to open Gaugery?"
    [[ -n $TS_IP ]] && echo "  1) Over Tailscale only ($TS_IP): recommended"
    echo "  2) Behind Tailscale serve or a reverse proxy on this machine (listens on 127.0.0.1 only)"
    echo "  3) From your whole network (LAN: ${LAN_IP:-every address of this machine})"
    ask where "Choose" "$([[ -n $TS_IP ]] && echo 1 || echo 3)" '^[123]$'
    [[ $where == 1 && -z $TS_IP ]] && where=3
    case $where in
      1) ANSWER[HOST]=$TS_IP; HOSTS_SUGGEST="$TS_IP,$(hostname)" ;;
      2) ANSWER[HOST]=127.0.0.1; ANSWER[TRUSTED_PROXIES]=127.0.0.1; HOSTS_SUGGEST="$(hostname)"
         TS_NAME=$(command -v tailscale >/dev/null && tailscale status --json 2>/dev/null \
                   | grep -m1 -o '"DNSName": *"[^"]*"' | cut -d'"' -f4 | sed 's/\.$//' || true)
         [[ -n $TS_NAME ]] && HOSTS_SUGGEST="$TS_NAME,$HOSTS_SUGGEST" ;;
      3) ANSWER[HOST]=0.0.0.0; HOSTS_SUGGEST="${LAN_IP:+$LAN_IP,}$(hostname)" ;;
    esac
  fi
  ask port "Port" "$(setting PORT | grep . || echo 8088)" '^[0-9]{2,5}$'
  (( port >= 1 && port <= 65535 )) || port=8088
  ANSWER[PORT]=$port

  if [[ $AGENT == 0 ]]; then
    ask user "Username for signing in" "$(setting AUTH_USER | grep . || echo admin)" '^[A-Za-z0-9._-]{1,32}$'
    ANSWER[AUTH_USER]=${user:-admin}
    if [[ $where == 3 ]]; then
      echo "  On your LAN, plain HTTP would send your password unencrypted."
      yes_no "Serve HTTPS with Gaugery's own certificate? Browsers ask once whether to trust it" y \
        && ANSWER[TLS]=auto || ANSWER[TLS]=""
    fi
    echo "  Host names and addresses you'll type in the browser (blocks DNS rebinding), comma separated."
    ask hosts "Allowed hosts" "$HOSTS_SUGGEST" '^[A-Za-z0-9.:_-]+(,[A-Za-z0-9.:_-]+)*$'
    ANSWER[ALLOWED_HOSTS]=$hosts
  fi

  if command -v docker >/dev/null; then
    echo "  Docker is installed. Container logs and start/stop/restart buttons are off unless you allow them:"
    echo "  'none', 'all', or container names like plex,nginx. Logs can contain secrets."
    ask logs "Show logs for" none "$names_re"
    ANSWER[ALLOW_LOGS]=$logs
    ask actions "Allow start/stop/restart for" none "$names_re"
    ANSWER[ALLOW_CONTAINER_ACTIONS]=$actions
  fi
  yes_no "Read drive health (SMART)? It runs smartctl as root" n && ANSWER[SMART]=true || ANSWER[SMART]=""

  echo "  Phone alerts with ntfy (https://ntfy.sh or your own server), e.g. https://ntfy.sh/my-private-topic"
  ask ntfy "ntfy topic URL" none '^https?://[^[:space:]|&\\"]+$'
  ANSWER[NTFY_URL]=$ntfy
  if [[ -n $ntfy ]]; then
    ask ntfy_token "Access token for that topic" none '^[A-Za-z0-9_.-]+$'
    ANSWER[NTFY_TOKEN]=$ntfy_token
  fi

  echo "  Webhook for alerts (e.g. an n8n workflow): POSTs each one as JSON, for automated triage."
  ask webhook "Webhook URL" none '^https?://[^[:space:]|&\\"]+$'
  ANSWER[WEBHOOK_URL]=$webhook
  if [[ -n $webhook ]]; then
    ask webhook_secret "Shared secret to verify requests (optional)" none '^[A-Za-z0-9_.-]+$'
    ANSWER[WEBHOOK_SECRET]=$webhook_secret
  fi
  echo
fi

# ---------- install ----------
echo "Installing packages (python3-venv, smartmontools, ping)..."
apt-get update -qq
apt-get install -y -qq python3-venv smartmontools iputils-ping >/dev/null

# The web interface runs as this unprivileged user; only the agent runs as root.
id gaugery >/dev/null 2>&1 || useradd --system --user-group --no-create-home --shell /usr/sbin/nologin gaugery

echo "Copying files to $DEST..."
mkdir -p "$DEST" /var/lib/gaugery
chmod 755 "$DEST"
cp -r "$SRC"/{app,hub,agent,common,collectors,alerts,auth,remote,checks,dockerops,security,tlsutil,netguard,netaccess}.py \
      "$SRC"/requirements.txt "$SRC"/static "$SRC"/{LICENSE,THIRD_PARTY_NOTICES.md,PRIVACY.md} "$DEST"/
chmod -R go+rX "$DEST"   # readable by the gaugery user, writable by root only

echo "Creating Python environment..."
[[ -d "$DEST/venv" ]] || python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q --upgrade pip
"$DEST/venv/bin/pip" install -q --require-hashes -r "$DEST/requirements.txt"   # exact, verified versions
chmod -R go+rX "$DEST/venv"

# ---------- settings ----------
[[ -f $ENV ]] || cp "$SRC/gaugery.env" "$ENV"
chown root:root "$ENV"; chmod 600 "$ENV"      # systemd reads it as root before dropping privileges
for key in "${!ANSWER[@]}"; do set_setting "$key" "${ANSWER[$key]}"; done
if grep -qE '^AUTH_DISABLED=' "$ENV"; then
  sed -i 's/^AUTH_DISABLED=/# removed, Gaugery always asks for a password: AUTH_DISABLED=/' "$ENV"
fi
[[ -n "$(setting AGENT_TOKEN)" ]] || set_setting AGENT_TOKEN "$("$PY" "$DEST/app.py" --new-token)"
if [[ $AGENT == 0 && ( -z "$(setting AUTH_PASSWORD_HASH)" || $RECONFIGURE == 1 ) ]]; then
  if [[ $INTERACTIVE == 0 && -z "$(setting AUTH_PASSWORD_HASH)" ]]; then
    echo "No terminal to ask for a password. Set AUTH_PASSWORD_HASH in $ENV (make one with"
    echo "  sudo $PY $DEST/app.py --hash-password) and run this again."
    exit 1
  fi
  if [[ $INTERACTIVE == 1 ]] && { [[ -z "$(setting AUTH_PASSWORD_HASH)" ]] || yes_no "Change the password?" n; }; then
    echo "Choose a password for signing in to Gaugery (user: $(setting AUTH_USER | grep . || echo admin), 10+ characters)."
    set_setting AUTH_PASSWORD_HASH "$("$PY" "$DEST/app.py" --hash-password)"
  fi
fi

# ---------- services ----------
GID=$(id -g gaugery)
if [[ $AGENT == 1 ]]; then LISTEN=tcp; else LISTEN=unix:/run/gaugery/agent.sock; fi

cat > /etc/systemd/system/gaugery-agent.service <<EOF
[Unit]
Description=Gaugery agent (collects this server's data)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Environment=ROLE=agent AGENT_LISTEN=$LISTEN AGENT_SOCKET_GROUP=$GID DB_PATH=/var/lib/gaugery/metrics.db
EnvironmentFile=$ENV
WorkingDirectory=$DEST
ExecStart=$PY $DEST/app.py agent
User=root
Group=gaugery
RuntimeDirectory=gaugery
RuntimeDirectoryMode=0750
UMask=0077
# root, to read every mount, process and (with SMART=true) the disks, but nothing more:
# only these capabilities, and the kernel, clock and other system settings stay out of reach
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_READ_SEARCH CAP_SYS_RAWIO CAP_SYS_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
ProtectHome=read-only
ProtectSystem=full
PrivateTmp=yes
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
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
Restart=on-failure
RestartSec=5
Nice=10

[Install]
WantedBy=multi-user.target
EOF

if [[ $AGENT == 0 ]]; then
  cat > /etc/systemd/system/gaugery.service <<EOF
[Unit]
Description=Gaugery web interface
After=network-online.target gaugery-agent.service
Wants=network-online.target gaugery-agent.service

[Service]
Environment=ROLE=hub HUB_DB=/var/lib/gaugery-hub/hub.db LOCAL_AGENT=unix:/run/gaugery/agent.sock
EnvironmentFile=$ENV
WorkingDirectory=$DEST
ExecStart=$PY $DEST/app.py hub
User=gaugery
Group=gaugery
StateDirectory=gaugery-hub
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
  systemctl disable --now gaugery 2>/dev/null || true
  rm -f /etc/systemd/system/gaugery.service
fi

systemctl daemon-reload
systemctl enable gaugery-agent >/dev/null 2>&1
systemctl restart gaugery-agent
if [[ $AGENT == 0 ]]; then
  systemctl enable gaugery >/dev/null 2>&1
  systemctl restart gaugery
fi

# ---------- where to go next ----------
PORT=$(setting PORT); PORT=${PORT:-8088}
BIND=$(setting HOST)
if [[ -z $BIND || $BIND == 0.0.0.0 || $BIND == :: ]]; then
  IP=$(command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null | head -1 || true)
  IP=${IP:-$(hostname -I | awk '{print $1}')}
else
  IP=$BIND
fi
echo
if [[ $AGENT == 1 ]]; then
  echo "Agent running. In your Gaugery hub, click \"Add server\" and enter:"
  echo "  Address:      https://$IP:$PORT"
  echo "  Pairing code: $(cd "$DEST" && set -a && . "$ENV" && set +a && DB_PATH=/var/lib/gaugery/metrics.db "$PY" app.py --pairing-code)"
  echo "The hub must be able to reach that address (Tailscale is easiest)."
  echo "Settings: $ENV  (change them: sudo ./install.sh --agent --reconfigure)"
  exit 0
fi
if [[ $IP == 127.0.0.1 ]]; then
  echo "Done. Gaugery listens on 127.0.0.1:$PORT only. To reach it over Tailscale with HTTPS, run:"
  echo "  sudo tailscale serve --bg $PORT"
  echo "then open https://<this machine>.<your tailnet>.ts.net (or point your reverse proxy at 127.0.0.1:$PORT)."
else
  SCHEME=http; [[ "$(setting TLS)" == auto ]] && SCHEME=https
  echo "Done. Open $SCHEME://$IP:$PORT and sign in as $(setting AUTH_USER | grep . || echo admin)."
fi
echo "Settings: $ENV  (change them: sudo ./install.sh --reconfigure)"
