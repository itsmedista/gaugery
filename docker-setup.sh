#!/usr/bin/env bash
# Writes .env for the Docker setup: a random agent token and, for the full install, your password hash.
#   ./docker-setup.sh           this server: web interface + agent (docker-compose.yml)
#   ./docker-setup.sh --agent   a server another Gaugery watches (docker-compose.agent.yml)
set -euo pipefail
cd "$(dirname "$0")"
umask 077                       # .env holds secrets: readable by you only

AGENT=0; [[ ${1:-} == --agent ]] && AGENT=1
COMPOSE=docker-compose.yml; [[ $AGENT == 1 ]] && COMPOSE=docker-compose.agent.yml
[[ -f .env ]] || cp .env.example .env
chmod 600 .env

set_var() {  # set_var NAME VALUE (values are token/hash characters only: no quoting needed)
  if grep -q "^$1=" .env; then sed -i "s|^$1=.*|$1=$2|" .env; else printf '%s=%s\n' "$1" "$2" >> .env; fi
}
get_var() { grep -E "^$1=" .env | head -1 | cut -d= -f2-; }

echo "Building the image..."
AGENT_TOKEN=x AUTH_PASSWORD_HASH=x docker compose -f "$COMPOSE" build -q

if [[ -z "$(get_var AGENT_TOKEN)" ]]; then
  set_var AGENT_TOKEN "$(AGENT_TOKEN=x AUTH_PASSWORD_HASH=x docker compose -f "$COMPOSE" run --rm -T --no-deps \
    gaugery-agent python app.py --new-token | tr -d '\r\n')"
  echo "Made an agent token."
fi

if [[ $AGENT == 0 && -z "$(get_var AUTH_PASSWORD_HASH)" ]]; then
  echo "Choose the password for signing in to Gaugery (user: $(get_var AUTH_USER || true))."
  HASH=$(AGENT_TOKEN=x AUTH_PASSWORD_HASH=x docker compose -f "$COMPOSE" run --rm --no-deps gaugery \
    python app.py --hash-password | tail -1 | tr -d '\r\n')
  [[ $HASH == scrypt:* ]] || { echo "Setting the password didn't work."; exit 1; }
  set_var AUTH_PASSWORD_HASH "$HASH"
fi

echo
echo "Done. Start it with: docker compose -f $COMPOSE up -d"
[[ $AGENT == 1 ]] && echo "Then get the pairing code with: docker compose -f $COMPOSE logs gaugery-agent"
exit 0
