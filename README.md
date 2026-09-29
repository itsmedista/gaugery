# Monitorr

A monitoring dashboard for one Linux server. It samples every 2 seconds,
keeps per-minute history in SQLite, and serves a live web page behind a login.

## Install with Docker (recommended)

    git clone https://github.com/itsmedista/server-monitor.git monitorr && cd monitorr
    docker compose build
    docker compose run --rm monitorr python app.py --hash-password   # prints scrypt:...
    nano .env      # add one line:  AUTH_PASSWORD_HASH=scrypt:...
    docker compose up -d

Open `http://<server-ip>:8088` and sign in as `admin` with the password you chose.
Settings are the `environment:` block in `docker-compose.yml`; apply changes with
`docker compose up -d`. History is kept in `./data`.

To keep it private to your tailnet, set `HOST` to the output of `tailscale ip -4`.

Why the container needs host access: it uses host networking (real interface
traffic), the host PID namespace (processes and mount table), a read-only view of
`/` at `/host` (drive space for every mount), the Docker socket (container stats),
and privileged mode (SMART). See the comments in `docker-compose.yml` for a
less-privileged option.

Update after changing files: `docker compose up -d --build`
Logs: `docker logs -f monitorr`

Upgrading from `server-monitor`: create the `.env` file above, then run
`docker compose up -d --build --remove-orphans`. The old container is removed and
the history in `./data` carries over.

## Install without Docker (systemd)

    sudo ./install.sh

It asks for a login password on first install. Settings live in `/etc/monitorr.env`.
An existing `server-monitor` install is migrated, settings and history included.

## Monitoring more servers

Monitorr opens on an overview with one card per server: green when it has no
active alerts, red when it has alerts or can't be reached. Click a card for
that server's full dashboard.

Arrange the overview your way. Every card stays the same size, so rows always line up:

- **Move** a card by dragging its grip (the dots left of the name), or focus the grip
  and use the arrow keys. The card's `⋯` menu also has "Move earlier" and "Move later".
- **Pin** important servers from the `⋯` menu; pinned cards always come first.
- **Detailed / Compact** in the header switches every card's size at once.

The layout is saved on the hub, so every device shows the same order.

Each extra server runs Monitorr as an **agent**: the same app, but with no login
page; it only answers your main Monitorr (the hub), which sends a secret token.
Your browser only ever talks to the hub.

On the remote server:

    sudo ./install.sh --agent          # prints the address and token to paste

or with Docker, put a token in `.env` and start it as usual:

    docker compose build
    echo "AGENT_TOKEN=$(docker compose run --rm -T monitorr python app.py --new-token)" > .env
    docker compose up -d

Then click **Add server** on the hub and enter a name, the address
(`http://<ip>:8088`) and the token. The hub checks the connection before saving.

- The hub must reach the agent's port. Tailscale is the easy way: set the agent's
  `HOST` to its `tailscale ip -4` so it isn't exposed anywhere else.
- The token only unlocks read-only data (info, history, live stream, summary).
- Each agent sends its own phone alerts, so set `NTFY_URL` on each one if you want them.

## Service checks

A running machine isn't the same as a working service. On any server's page,
**Services → Add check** watches something that should answer:

- **Website (HTTP)**: expected status (default 200-399), optional text the page
  must contain, and a warning before its HTTPS certificate expires (default 14 days).
  Turn off certificate verification for self-signed ones.
- **Port (TCP)**: `host:port` accepts connections (SSH, databases, game servers).
- **Ping**: the host replies.

Your main Monitorr (the hub) runs every check, every 30 s to 15 min, and files it
under the server you added it on. Two failures in a row raise a critical alert and
send a phone alert through ntfy like any other. The service also shows on the server's
card, which turns red. Each check keeps 30 days of results for its response-time
sparkline and 24-hour and 7-day uptime.

Because the hub runs the checks, they test what the hub can reach. Agents need
nothing extra.

## Container logs and actions

Each server's page has a **Logs** section for any container: search, a live tail,
and a time window that follows the range buttons (Live, 1h, 6h, 24h, 7d).
**Click any chart** to jump to the logs from that moment, with the closest line
highlighted. The logs button on a container row opens that container's logs.

With `ALLOW_CONTAINER_ACTIONS=true`, container rows also get start, stop and
restart buttons. They're off by default, and each server decides for itself (on an
agent, set it in the agent's settings). Guardrails:

- Every action is recorded in that server's alert history and sent to ntfy.
- Actions only accept JSON, so another website can't trigger them through your
  signed-in browser.
- Monitorr won't stop its own container (that would take the page down).

`ALLOW_LOGS=false` hides logs on a server; logs often contain secrets.

A word on `docker.sock`: mounting it `:ro` does **not** make Docker read-only.
Anything that can reach the socket can control Docker. These switches decide what
Monitorr's page exposes; the socket itself always allowed more.

## Login

- One user: `AUTH_USER` (default `admin`) and `AUTH_PASSWORD_HASH`, a scrypt hash
  made by `python app.py --hash-password`. The plain password is never stored.
- Sessions last `SESSION_DAYS` (default 30). Changing the password signs everyone out.
- Five wrong passwords from one address lock it out for five minutes.
- `AUTH_DISABLED=true` turns the login off, e.g. if a reverse proxy already handles it.
- Over plain HTTP the password crosses the network unencrypted. Use it over
  Tailscale (encrypted) or put HTTPS in front of it.

## Security

What Monitorr does for you:

- **Login:** scrypt password hash; sessions are signed, expire, and are revoked at
  sign-out, so a copied cookie stops working. Five wrong passwords lock that address out
  for five minutes, and password checks run off the main loop, so a login flood can't
  freeze the app.
- **Browser protections:** a strict Content-Security-Policy (only Monitorr's own scripts
  run), no framing (no clickjacking), `nosniff`, and no referrer. Requests that change
  something must come from Monitorr's own pages as JSON. That blocks other sites, and
  other apps on the same host, from acting with your session.
- **Remote servers are untrusted:** the hub checks and trims what agents send, never serves
  an agent's reply as a page, and the pages escape everything. A hacked agent can lie
  about its own numbers, but it can't take over the hub.
- **Files:** the database (which holds agent tokens) and keys are readable by Monitorr's
  user only.

What stays your job:

- **Keep it off the internet.** Serve it over Tailscale, or behind HTTPS. Over plain HTTP
  on a LAN, passwords and agent tokens travel unencrypted. Set `HOST` to a Tailscale
  IP to listen only there.
- **Set `ALLOWED_HOSTS`** to the names and IPs you use to open it. This blocks DNS rebinding,
  and it's essential if you ever set `AUTH_DISABLED=true`.
- **Treat the Docker socket as root.** Whatever can use `docker.sock` controls the host,
  with or without `:ro`, and so does the privileged container. If Monitorr itself were
  compromised, so would the host be. Keep it updated, and keep `ALLOW_CONTAINER_ACTIONS` off
  where you don't need it.
- **Service checks and servers can point anywhere** the hub can reach. That's the feature,
  but it means your login is also the key to probing your network.

## Test changes in the sandbox first

Work on a branch, run it next to production, and only merge when it works:

    git switch -c my-change
    # ...edit...
    docker compose -f docker-compose.dev.yml up -d --build
    # open http://localhost:8089, check it, repeat

    git commit -am "..."            # still only on your machine
    git switch main && git merge my-change && git push
    docker compose -f docker-compose.dev.yml down

The sandbox is its own container (`monitorr-dev`) on port 8089 with its own
history in `./data-dev`. It never sends phone alerts. It also starts a pretend
remote server (`monitorr-agent`); add it on the overview with the address
`http://monitorr-agent:8088` and the `DEV_AGENT_TOKEN` from `.env`.

## What it watches

- CPU (per mode and per thread), load, RAM, swap
- Every mounted drive, found automatically: space, inodes, read/write speed,
  SMART health, and a "full in N days" forecast from the last week of growth
- Network traffic per interface, temperatures
- Docker containers: state, CPU, memory, restarts, health checks
- Top processes by CPU and memory

## Notes

- Drives mounted after the container starts (USB disks, new NFS shares) still
  show up, thanks to the `rslave` mount propagation.
- Stuck network mounts are marked "not responding" instead of freezing the page.
- Inside a VM, disks usually don't expose SMART; the page shows "No SMART".
