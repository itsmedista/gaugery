<img src="static/icon.svg" width="72" alt="">

# Gaugery

A monitoring dashboard for your Linux servers. It samples every 2 seconds, keeps
per-minute history in SQLite, checks that your services answer, and serves a live
web page behind a login.

## Upgrading from Monitorr

Monitorr is now called **Gaugery**. Upgrading keeps your settings, history, password,
two-factor sign-in, paired servers and service checks. Everyone is signed out once, because
the sign-in cookie has a new name.

- **Docker:** `git pull`, then `docker compose up -d --build --remove-orphans`. The
  containers are now `gaugery` and `gaugery-agent`; `--remove-orphans` removes the old
  `monitorr` ones. Your data volumes keep their names. On agent-only servers, add
  `-f docker-compose.agent.yml`.
- **Without Docker:** `git pull`, then `sudo ./install.sh` (add `--agent` on agent-only
  servers). It stops the `monitorr` services and moves `/etc/monitorr.env`,
  `/var/lib/monitorr` and `/var/lib/monitorr-hub` to their `gaugery` names. It also renames
  the `monitorr` system user, keeping its ID so file ownership doesn't change.
- **Remote servers:** remote servers stay paired; their certificates don't change. Agents
  you haven't upgraded yet keep working with an upgraded web interface, and their old
  `mtr1.` pairing codes are still accepted.
- **Authenticator apps:** two-factor entries made before the rename still show "Monitorr" in
  your authenticator app. They keep working; to change the label, turn two-factor off and on
  again.

## How it's put together

Gaugery is two parts, so the part you open in a browser never has power over your server:

- **The web interface** (`gaugery`): pages, sign-in, service checks, your list of servers.
  It runs as an unprivileged user with no access to the host or to Docker.
- **The agent** (`gaugery-agent`): collects one server's data. It's the only part with
  host access, it has no web page, and it answers only the web interface, which proves
  itself with a secret token. On the same machine they talk over a Unix socket (no port).
  On other servers the agent listens on HTTPS with its own certificate, which the web
  interface pins when you pair it.
- With Docker, the agent reaches Docker through a **socket proxy** that only allows reading
  (containers, their stats and logs). If you turn on container actions, a second proxy
  allows exactly start, stop and restart. Nothing that could create containers, run
  commands in them or otherwise take over the host gets through either one.

## Install with Docker (recommended)

    git clone https://github.com/itsmedista/server-monitor.git gaugery && cd gaugery
    ./docker-setup.sh          # asks for your password, writes .env
    docker compose up -d

Open `http://<server-ip>:8088` and sign in as `admin`. Settings are in `.env` (every
option is explained in `.env.example`); apply changes with `docker compose up -d`.

- Update after pulling changes: `docker compose up -d --build`
- Logs: `docker logs -f gaugery` (web interface), `docker logs -f gaugery-agent`
- History is kept in `./data`; the web interface's own data (servers, checks, layout)
  in the `hub-data` volume.
- Drive health (SMART) needs raw disk access, so it's opt-in: list your disks in
  `docker-compose.smart.yml` and start with
  `docker compose -f docker-compose.yml -f docker-compose.smart.yml up -d`.
- NVIDIA GPUs need the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html)
  on the host; then start with
  `docker compose -f docker-compose.yml -f docker-compose.gpu.yml up -d`.
  AMD GPUs work as they are. Without Docker, the agent uses the host's `nvidia-smi`.

**Upgrading from the single-container version:** run `./docker-setup.sh` (it adds the
agent token to your `.env`), then `docker compose up -d --build --remove-orphans`. On first
start the web interface takes over your servers, service checks and layout from the old
database automatically. Servers added before encrypted connections show "added before
connections were encrypted": remove them and add them again with their pairing code.

## Install without Docker (systemd)

    sudo ./install.sh

It first asks a few questions and writes the answers to `/etc/gaugery.env`, so you
don't have to edit it by hand. Press Enter to take each suggestion:

- **Where to open Gaugery:** over Tailscale only, behind Tailscale serve or a reverse
  proxy on the same machine, or from your whole LAN (then it offers HTTPS with its own
  certificate)
- the **port** and your **username**, then your **password**
- the **host names** you'll use in the browser (`ALLOWED_HOSTS`)
- **container logs** and **start/stop/restart**: none, all, or a list of containers
- **drive health (SMART)**, and an **ntfy** topic (and token) for phone alerts

Then it runs two services: `gaugery` (web interface, as the unprivileged `gaugery` user,
heavily sandboxed) and `gaugery-agent` (root, reached only over `/run/gaugery/agent.sock`).
Running it again later updates Gaugery and keeps your settings. To answer the questions
again: `sudo ./install.sh --reconfigure`. To change a setting by hand: edit
`/etc/gaugery.env` (readable by root only), then
`sudo systemctl restart gaugery-agent gaugery`.

## Monitoring more servers

On each extra server, install just the agent:

    sudo ./install.sh --agent                              # systemd (asks a few questions)
    ./docker-setup.sh --agent && docker compose -f docker-compose.agent.yml up -d   # Docker

It prints an address and a **pairing code**. On your main Gaugery click **Add server**,
give it a name, and paste both. The pairing code carries the agent's token and its
certificate's fingerprint: the web interface refuses to connect if the certificate at that
address isn't the one in the code, so nobody in between can read or impersonate the agent.
(Lost the code? `docker compose -f docker-compose.agent.yml logs gaugery-agent`, or
`sudo /opt/gaugery/venv/bin/python /opt/gaugery/app.py --pairing-code` with the
settings loaded.)

The web interface must reach the agent's port; Tailscale is the easy way (set the
agent's `BIND`/`HOST` to its `tailscale ip -4`). Each agent sends its own phone alerts, so
set `NTFY_URL` on each one if you want them.

The overview shows one card per server: green with no active alerts, red with alerts or
when it can't be reached. Every card is the same size, so rows always line up:

- **Move** a card by dragging its grip (the dots left of the name), or focus the grip
  and use the arrow keys. The card's `⋯` menu also has "Move earlier" and "Move later".
- **Pin** important servers from the `⋯` menu; pinned cards always come first.
- **Detailed / Compact** in the header switches every card's size at once.

The layout is saved on the web interface, so every device shows the same order.

## Service checks

A running machine isn't the same as a working service. On any server's page,
**Services → Add check** watches something that should answer:

- **Website (HTTP)**: expected status (default 200-399), optional text the page
  must contain, and a warning before its HTTPS certificate expires (default 14 days).
  Turn off certificate verification for self-signed ones.
- **Port (TCP)**: `host:port` accepts connections (SSH, databases, game servers).
- **Ping**: the host replies.

The web interface runs every check, every 30 s to 15 min, and files it under the server
you added it on. Two failures in a row raise a critical alert and a phone alert through
ntfy. Each check keeps 30 days of results for its response-time sparkline and 24-hour and
7-day uptime.

Checks can't reach loopback, link-local or cloud-metadata addresses (so they can't be
turned against the machine itself or a cloud provider's credentials), including through
redirects. `CHECK_ALLOWED_NETWORKS` (e.g. `192.168.1.0/24,100.64.0.0/10`) limits them
further to your own networks.

## Container logs and actions

Both are off until you allow them, per server and per container:

    ALLOW_LOGS=all                 # or: plex,nginx
    ALLOW_CONTAINER_ACTIONS=plex   # start/stop/restart buttons; with Docker also COMPOSE_PROFILES=actions

Each server's page then has a **Logs** section: search, a live tail, and a time window
that follows the range buttons. **Click any chart** to jump to the logs from that moment.
Log lines are scrubbed of obvious secrets (passwords in URLs, `password=`/`token=` values,
bearer tokens, JWTs, AWS keys) before they leave the server; it's best-effort, which is
why logs are opt-in per container (`LOG_REDACT=false` turns the scrubbing off).

Every container action asks for your password if you last entered it more than 15
minutes ago, is recorded on both sides, and goes to ntfy. Gaugery won't stop its own
container.

## Your account and settings

Click your picture (top right) for **Settings** or **Sign out**. Settings are saved to your
account, so every device looks the same:

- **Customization:** dark, light or match-your-device theme and an accent colour; language
  (English, Français, Español, Deutsch, or your browser's); 12- or 24-hour time; °C or °F; the
  time range server pages open on; card size; and which page opens after signing in.
- **Account:** a built-in picture, your own upload (cropped and shrunk in your browser, stored
  and served only as a checked PNG, JPEG or WebP), or your initials; display name and email
  (Gaugery doesn't send email). The username is set on the server (`AUTH_USER`).
- **Security:** change your password (it signs out every other session), two-factor sign-in
  with 8 one-time recovery codes, "sign out everywhere else", and the activity log.

Forgot the password? On the server: `python app.py --reset-password` (Docker:
`docker compose exec gaugery python app.py --reset-password`), then restart the web
interface. A password changed in Settings is kept in the database and wins over
`AUTH_PASSWORD_HASH`, until you change `AUTH_PASSWORD_HASH` on the server; then that wins again.

## Signing in

- One user: `AUTH_USER` (default `admin`) and `AUTH_PASSWORD_HASH`, a scrypt hash
  made by `python app.py --hash-password`. The plain password is never stored.
- **Two-factor sign-in:** Settings → Security → Turn on, then scan or type the key into
  any authenticator app. Save the 8 recovery codes it shows: each one signs you in once
  instead of a code. Lost your phone and the codes? On the server:
  `docker compose exec gaugery python app.py --disable-2fa` (Docker) or
  `sudo -u gaugery ... app.py --disable-2fa` with the settings loaded (systemd).
- Forgot the password: `python app.py --reset-password` on the server (see
  [Your account and settings](#your-account-and-settings)).
- Sensitive changes (servers, service checks, container actions, two-factor) ask for your
  password again after 15 minutes, so a stolen session can look but not change anything.
- Sessions last `SESSION_DAYS` (default 30) and are revoked at sign-out. Changing the
  password signs everyone out.
- Wrong passwords make that address wait longer each time (up to 30 s). There's no
  lockout, so an attacker can't lock you out.
- Signing in over plain HTTP is refused from public addresses; this machine, private
  networks and Tailscale are fine.

## HTTPS

Pick one:

- **Tailscale serve** (easiest; a real certificate, nothing to manage): set `BIND=127.0.0.1`
  (Docker) or `HOST=127.0.0.1` (systemd) and `TRUSTED_PROXIES=127.0.0.1` (Docker on Linux:
  the bridge gateway, usually `172.17.0.1`), then `tailscale serve --bg 8088`. Open
  `https://<machine>.<tailnet>.ts.net`.
- **Built in:** `TLS=auto` serves HTTPS with Gaugery's own certificate (your browser asks
  once whether to trust it), or `TLS_CERT`/`TLS_KEY` for your own.
- **Your reverse proxy:** point it at port 8088 and set `TRUSTED_PROXIES` to its address,
  so Gaugery sees the real client address and knows the connection is HTTPS.

With HTTPS the session cookie is marked Secure. With a certificate browsers trust (Tailscale
serve, your own, or your proxy's) they're also told to always use HTTPS (HSTS). Not with
`TLS=auto`: HSTS would stop you from accepting its self-signed certificate.

## Security

What Gaugery does for you:

- **Least privilege:** the web interface has no host access, no Docker, no root and no
  Linux capabilities, on a read-only filesystem (systemd rates its sandbox 3.0 "OK"; the
  agent's 4.6 "OK"). The agent has host access but no port on
  the main server, and Docker only through the socket proxy. A compromised web interface
  can read your dashboards and do what you allowed (logs, container actions); it can't
  become root.
- **Encrypted, authenticated agents:** pinned TLS between the web interface and remote
  agents; tokens never cross the network in the clear.
- **Sign-in:** see above. Security events (sign-ins from new addresses, repeated wrong
  passwords, servers/checks/two-factor changed, container actions) are listed under
  Security and sent to ntfy.
- **Browser protections:** a strict Content-Security-Policy (only Gaugery's own scripts
  run), no framing, `nosniff`, no referrer, `SameSite=Strict` cookies, and changes only
  from Gaugery's own pages as JSON.
- **Remote servers are untrusted:** the web interface checks and trims what agents send,
  never serves an agent's reply as a page, and the pages escape everything.
- **Supply chain:** the base images (Python, socket proxy) are pinned by digest, and every
  Python package, dependencies included, by exact version and hash (`requirements.txt`).
  A tampered or swapped package fails the install.

What stays your job:

- **Keep it off the internet**, or put HTTPS in front of it (see above).
- **Set `ALLOWED_HOSTS`** to the names and IPs you open it with (blocks DNS rebinding).
- **Only allow logs and actions where you need them.**
- **Update now and then:** pull the new base image and put its digest in the Dockerfile
  (the command is in the comment there), refresh the package lock (the command is at the top of
  `requirements.txt`), then `docker compose up -d --build`.

## Test changes in the sandbox first

Work on a branch, run it next to production, and only merge when it works:

    git switch -c my-change
    # ...edit...
    docker compose -f docker-compose.dev.yml up -d --build
    # open http://localhost:8089, check it, repeat

    git commit -am "..."            # still only on your machine
    git switch main && git merge my-change && git push
    docker compose -f docker-compose.dev.yml down

The sandbox needs a `.env` next to the compose file with `AUTH_PASSWORD_HASH`, `AGENT_TOKEN`
and `DEV_AGENT_TOKEN` (make tokens with `python app.py --new-token`). It has the same
layout as production, on port 8089, with its own data. It
never sends phone alerts. It also starts a pretend remote server: add it on the overview
with the address `https://gaugery-agent:8088` and the pairing code from
`docker logs gaugery-dev-remote`.

## What it watches

- CPU (per mode and per thread), load, RAM, swap
- Every mounted drive, found automatically: space, inodes, read/write speed,
  SMART health (opt-in), and a "full in N days" forecast from the last week of growth
- Network traffic per interface, temperatures
- GPUs (NVIDIA and AMD): shader load, video memory, temperature; on NVIDIA also the video
  encoder and decoder, power draw, and which processes use the GPU
- Docker containers: state, CPU, memory, restarts, health checks
- Top processes by CPU and memory
- Hardware: system and board, BIOS, processor (cores, cache, top speed, virtualization),
  memory modules per slot, disks, GPUs

## Notes

- Drives mounted after the agent starts (USB disks, new NFS shares) still
  show up, thanks to the `rslave` mount propagation.
- Stuck network mounts are marked "not responding" instead of freezing the page.
- Inside a VM, disks usually don't expose SMART; the page shows "No SMART".

## License and privacy

Copyright (C) 2026 itsmedista.

Gaugery is free software: you can redistribute it and/or modify it under the terms of the
[GNU Affero General Public License, version 3](LICENSE) (AGPL-3.0-only). It comes with no
warranty. In short:
- You may use, study, change and share it, also commercially.
- If you share it, or let other people use a **modified** copy over a network, you must
  offer them the complete source of your version under the same license. The "Source code"
  link on the sign-in and Settings pages is how users find it: point it at your copy.

Other software it uses and their licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

**Privacy:** Gaugery sends nothing to its authors or anyone else: no telemetry, analytics or
update checks, and its fonts are served locally. It sets one sign-in cookie, needed to stay
signed in, so there's no cookie banner. [PRIVACY.md](PRIVACY.md) lists everything it stores,
how long it keeps it, and every connection it makes.

## What's changed

Newest first. Each entry links to its pull request, which has the details and test results.

### Monitorr is now Gaugery ([#13](https://github.com/itsmedista/server-monitor/pull/13))
- New name, because another self-hosted monitoring project is already called Monitorr. The
  new icon is a ring gauge drawn as a G; [BRAND.md](BRAND.md) has the colours, type and
  usage.
- Everything is renamed: pages, containers, services, paths, the system user and the
  cookie. Pairing codes now start with `gry1.`. See *Upgrading from Monitorr* above: data
  carries over, and you're signed out once.

### License, privacy and fonts ([#12](https://github.com/itsmedista/server-monitor/pull/12))
- Licensed under the GNU AGPL v3, with a "Source code" link on the sign-in and Settings
  pages.
- [PRIVACY.md](PRIVACY.md) lists everything Monitorr stores, for how long, and every
  connection it makes. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists the licenses
  of the software it uses.
- The fonts are now served by Monitorr instead of Google Fonts, so opening a page no longer
  sends your IP address to Google. Monitorr now makes no connection you didn't configure.
- The sign-in page now loads its translations and theme. Before, they were blocked until
  you signed in, so it always showed in English.

### Security review of #4 to #10 ([#11](https://github.com/itsmedista/server-monitor/pull/11))
- The web interface stops reading an agent's answer past 32 MB (counted after
  decompression). Before, a hacked remote server could send an endless answer and run the
  web interface out of memory, taking monitoring down for every server.
- With two-factor sign-in on, setting up another authenticator app is refused until it's
  turned off, which needs a current code. Before, the setup steps could replace the app with
  only the password.
- Checked and unchanged: everything a server reports (GPU and process names, hardware
  strings) is escaped on the page; account endpoints validate their input; no known
  vulnerabilities in the locked Python packages (pip-audit).

### Hardware section ([#10](https://github.com/itsmedista/server-monitor/pull/10))
- A Hardware section at the end of each server's page (last item in the side menu):
  - System: manufacturer, model, motherboard, BIOS, platform, OS and kernel.
  - Processor: sockets, cores and threads, top speed, cache, virtualization, instruction sets.
  - Memory: modules per slot (size, type, speed, maker, part number).
  - Storage: disks with model, type and size.
  - Graphics: GPUs with their video memory.
- Read once when the agent starts. Serial numbers are never collected. Placeholder values
  from the firmware ("To Be Filled By O.E.M.") are hidden.
- Memory modules come from the firmware's table, which virtual machines and some boards
  don't provide; the page says so instead.

### Charts use the full width ([#9](https://github.com/itsmedista/server-monitor/pull/9))
- On the server page every row of charts now fills the page: a lone chart (one GPU, one
  network interface) or the last chart of a row stretches instead of leaving a gap.

### GPU processes, encoder and decoder ([#8](https://github.com/itsmedista/server-monitor/pull/8))
- NVIDIA: each GPU's chart also shows the video encoder and decoder, and a table lists the
  processes using the GPUs (shader, encoder, decoder and memory per process).
- The process list needs the agent to see the host's processes, which the Docker setup
  already does. Windows/WSL hosts don't report GPU processes, so the table stays empty there.
- "busy" on GPU charts is now called "shader".

### GPU monitoring ([#7](https://github.com/itsmedista/server-monitor/pull/7))
- A GPU section on the server page, shown only when the server has one: busy time and video
  memory for each GPU, with memory in use and power draw next to the title.
- NVIDIA through `nvidia-smi`, AMD through the amdgpu driver's files in `/sys`. Intel isn't
  covered yet.
- GPU temperatures join the Sensors chart, the "Hottest sensor" gauge and the temperature
  alerts.
- Docker: `docker-compose.gpu.yml` gives the agent NVIDIA GPUs (read-only `nvidia-smi`, no
  CUDA). AMD needs nothing extra.

### Account menu on every screen size ([#5](https://github.com/itsmedista/server-monitor/pull/5))
- On phones and tablets the account menu opened behind the dashboard. It now always
  opens on top, under your picture, fully on screen.

### Settings and three more languages ([#4](https://github.com/itsmedista/server-monitor/pull/4))
- **Account menu** (your picture, top right) with Settings and Sign out on every page.
- **Settings:**
  - **Customization:** theme (dark, light or your device's), accent colour, language,
    12/24-hour time, °C/°F, default time range, card size and start page, all saved to
    your account.
  - **Account:** built-in picture, your own upload or initials; name and email.
  - **Security:** change password, two-factor with recovery codes, sign out everywhere
    else, and the activity log.
- **French, Spanish and German** interface.
- `python app.py --reset-password` for a forgotten password.
- **Fixed:** reloading a page could leave it blank and unstyled.

### Security check of every mitigation ([#3](https://github.com/itsmedista/server-monitor/pull/3))
- Every item of the security plan re-tested on the current version, and the earlier attacks re-run.
- **Fixed:**
  - `TLS=auto` no longer turns on HSTS, which would have locked you out of a self-signed page.
  - Web service checks connect to the address that passed the safety check (no DNS rebinding).
  - The one-time data hand-over only exists on the local agent.
  - The systemd agent keeps only the rights it needs (systemd exposure score 8.8 → 4.6).

### Installer asks for its settings ([#2](https://github.com/itsmedista/server-monitor/pull/2))
- `install.sh` asks where to listen, the port, username, allowed host names, logs and
  actions, SMART and ntfy, checks the answers, and writes `/etc/monitorr.env`.
- `--reconfigure` asks again; updates keep your settings.

### Monitorr ([#1](https://github.com/itsmedista/server-monitor/pull/1))
- **Renamed to Monitorr**, with a new icon and a sign-in page.
- **Several servers:** an overview of same-size server cards (green, or red with alerts or
  when unreachable) that you can drag, pin and switch between detailed and compact.
- **Service checks:** websites, ports and ping, with uptime, response times and
  certificate expiry; failures raise alerts.
- **Container logs** next to the metrics (click a chart to jump to that moment) and
  **start/stop/restart** buttons, both opt-in per container.
- **Least privilege:**
  - The web interface runs unprivileged with no host or Docker access, and a separate agent collects the data.
  - Docker is reached through two socket proxies: read-only, and start/stop/restart only.
  - SMART and privileged mode are opt-in.
- **Encrypted agents:** remote agents are paired with a code that pins their certificate.
- **Sign-in:**
  - optional two-factor codes, and your password again for sensitive changes
  - growing delays instead of lockouts, and no sign-in over plain HTTP from public addresses
  - `AUTH_DISABLED` removed
  - a security activity log that also goes to ntfy
- **Hardening:**
  - everything remote servers send is escaped, and pages only run Monitorr's own scripts
  - protection against cross-site requests and clickjacking
  - sessions can be revoked, and login floods are limited
  - files are private, and packages and images are pinned
- **Sandbox** (`docker-compose.dev.yml`) for trying changes before they reach your server.
