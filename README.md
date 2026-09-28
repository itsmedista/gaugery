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

## Login

- One user: `AUTH_USER` (default `admin`) and `AUTH_PASSWORD_HASH`, a scrypt hash
  made by `python app.py --hash-password`. The plain password is never stored.
- Sessions last `SESSION_DAYS` (default 30). Changing the password signs everyone out.
- Five wrong passwords from one address lock it out for five minutes.
- `AUTH_DISABLED=true` turns the login off, e.g. if a reverse proxy already handles it.
- Over plain HTTP the password crosses the network unencrypted. Use it over
  Tailscale (encrypted) or put HTTPS in front of it.

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
history in `./data-dev`. It never sends phone alerts.

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
