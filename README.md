# Server Monitor

A monitoring dashboard for one Linux server. It samples every 2 seconds,
keeps per-minute history in SQLite, and serves a live web page.

## Install with Docker (recommended)

    tar xzf server-monitor.tar.gz && cd server-monitor
    docker compose up -d --build

Open `http://<server-ip>:8088`. Settings are the `environment:` block in
`docker-compose.yml`; apply changes with `docker compose up -d`.
History is kept in `./data`.

To keep it private to your tailnet, set `HOST` to the output of `tailscale ip -4`.

Why the container needs host access: it uses host networking (real interface
traffic), the host PID namespace (processes and mount table), a read-only view of
`/` at `/host` (drive space for every mount), the Docker socket (container stats),
and privileged mode (SMART). See the comments in `docker-compose.yml` for a
less-privileged option.

Update after changing files: `docker compose up -d --build`
Logs: `docker logs -f server-monitor`

## Install without Docker (systemd)

    sudo ./install.sh

Settings then live in `/etc/server-monitor.env`.

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
