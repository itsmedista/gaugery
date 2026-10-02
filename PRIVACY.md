# Privacy and data

Gaugery is software you run on your own servers. **It sends nothing to its authors or to
any third party**: no telemetry, no usage statistics, no crash reports, no update checks, no
analytics, no advertising. Fonts and icons are served by Gaugery itself, so opening a page
contacts nobody but your own server.

Whoever installs and runs Gaugery (the *operator*) decides what it watches and where its
alerts go, and is responsible for that data, for example as the "controller" under the GDPR.
This page lists everything Gaugery stores and every connection it makes, so you can describe
it accurately to the people it concerns.

## What it stores

### The web interface (hub): `hub.db` and `revoked-sessions.json` in its data folder

| Data | Why | Kept |
|---|---|---|
| Username, password (as a salted scrypt hash, never the password itself) | Signing in | Until changed |
| Display name, email address, picture (all optional) | Shown in the account menu. The email is never used to send anything | Until changed or removed in Settings |
| Two-factor secret, recovery codes (only as SHA-256 hashes) | Two-factor sign-in | Until two-factor is turned off |
| Appearance and language choices, overview layout | Your settings | Until changed |
| Security activity: sign-ins from new IP addresses, wrong-password counts with the IP address, changes to servers, checks, containers and security | Lets you spot misuse | 180 days |
| The last 50 IP addresses that signed in | To notice a sign-in from a new address | Last 50 only |
| IDs of signed-out sessions | So a copied cookie stops working | Until that session would have expired |
| Servers you added: name, address, access token, certificate | Connecting to their agents | Until you remove the server |
| Service checks and their results (up/down, response time, error) | Uptime history | Results 30 days |

Wrong-password counters per IP address exist **only in memory** and are gone after a restart.

### Each agent: `metrics.db`

| Data | Kept |
|---|---|
| Per-minute averages of the numbers on the dashboard (CPU, memory, disk, network, temperatures, GPU, per-container CPU/memory). Container, network interface, mount and sensor names appear as labels | `RETENTION_DAYS`, default 14 days |
| Alert history (e.g. "/data is 92% full", "container web exited") | 90 days |

Shown live but **never saved**: the process list (process names, users, PIDs, CPU and
memory), GPU processes, container logs, and hardware details. Container logs have obvious
secrets (passwords, tokens, keys) blanked out before they leave the server.

### In your browser

| Name | Type | Purpose | Lifetime |
|---|---|---|---|
| `gaugery_session` | Cookie: HttpOnly, SameSite=Strict, Secure over HTTPS | Keeps you signed in | 30 days (`SESSION_DAYS`) or until you sign out |
| `gaugery.prefs` | Local storage | Theme, accent colour, language, time format, temperature unit, default time range, so the page draws correctly before it loads your settings. Never your name or email | Until you clear site data |

Both are strictly necessary for the service you asked for, and neither is used for tracking.
Under the EU ePrivacy rules (Article 5(3)) such storage needs no consent, so Gaugery shows
no cookie banner. If you add your own analytics or tracking to it, that changes.

## Connections it makes

Only the ones you set up:

- **Your agents**: the web interface connects to each server you add, over TLS pinned to
  the certificate in its pairing code.
- **Service checks**: the HTTP, TCP, TLS and ping targets you enter. Gaugery won't reach
  the cloud metadata service or the machine's own loopback address.
- **ntfy** (optional): alert and security-event titles and details go to the `NTFY_URL` you
  configure, which is `ntfy.sh` only if you choose it. Set nothing and nothing is sent.
- **Docker** on the same machine, through a read-only socket proxy, to list containers
  (and, if you enabled actions, to start, stop or restart them).

At install and update only, Docker or `pip` download Gaugery's dependencies from Docker
Hub and PyPI.

## Personal data you may be processing

What counts as personal data depends on what you monitor. Common cases:

- **IP addresses** in the security activity, of you and of anyone who tries to sign in.
- **Usernames of people on the monitored servers**, in the live process list.
- **Whatever your applications write to their logs**, if you open container logs.
- **Your own** name, email and picture, if you enter them.

If other people use or are visible in your Gaugery, tell them what it collects (this page
can help), and keep retention no longer than you need.

## Removing data

- **Profile, picture, two-factor**: in Settings.
- **A server or a service check, with its history**: remove it on the overview.
- **Metrics history**: lower `RETENTION_DAYS`; older data is deleted within the hour.
- **Everything**: stop Gaugery and delete its data. With Docker that's the `./data` folder
  and the `hub-data` volume (`docker compose down -v`); without Docker, `/var/lib/gaugery`
  and `/var/lib/gaugery-hub`.
