"""Who may reach this server: its firewall rules and its Tailscale setup. Read-only, by design.

Firewall: read from ufw's and firewalld's own configuration files, so the agent needs no extra
privileges (listing the live kernel rules would need CAP_NET_ADMIN, which can also change them).

Tailscale: two GET requests to tailscaled's local API, nothing else. Under Docker the agent never
touches tailscaled's socket: a separate container running as `nobody` asks, and tailscaled itself
refuses any change from a non-root user. That container writes the answer to a file the agent
reads (see docker-compose.tailscale.yml). Without Docker the agent asks directly.
"""
import http.client
import json
import os
import socket
import time
import xml.etree.ElementTree as ET

from collectors import hp

TS_SOCKET = os.environ.get("TAILSCALE_SOCKET", "/run/tailscale/tailscaled.sock")
TS_STATUS_FILE = os.environ.get("TAILSCALE_STATUS_FILE", "")   # set when a separate reader writes it
MAX_FILE = 512 * 1024
MAX_ROWS = 200


def _read(path, limit=MAX_FILE):
    try:
        with open(path, "rb") as f:
            return f.read(limit).decode("utf-8", "replace")
    except OSError:
        return None


def _s(v, n=200):
    return v[:n] if isinstance(v, str) else ""


def _kv(text):
    """KEY=value lines (shell style, quotes stripped)."""
    out = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("\"'")
    return out


def _unit_enabled(name):
    return any(os.path.lexists(hp(f"/etc/systemd/system/{t}.target.wants/{name}.service"))
               for t in ("multi-user", "sysinit", "network-pre"))


# ---------------- ufw ----------------
ANY_ADDR = {"0.0.0.0/0", "::/0", "any"}


def parse_ufw_rules(text):
    """The `### tuple ###` lines ufw writes to user.rules / user6.rules."""
    rules = []
    for line in (text or "").splitlines():
        if not line.startswith("### tuple ###"):
            continue
        t = line.split()[3:]
        comment = ""
        if t and t[-1].startswith("comment="):
            try:
                comment = bytes.fromhex(t.pop()[8:]).decode("utf-8", "replace")
            except ValueError:
                comment = ""
        if len(t) not in (7, 9):
            continue
        action, proto, dport, dst, sport, src = t[:6]
        app_to, app_from = (t[6], t[7]) if len(t) == 9 else ("-", "-")
        direction, _, iface = t[-1].partition("_")
        route = action.startswith("route:")
        action = action.split(":")[-1].split("_")[0]          # "allow_log" -> "allow"
        rules.append({
            "action": action if action in ("allow", "deny", "reject", "limit") else "other",
            "route": route,
            "direction": "out" if direction == "out" else "in",
            "interface": iface[:40],
            "proto": proto[:10],
            "to": "any" if dst in ANY_ADDR else dst[:60],
            "port": "" if dport == "any" else dport[:60],
            "app": "" if app_to == "-" else app_to.replace("%20", " ")[:60],
            "from": "any" if src in ANY_ADDR else src[:60],
            "from_port": "" if sport == "any" else sport[:60],
            "from_app": "" if app_from == "-" else app_from.replace("%20", " ")[:60],
            "comment": comment[:200],
        })
    return rules


def ufw():
    conf = _read(hp("/etc/ufw/ufw.conf"))
    if conf is None:
        return None
    seen, rules = set(), []
    for name in ("user.rules", "user6.rules"):           # IPv4 and IPv6 copies of mostly the same rules
        for r in parse_ufw_rules(_read(hp(f"/etc/ufw/{name}"))):
            key = json.dumps(r, sort_keys=True)
            if key not in seen:
                seen.add(key)
                rules.append(r)
    d = _kv(_read(hp("/etc/default/ufw")))
    pol = lambda k: d.get(k, "").lower().replace("accept", "allow").replace("drop", "deny")
    return {"manager": "ufw", "enabled": _kv(conf).get("ENABLED", "").lower() == "yes",
            "defaults": {"in": pol("DEFAULT_INPUT_POLICY"), "out": pol("DEFAULT_OUTPUT_POLICY"),
                         "routed": pol("DEFAULT_FORWARD_POLICY")},
            "rules": rules[:MAX_ROWS], "truncated": len(rules) > MAX_ROWS}


# ---------------- firewalld ----------------
def _rich(el):
    """A firewalld rich rule as a short readable line."""
    parts = [el.get("family", "")]
    for tag, word in (("source", "from"), ("destination", "to")):
        x = el.find(tag)
        if x is not None:
            what = x.get("address") or x.get("ipset") or x.get("mac") or ""
            parts.append(f"{word} {'not ' if x.get('invert') == 'true' else ''}{what}")
    for tag in ("service", "port", "protocol", "forward-port", "icmp-block", "masquerade"):
        x = el.find(tag)
        if x is not None:
            v = x.get("name") or (f"{x.get('port')}/{x.get('protocol')}" if x.get("port") else x.get("value")) or ""
            parts.append(f"{tag} {v}".strip())
    action = next((a.tag for a in el if a.tag in ("accept", "reject", "drop", "mark")), "")
    return " ".join(p for p in parts if p)[:200], action or "other"


def parse_firewalld_zone(text, name):
    root = ET.fromstring(text)
    target = (root.get("target") or "default").lower()
    rows = []
    for s in root.findall("service"):
        rows.append({"action": "allow", "what": f"service {s.get('name', '')}"[:100]})
    for p in root.findall("port"):
        rows.append({"action": "allow", "what": f"port {p.get('port', '')}/{p.get('protocol', '')}"[:100]})
    for r in root.findall("rule"):
        text_, action = _rich(r)
        rows.append({"action": {"accept": "allow", "drop": "deny"}.get(action, action), "what": text_})
    return {"zone": name[:60], "target": target[:20],
            "interfaces": [i.get("name", "")[:40] for i in root.findall("interface")][:20],
            "sources": [s.get("address", "")[:60] for s in root.findall("source") if s.get("address")][:50],
            "rows": rows[:MAX_ROWS]}


def firewalld():
    conf = _read(hp("/etc/firewalld/firewalld.conf"))
    if conf is None:
        return None
    default = _kv(conf).get("DefaultZone", "public")
    names = {default}
    try:
        names |= {f[:-4] for f in os.listdir(hp("/etc/firewalld/zones")) if f.endswith(".xml")}
    except OSError:
        pass
    zones = []
    for n in sorted(names, key=lambda z: (z != default, z))[:20]:
        if "/" in n or n.startswith("."):
            continue
        text = _read(hp(f"/etc/firewalld/zones/{n}.xml")) or _read(hp(f"/usr/lib/firewalld/zones/{n}.xml"))
        if not text:
            continue
        try:
            z = parse_firewalld_zone(text, n)
        except ET.ParseError:
            continue
        z["default"] = n == default
        zones.append(z)
    return {"manager": "firewalld", "enabled": _unit_enabled("firewalld"), "zones": zones}


def firewall():
    found = [x for x in (ufw(), firewalld()) if x]
    other = []
    if _unit_enabled("nftables"):
        other.append("nftables")
    if os.path.exists(hp("/etc/iptables/rules.v4")) or os.path.exists(hp("/etc/sysconfig/iptables")):
        other.append("iptables")
    return {"managers": found, "other": other}


# ---------------- Tailscale ----------------
class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout=3):
        super().__init__("local-tailscaled.sock", timeout=timeout)  # the Host tailscaled expects
        self._path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._path)


def _ts_get(path, sock):
    """GET only, to fixed paths; nothing here can change tailscaled's settings."""
    c = _UnixHTTP(sock)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read(8 * 2**20 + 1)
    finally:
        c.close()
    if len(body) > 8 * 2**20:
        raise ValueError("answer too large")
    return r.status, body


def tailscale_raw(sock=TS_SOCKET):
    """{"status": ..., "serve": ...} straight from tailscaled, or {"error": ...}."""
    if not os.path.exists(sock):
        return {"error": "not installed"}
    try:
        st, body = _ts_get("/localapi/v0/status", sock)
        if st != 200:
            return {"error": f"tailscaled answered {st}"}
        out = {"status": json.loads(body)}
        st, body = _ts_get("/localapi/v0/serve-config", sock)
        out["serve"] = json.loads(body) if st == 200 and body.strip() else ({} if st == 200 else None)
        return out
    except (OSError, ValueError, http.client.HTTPException) as e:
        return {"error": f"can't reach tailscaled ({type(e).__name__})"}


def _serve_rows(cfg, out, funnel_from=None):
    if not isinstance(cfg, dict):
        return
    funnel = {**(funnel_from or {}), **(cfg.get("AllowFunnel") or {})}
    tcp = cfg.get("TCP") or {}
    for port, h in tcp.items():
        if isinstance(h, dict) and h.get("TCPForward"):
            out.append({"port": _s(str(port), 8), "path": "", "kind": "tcp", "target": _s(h["TCPForward"]),
                        "public": any(k.endswith(f":{port}") and v for k, v in funnel.items())})
    for hostport, web in (cfg.get("Web") or {}).items():
        if not isinstance(web, dict):
            continue
        port = str(hostport).rsplit(":", 1)[-1]
        http_only = isinstance(tcp.get(port), dict) and tcp[port].get("HTTP")
        for mount, h in (web.get("Handlers") or {}).items():
            if not isinstance(h, dict):
                continue
            target = h.get("Proxy") or (f"files: {h['Path']}" if h.get("Path") else "") or ("text" if "Text" in h else "")
            out.append({"port": _s(port, 8), "path": _s(str(mount), 100), "kind": "http" if http_only else "https",
                        "target": _s(target), "public": bool(funnel.get(hostport))})
    for fg in (cfg.get("Foreground") or {}).values():   # `tailscale serve` sessions running in a terminal
        _serve_rows(fg, out, funnel)


def _peer(p):
    tags = p.get("Tags") if isinstance(p.get("Tags"), list) else []
    return {"name": _s(p.get("HostName"), 80), "dns": _s(p.get("DNSName"), 120).rstrip("."),
            "ips": [_s(i, 45) for i in (p.get("TailscaleIPs") or [])[:2] if isinstance(i, str)],
            "os": _s(p.get("OS"), 30), "online": bool(p.get("Online")),
            "exit_node": bool(p.get("ExitNode")), "exit_option": bool(p.get("ExitNodeOption")),
            "last_seen": _s(p.get("LastSeen"), 40), "tags": [_s(t, 60) for t in tags[:10] if isinstance(t, str)],
            "key_expiry": _s(p.get("KeyExpiry"), 40)}


def clean_tailscale(raw):
    """Only the fields the page shows: no keys, no account emails, sizes capped. Also used on
    whatever the reader container wrote, which the agent doesn't trust blindly."""
    if not isinstance(raw, dict):
        return {"error": "unreadable"}
    if raw.get("error"):
        return {"error": _s(raw["error"])}
    st = raw.get("status") if isinstance(raw.get("status"), dict) else {}
    me = st.get("Self") if isinstance(st.get("Self"), dict) else {}
    tn = st.get("CurrentTailnet") if isinstance(st.get("CurrentTailnet"), dict) else {}
    peers = [_peer(p) for p in (st.get("Peer") or {}).values() if isinstance(p, dict)]
    peers.sort(key=lambda p: (not p["online"], p["name"].lower()))
    serve = []
    if isinstance(raw.get("serve"), dict):
        _serve_rows(raw["serve"], serve)
    return {
        "state": _s(st.get("BackendState"), 30), "version": _s(st.get("Version"), 60).split("-")[0],
        "self": _peer(me), "tailnet": _s(tn.get("Name"), 100), "magic_dns": bool(tn.get("MagicDNSEnabled")),
        "health": [_s(h, 300) for h in (st.get("Health") or [])[:10] if isinstance(h, str)],
        "exit_node": next((p["name"] for p in peers if p["exit_node"]), ""),
        "peers": peers[:MAX_ROWS], "peer_count": len(peers),
        "serve": serve[:100], "serve_known": isinstance(raw.get("serve"), dict),
    }


def tailscale():
    if TS_STATUS_FILE:   # written by the separate reader (Docker)
        text = _read(TS_STATUS_FILE, 16 * 2**20)
        if text is None:
            return {"error": "no status from the Tailscale reader yet"}
        try:
            data = json.loads(text)
        except ValueError:
            return {"error": "unreadable status from the Tailscale reader"}
        out = clean_tailscale(data)
        t = data.get("t") if isinstance(data, dict) else None
        age = time.time() - (t if isinstance(t, (int, float)) else 0)
        if age > 180:
            out["stale"] = int(age)
        return out
    return clean_tailscale(tailscale_raw())


def run_reader(path, interval=30):
    """The Docker reader: as `nobody`, ask tailscaled every 30 s and write the answer to `path`."""
    tmp = path + ".tmp"
    while True:
        data = {"t": time.time(), **tailscale_raw()}
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)
        time.sleep(interval)


def snapshot():
    return {"t": time.time(), "firewall": firewall(), "tailscale": tailscale()}
