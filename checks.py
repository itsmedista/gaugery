"""Service checks for Monitorr: is a website, port, or host actually answering?

The hub runs every check itself (agents need nothing new) and files each one under a server,
so a service that's down turns that server's card red and raises a normal alert (and ntfy).
"""
import asyncio
import re
import secrets
import ssl
import time
from urllib.parse import urlsplit

import httpx

from alerts import AlertEngine

KINDS = ("http", "tcp", "ping")
KEEP_DAYS = 30             # result history
CERT_EVERY = 6 * 3600      # how often to re-read an HTTPS certificate's expiry
FAILS_TO_ALERT = 2         # consecutive failures before "down" becomes an alert
MAX_PARALLEL = 20
HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
FIELDS = ("id", "server", "name", "kind", "target", "interval", "timeout", "expect", "keyword",
          "verify_tls", "cert_days", "added")


class CheckError(Exception):
    pass


def parse_expect(spec):
    """'200-399' (default), '200', or '200,204,300-308' -> [(lo, hi), ...]"""
    out = []
    for part in (spec or "200-399").replace(" ", "").split(","):
        lo, _, hi = part.partition("-")
        try:
            lo, hi = int(lo), int(hi or lo)
        except ValueError:
            raise CheckError(f"Expected status '{spec}' isn't like 200, 200-299 or 200,301") from None
        if not 100 <= lo <= hi <= 599:
            raise CheckError(f"Expected status '{spec}' is outside 100-599")
        out.append((lo, hi))
    return out


def _host_port(target):
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit() or not 0 < int(port) < 65536:
        raise CheckError("Write the port as host:port, e.g. 192.168.1.10:22")
    host = host.strip("[]")
    if not host or not HOST_RE.match(host) or host.startswith("-"):
        raise CheckError("That host name doesn't look right")
    return host, int(port)


def validate(body):
    """Clean up a check from the API, or raise CheckError with a sentence for the user."""
    name = str(body.get("name", "")).strip()[:60]
    kind = str(body.get("kind", "http"))
    target = str(body.get("target", "")).strip()
    if not name:
        raise CheckError("Give the check a name")
    if kind not in KINDS:
        raise CheckError("Type must be website, port or ping")
    if kind == "http":
        u = urlsplit(target)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise CheckError("The address must start with http:// or https://")
    elif kind == "tcp":
        _host_port(target)
    elif not HOST_RE.match(target) or target.startswith("-"):  # never let ping see an option
        raise CheckError("Enter a host name or IP address to ping")
    try:
        interval = min(3600, max(20, int(body.get("interval") or 60)))
        timeout = min(60.0, max(1.0, float(body.get("timeout") or 10)))
        cert_days = min(365, max(0, int(body.get("cert_days", 14))))
    except (TypeError, ValueError):
        raise CheckError("Interval, timeout and certificate days must be numbers") from None
    expect = str(body.get("expect") or "").strip()
    if kind == "http":
        parse_expect(expect)
    return {"name": name, "kind": kind, "target": target, "interval": interval,
            "timeout": min(timeout, interval - 5), "expect": expect if kind == "http" else "",
            "keyword": str(body.get("keyword") or "")[:200] if kind == "http" else "",
            "verify_tls": 1 if body.get("verify_tls", True) else 0, "cert_days": cert_days}


class Checks:
    def __init__(self, db, db_lock, server_name):
        self.db, self.db_lock, self.server_name = db, db_lock, server_name
        with self.db_lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS checks (id TEXT PRIMARY KEY, server TEXT, name TEXT, "
                            "kind TEXT, target TEXT, interval INTEGER, timeout REAL, expect TEXT, keyword TEXT, "
                            "verify_tls INTEGER, cert_days INTEGER, added REAL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS check_results (cid TEXT, ts REAL, ok INTEGER, ms REAL, detail TEXT)")
            self.db.execute("CREATE INDEX IF NOT EXISTS check_results_cid_ts ON check_results (cid, ts)")
            self.db.commit()
            rows = self.db.execute(f"SELECT {', '.join(FIELDS)} FROM checks ORDER BY added").fetchall()
        self.checks = {r[0]: dict(zip(FIELDS, r)) for r in rows}
        self.state = {cid: self._blank() for cid in self.checks}
        self.next_run = dict.fromkeys(self.checks, 0.0)
        self.engines, self.alerts = {}, {}   # per server: an AlertEngine and its active service alerts
        self._http = {v: httpx.AsyncClient(verify=v, follow_redirects=True,
                                           headers={"User-Agent": "Monitorr service check"}) for v in (True, False)}
        self._pruned = 0.0

    @staticmethod
    def _blank():
        return {"status": "pending", "ms": None, "detail": "Not checked yet", "last": None, "since": None,
                "fails": 0, "cert_expires": None, "cert_checked": 0.0}

    # ---------- registry ----------
    def create(self, server, body):
        c = {"id": secrets.token_hex(4), "server": server, **validate(body), "added": time.time()}
        with self.db_lock:
            self.db.execute(f"INSERT INTO checks VALUES ({', '.join('?' * len(FIELDS))})", [c[f] for f in FIELDS])
            self.db.commit()
        self.checks[c["id"]], self.state[c["id"]] = c, self._blank()
        self.next_run[c["id"]] = time.time() + c["interval"]  # the API runs it right away itself
        return c["id"]

    def update(self, cid, body):
        c = self.checks[cid]
        new = validate(body)
        # results measured against a different address or pass rule would skew uptime
        changed_target = any(new[k] != c[k] for k in ("kind", "target", "expect", "keyword", "verify_tls"))
        c.update(new)
        with self.db_lock:
            self.db.execute(f"UPDATE checks SET {', '.join(f'{k} = ?' for k in new)} WHERE id = ?", [*new.values(), cid])
            if changed_target:  # old results describe something else now
                self.db.execute("DELETE FROM check_results WHERE cid = ?", (cid,))
            self.db.commit()
        if changed_target:
            self.state[cid] = self._blank()
        self.next_run[cid] = time.time() + c["interval"]

    def delete(self, cid):
        c = self.checks.pop(cid, None)
        if not c:
            return False
        self.state.pop(cid, None)
        self.next_run.pop(cid, None)
        with self.db_lock:
            self.db.execute("DELETE FROM checks WHERE id = ?", (cid,))
            self.db.execute("DELETE FROM check_results WHERE cid = ?", (cid,))
            self.db.commit()
        self._evaluate(c["server"])  # resolves its alerts
        return True

    def delete_server(self, server):
        for cid in [cid for cid, c in self.checks.items() if c["server"] == server]:
            self.delete(cid)
        self.engines.pop(server, None)
        self.alerts.pop(server, None)

    # ---------- reading ----------
    def listing(self, server):
        ids = [cid for cid, c in self.checks.items() if c["server"] == server]
        now = time.time()
        with self.db_lock:
            up = {span: dict(self.db.execute(
                "SELECT cid, AVG(ok) * 100 FROM check_results WHERE ts >= ? GROUP BY cid", (now - span,)).fetchall())
                for span in (86400, 7 * 86400)}
            recent = {cid: self.db.execute("SELECT ts, ok, ms FROM check_results WHERE cid = ? ORDER BY ts DESC LIMIT 40",
                                           (cid,)).fetchall()[::-1] for cid in ids}
        out = []
        for cid in ids:
            st = {k: v for k, v in self.state[cid].items() if k != "cert_checked"}
            out.append({**self.checks[cid], **st, "verify_tls": bool(self.checks[cid]["verify_tls"]),
                        "uptime_24h": up[86400].get(cid), "uptime_7d": up[7 * 86400].get(cid),
                        "recent": recent[cid]})
        return out

    def summary(self, server):
        sts = [self.state[cid]["status"] for cid, c in self.checks.items() if c["server"] == server]
        return {"total": len(sts), "up": sts.count("up"), "down": sts.count("down"), "pending": sts.count("pending"),
                "alerts": self.alerts.get(server, [])}

    # ---------- running ----------
    async def run(self):
        sem = asyncio.Semaphore(MAX_PARALLEL)

        async def one(c):
            async with sem:
                await self.run_now(c["id"])

        while True:
            now = time.time()
            for cid, c in list(self.checks.items()):
                if self.next_run.get(cid, 0) <= now:
                    self.next_run[cid] = now + c["interval"]
                    asyncio.create_task(one(c))
            if now - self._pruned > 3600:
                self._pruned = now
                with self.db_lock:
                    self.db.execute("DELETE FROM check_results WHERE ts < ?", (now - KEEP_DAYS * 86400,))
                    self.db.commit()
            await asyncio.sleep(1)

    async def run_now(self, cid):
        c = self.checks.get(cid)
        if not c:
            return None
        t0 = time.perf_counter()
        try:
            ok, detail, ms = await asyncio.wait_for(self._probe(c), c["timeout"] + 2)
        except asyncio.TimeoutError:
            ok, detail, ms = False, f"No answer within {c['timeout']:g}s", None
        except Exception as e:  # noqa: BLE001  a check must never take the runner down
            ok, detail, ms = False, f"Check failed: {type(e).__name__}", None
        if ok and ms is None:
            ms = (time.perf_counter() - t0) * 1000
        if cid not in self.checks:  # deleted while it ran
            return None
        st, now = self.state[cid], time.time()
        status = "up" if ok else "down"
        if status != st["status"]:
            st["since"] = now
        st.update(status=status, ms=round(ms, 1) if ok else None, detail=detail, last=now,
                  fails=0 if ok else st["fails"] + 1)
        if ok and c["kind"] == "http" and c["target"].startswith("https://") and c["verify_tls"] \
                and now - st["cert_checked"] > CERT_EVERY:
            st["cert_checked"] = now
            st["cert_expires"] = await self._cert_expiry(c["target"])
        with self.db_lock:
            self.db.execute("INSERT INTO check_results VALUES (?, ?, ?, ?, ?)",
                            (cid, now, int(ok), st["ms"], detail))
            self.db.commit()
        self._evaluate(c["server"])
        return st

    async def _probe(self, c):
        """-> (ok, detail, ms or None to use wall time)"""
        t = c["timeout"]
        if c["kind"] == "http":
            try:
                r = await self._http[bool(c["verify_tls"])].get(c["target"], timeout=t)
            except httpx.TimeoutException:
                return False, f"No answer within {t:g}s", None
            except httpx.HTTPError as e:
                msg = str(e) or type(e).__name__
                if "CERTIFICATE_VERIFY_FAILED" in msg:
                    return False, "Certificate isn't trusted (turn off verification for self-signed ones)", None
                return False, "Can't connect: " + msg[:120], None
            if not any(lo <= r.status_code <= hi for lo, hi in parse_expect(c["expect"])):
                return False, f"Answered HTTP {r.status_code}, expected {c['expect'] or '200-399'}", None
            if c["keyword"] and c["keyword"] not in r.text:
                return False, f"HTTP {r.status_code}, but \"{c['keyword']}\" isn't on the page", None
            return True, f"HTTP {r.status_code}", None
        if c["kind"] == "tcp":
            host, port = _host_port(c["target"])
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(host, port), t)
            except asyncio.TimeoutError:
                return False, f"No answer within {t:g}s", None
            except ConnectionRefusedError:
                return False, f"Port {port} refused the connection", None
            except OSError as e:
                return False, f"Can't connect: {e.strerror or e}", None
            w.close()
            return True, f"Port {port} is open", None
        # ping
        try:
            p = await asyncio.create_subprocess_exec("ping", "-c", "1", "-W", str(max(1, round(t))), c["target"],
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        except FileNotFoundError:
            return False, "ping isn't installed where Monitorr runs", None
        out = (await p.communicate())[0].decode(errors="replace")
        if p.returncode != 0:
            unknown = any(w in out.lower() for w in ("unknown host", "not known", "name resolution", "resolve"))
            return False, "Unknown host" if unknown else "No reply", None
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", out)
        return True, "Replied", float(m.group(1)) if m else None

    @staticmethod
    async def _cert_expiry(url):
        u = urlsplit(url)
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(
                u.hostname, u.port or 443, ssl=ssl.create_default_context(), server_hostname=u.hostname), 10)
            cert = w.get_extra_info("peercert")
            w.close()
            return ssl.cert_time_to_seconds(cert["notAfter"])
        except Exception:  # noqa: BLE001  the page answered; expiry is a bonus
            return None

    # ---------- alerts ----------
    def _evaluate(self, server):
        now, items = time.time(), []
        for cid, c in self.checks.items():
            if c["server"] != server:
                continue
            st = self.state[cid]
            items.append((f"svc:{cid}", st["fails"] >= FAILS_TO_ALERT, "critical", f"{c['name']} is down",
                          f"{st['detail']} ({c['target']})"))
            exp = st["cert_expires"]
            if c["cert_days"] and exp:
                days = (exp - now) / 86400
                items.append((f"cert:{cid}", days < c["cert_days"], "critical" if days < 3 else "warning",
                              f"{c['name']}: certificate " + ("has expired" if days < 0 else f"expires in {days:.0f} days"),
                              f"Renew the certificate for {urlsplit(c['target']).hostname}."))
        engine = self.engines.get(server)
        if engine is None:
            engine = self.engines[server] = AlertEngine(self.server_name(server) or server, 0)
        self.alerts[server] = engine.evaluate_items(items, now)["active"]

    async def close(self):
        for client in self._http.values():
            await client.aclose()
