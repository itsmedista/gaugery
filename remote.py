"""The servers a Monitorr hub watches. Each runs the Monitorr agent; the hub polls their summaries
for the overview and relays their API to the dashboard.

This machine's agent is reached over a Unix socket (LOCAL_AGENT). Other agents are reached over
TLS, trusting only the certificate whose fingerprint came with their pairing code.
"""
import asyncio
import hmac
import math
import secrets
import ssl
import time
from urllib.parse import urlsplit

import httpx

import netguard
import tlsutil

POLL_SECONDS = 5
# The only agent endpoints the hub relays for the dashboard. Each agent still decides for
# itself whether logs and container actions are allowed, and for which containers.
AGENT_PATHS = {"info", "recent", "state", "history", "stream", "summary", "logs", "logstream", "container-action"}
STREAM_PATHS = {"stream", "logstream"}
TIMEOUT = httpx.Timeout(8, connect=4)


class AgentError(Exception):
    pass


def _num(v, lo=0.0, hi=1e15):
    return float(min(hi, max(lo, v))) if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) else None


def _str(v, n=200):
    return v[:n] if isinstance(v, str) else ""


def clean_summary(j):
    """An agent's summary, reduced to exactly the fields, types and sizes the overview uses.
    A hacked agent can lie about its numbers, but it can't break the hub or inject markup through it."""
    if not isinstance(j, dict):
        raise AgentError("The agent's summary isn't in the expected format")
    a = j.get("alerts") if isinstance(j.get("alerts"), dict) else {}
    top = [{"severity": "critical" if t.get("severity") == "critical" else "warning", "title": _str(t.get("title"))}
           for t in (a.get("top") if isinstance(a.get("top"), list) else [])[:3] if isinstance(t, dict)]
    c = j.get("containers")
    ctrs = None
    if isinstance(c, dict) and _num(c.get("running")) is not None and _num(c.get("total")) is not None:
        ctrs = {"running": int(_num(c["running"], hi=1e5)), "total": int(_num(c["total"], hi=1e5))}
    return {"hostname": _str(j.get("hostname"), 100), "os": _str(j.get("os"), 100),
            "t": _num(j.get("t")) or 0.0, "uptime": _num(j.get("uptime")) or 0.0,
            "cpu": _num(j.get("cpu"), hi=100), "mem": _num(j.get("mem"), hi=100), "disk": _num(j.get("disk"), hi=100),
            "containers": ctrs,
            "alerts": {"critical": int(_num(a.get("critical"), hi=1e5) or 0),
                       "warning": int(_num(a.get("warning"), hi=1e5) or 0), "top": top}}


class Remotes:
    def __init__(self, db, db_lock, local_url=None, local_token=None):
        self.db, self.db_lock = db, db_lock
        with self.db_lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS servers "
                            "(id TEXT PRIMARY KEY, name TEXT, url TEXT, token TEXT, added REAL, cert TEXT)")
            cols = {r[1] for r in self.db.execute("PRAGMA table_info(servers)")}
            if "cert" not in cols:
                self.db.execute("ALTER TABLE servers ADD COLUMN cert TEXT")
            self.db.commit()
            rows = self.db.execute("SELECT id, name, url, token, cert FROM servers ORDER BY added").fetchall()
        self.servers = {}
        if local_url:
            self.servers["local"] = {"id": "local", "name": None, "url": local_url, "token": local_token,
                                     "cert": None, "local": True}
        for r in rows:
            self.servers[r[0]] = {"id": r[0], "name": r[1], "url": r[2], "token": r[3], "cert": r[4], "local": False}
        self.status = {}  # id -> {"online", "error", "summary", "checked"}
        self._clients = {}

    def name(self, sid):
        srv = self.servers.get(sid)
        if not srv:
            return None
        if srv["local"]:
            return ((self.status.get(sid) or {}).get("summary") or {}).get("hostname") or "This server"
        return srv["name"]

    # ---------- registry ----------
    async def add(self, name, address, pairing):
        name = name.strip()[:60]
        if not name:
            raise AgentError("Give the server a name")
        try:
            fingerprint, token = tlsutil.parse_pairing(pairing)
        except ValueError as e:
            raise AgentError(str(e)) from None
        address = address.strip().rstrip("/")
        if "://" not in address:
            address = "https://" + address
        u = urlsplit(address)
        if u.scheme != "https" or not u.hostname:
            raise AgentError("Use the address the agent printed, like https://192.168.1.20:8088")
        port = u.port or 8088
        host = f"[{u.hostname}]" if ":" in u.hostname else u.hostname
        url = f"https://{host}:{port}"
        try:
            ip = (await netguard.resolve(u.hostname, port, limit_to_allowed=False))[0]
            der = await tlsutil.fetch_cert(ip, port)
        except netguard.Blocked as e:
            raise AgentError(str(e)) from None
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            raise AgentError(f"Can't reach {url} ({type(e).__name__}). Is the agent running, and is the port open?") from None
        if not hmac.compare_digest(tlsutil.fingerprint_der(der), fingerprint):
            raise AgentError("The certificate at this address doesn't match the pairing code. Check the address; "
                             "if it's right, something between you and the agent is intercepting the connection.")
        srv = {"id": secrets.token_hex(4), "name": name, "url": url, "token": token,
               "cert": ssl.DER_cert_to_PEM_cert(der), "local": False}
        try:
            summary = await self.fetch_summary(srv)  # proves the token too
        except AgentError:
            await self._drop_client(srv["id"])
            raise
        with self.db_lock:
            self.db.execute("INSERT INTO servers (id, name, url, token, added, cert) VALUES (?, ?, ?, ?, ?, ?)",
                            (srv["id"], name, url, token, time.time(), srv["cert"]))
            self.db.commit()
        self.servers[srv["id"]] = srv
        self.status[srv["id"]] = {"online": True, "error": None, "summary": summary, "checked": time.time()}
        return srv["id"]

    def import_rows(self, rows):
        """Servers from before encrypted connections: kept so their checks and place survive,
        but they must be paired again before the hub talks to them."""
        with self.db_lock:
            for r in rows:
                self.db.execute("INSERT OR IGNORE INTO servers (id, name, url, token, added, cert) "
                                "VALUES (?, ?, ?, ?, ?, NULL)", (r["id"], r["name"], r["url"], r["token"], r["added"]))
                self.servers.setdefault(r["id"], {"id": r["id"], "name": r["name"], "url": r["url"],
                                                  "token": r["token"], "cert": None, "local": False})
            self.db.commit()

    async def remove(self, sid):
        srv = self.servers.get(sid)
        if not srv or srv["local"]:
            return False
        del self.servers[sid]
        self.status.pop(sid, None)
        await self._drop_client(sid)
        with self.db_lock:
            self.db.execute("DELETE FROM servers WHERE id = ?", (sid,))
            self.db.commit()
        return True

    def listing(self):
        out = []
        for sid, srv in self.servers.items():
            st = self.status.get(sid, {"online": None, "error": None, "summary": None, "checked": None})
            out.append({"id": sid, "name": self.name(sid), "url": None if srv["local"] else srv["url"],
                        "local": srv["local"], **st})
        return out

    # ---------- talking to agents ----------
    def _client(self, srv):
        c = self._clients.get(srv["id"])
        if c:
            return c
        url = srv["url"]
        if url.startswith("unix:"):
            c = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=url[5:]), base_url="http://agent",
                                  timeout=TIMEOUT)
        elif url.startswith("https://") and srv.get("cert"):
            c = httpx.AsyncClient(verify=tlsutil.pinned_context(srv["cert"]), base_url=url, timeout=TIMEOUT)
        else:
            raise AgentError("This server was added before connections were encrypted. Remove it and add it "
                             "again with the pairing code its agent prints.")
        self._clients[srv["id"]] = c
        return c

    async def _drop_client(self, sid):
        c = self._clients.pop(sid, None)
        if c:
            await c.aclose()

    def _headers(self, srv):
        return {"Authorization": f"Bearer {srv['token']}"}

    @staticmethod
    def _check(r):
        if r.status_code == 401:
            raise AgentError("The agent rejected the token")
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail")  # the agent's own explanation, e.g. "No container named x"
            except Exception:  # noqa: BLE001
                detail = None
            raise AgentError(str(detail)[:300] if detail else (
                "No Monitorr agent answered at this address" if r.status_code == 404
                else f"The agent answered {r.status_code}"))

    async def _send(self, srv, method, path, **kw):
        try:
            r = await self._client(srv).request(method, f"/api/{path}", headers=self._headers(srv), **kw)
        except httpx.HTTPError as e:
            if "CERTIFICATE_VERIFY_FAILED" in str(e):  # not the certificate it was paired with
                raise AgentError(f"{srv['name'] or 'The agent'} presented a different certificate than when it "
                                 "was paired, so Monitorr refused the connection.") from None
            raise AgentError(f"Can't reach {srv['name'] or 'this server'} ({type(e).__name__})") from None
        self._check(r)
        return r

    async def fetch_summary(self, srv):
        r = await self._send(srv, "GET", "summary")
        try:
            return clean_summary(r.json())
        except ValueError:
            raise AgentError("The address answered, but not like a Monitorr agent") from None

    async def get(self, sid, path, params):
        return await self._send(self.servers[sid], "GET", path, params=params)

    async def post(self, sid, path, body):
        return await self._send(self.servers[sid], "POST", path, json=body, timeout=httpx.Timeout(45, connect=4))

    async def stream(self, sid, path="stream", params=None):
        srv = self.servers[sid]
        # logs can go quiet for a long time, so only the metrics stream has a read timeout
        read = 30 if path == "stream" else None
        client = self._client(srv)
        req = client.build_request("GET", f"/api/{path}", params=params, headers=self._headers(srv),
                                   timeout=httpx.Timeout(8, connect=4, read=read))
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            raise AgentError(f"Can't reach {srv['name'] or 'this server'} ({type(e).__name__})") from None
        if resp.status_code != 200:
            await resp.aread()
            await resp.aclose()
            self._check(resp)
        return resp

    # ---------- background polling ----------
    async def run(self):
        while True:
            await asyncio.gather(*(self._poll(sid) for sid in list(self.servers)), return_exceptions=True)
            await asyncio.sleep(POLL_SECONDS)

    async def _poll(self, sid):
        srv = self.servers.get(sid)
        if not srv:
            return
        prev = self.status.get(sid, {})
        try:
            summary = await self.fetch_summary(srv)
            st = {"online": True, "error": None, "summary": summary}
        except AgentError as e:
            # keep the last numbers so the card still says what the server looked like
            st = {"online": False, "error": str(e), "summary": prev.get("summary")}
        if sid in self.servers:
            self.status[sid] = {**st, "checked": time.time()}

    async def close(self):
        for sid in list(self._clients):
            await self._drop_client(sid)
