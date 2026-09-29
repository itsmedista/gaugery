"""Remote servers for Monitorr: each one runs Monitorr as an agent (AGENT_TOKEN set), and this
instance polls their summaries for the overview and relays their API to the dashboard."""
import asyncio
import math
import secrets
import time

import httpx

POLL_SECONDS = 5
# The only agent endpoints the hub relays (and the only ones an agent token unlocks).
# Each agent still decides for itself whether logs and container actions are allowed.
AGENT_PATHS = {"info", "recent", "state", "history", "stream", "summary", "logs", "logstream", "container-action"}
STREAM_PATHS = {"stream", "logstream"}


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
    def __init__(self, db, db_lock):
        self.db, self.db_lock = db, db_lock
        with self.db_lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS servers "
                            "(id TEXT PRIMARY KEY, name TEXT, url TEXT, token TEXT, added REAL)")
            self.db.commit()
            rows = self.db.execute("SELECT id, name, url, token FROM servers ORDER BY added").fetchall()
        self.servers = {r[0]: {"id": r[0], "name": r[1], "url": r[2], "token": r[3]} for r in rows}
        self.status = {}  # id -> {"online", "error", "summary", "checked"}
        self.client = httpx.AsyncClient(timeout=httpx.Timeout(8, connect=4))

    # ---------- registry ----------
    async def add(self, name, url, token):
        name, url, token = name.strip(), url.strip().rstrip("/"), token.strip()
        if not name or not token:
            raise AgentError("Name and token are required")
        if not url.startswith(("http://", "https://")):
            raise AgentError("The address must start with http:// or https://")
        srv = {"id": secrets.token_hex(4), "name": name, "url": url, "token": token}
        summary = await self.fetch_summary(srv)  # refuse servers we can't read
        with self.db_lock:
            self.db.execute("INSERT INTO servers VALUES (?, ?, ?, ?, ?)",
                            (srv["id"], name, url, token, time.time()))
            self.db.commit()
        self.servers[srv["id"]] = srv
        self.status[srv["id"]] = {"online": True, "error": None, "summary": summary, "checked": time.time()}
        return srv["id"]

    def remove(self, sid):
        if self.servers.pop(sid, None) is None:
            return False
        self.status.pop(sid, None)
        with self.db_lock:
            self.db.execute("DELETE FROM servers WHERE id = ?", (sid,))
            self.db.commit()
        return True

    def listing(self):
        out = []
        for sid, srv in self.servers.items():
            st = self.status.get(sid, {"online": None, "error": None, "summary": None, "checked": None})
            out.append({"id": sid, "name": srv["name"], "url": srv["url"], "local": False, **st})
        return out

    # ---------- talking to agents ----------
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
            raise AgentError(detail or ("No Monitorr agent answered at this address" if r.status_code == 404
                                        else f"The agent answered {r.status_code}"))

    async def fetch_summary(self, srv):
        try:
            r = await self.client.get(f"{srv['url']}/api/summary", headers=self._headers(srv))
        except httpx.HTTPError as e:
            raise AgentError(f"Can't reach {srv['url']} ({type(e).__name__})") from None
        self._check(r)
        try:
            return clean_summary(r.json())
        except ValueError:
            raise AgentError("The address answered, but not like a Monitorr agent") from None

    async def get(self, sid, path, params):
        srv = self.servers[sid]
        try:
            r = await self.client.get(f"{srv['url']}/api/{path}", params=params, headers=self._headers(srv))
        except httpx.HTTPError as e:
            raise AgentError(f"Can't reach {srv['name']} ({type(e).__name__})") from None
        self._check(r)
        return r

    async def post(self, sid, path, body):
        srv = self.servers[sid]
        try:
            r = await self.client.post(f"{srv['url']}/api/{path}", json=body, headers=self._headers(srv),
                                       timeout=httpx.Timeout(45, connect=4))
        except httpx.HTTPError as e:
            raise AgentError(f"Can't reach {srv['name']} ({type(e).__name__})") from None
        self._check(r)
        return r

    async def stream(self, sid, path="stream", params=None):
        srv = self.servers[sid]
        # logs can go quiet for a long time, so only the metrics stream has a read timeout
        read = 30 if path == "stream" else None
        req = self.client.build_request("GET", f"{srv['url']}/api/{path}", params=params, headers=self._headers(srv),
                                        timeout=httpx.Timeout(8, connect=4, read=read))
        try:
            resp = await self.client.send(req, stream=True)
        except httpx.HTTPError as e:
            raise AgentError(f"Can't reach {srv['name']} ({type(e).__name__})") from None
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
