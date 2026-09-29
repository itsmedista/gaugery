"""Monitorr: a single-process Linux server dashboard.

Run:  python app.py          (see README.md for the systemd install)
"""
import asyncio
import json
import os
import sqlite3
import threading
import time
import traceback
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import psutil
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

from alerts import DISC_FS, AlertEngine
from auth import COOKIE, SESSION_DAYS, Auth
from checks import CheckError, Checks
from collectors import DOCKER_SOCK, Collector, host_info
from dockerops import ALLOW_ACTIONS, ALLOW_LOGS, Docker, DockerError
from remote import AGENT_PATHS, STREAM_PATHS, AgentError, Remotes
from security import API_CSP, BASE_HEADERS, PageCSP, refuse

HERE = Path(__file__).resolve().parent
os.umask(0o077)
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8088"))
INTERVAL = float(os.environ.get("SAMPLE_INTERVAL", "2"))
RETENTION_DAYS = float(os.environ.get("RETENTION_DAYS", "14"))
DB_PATH = os.environ.get("DB_PATH", "/var/lib/monitorr/metrics.db")
LIVE_SECONDS = 3600
SPANS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}


def open_db(path):
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, check_same_thread=False)
    except (OSError, sqlite3.OperationalError):
        path = str(HERE / "metrics.db")  # fallback when not running as root
        db = sqlite3.connect(path, check_same_thread=False)
    for f in (path, path + "-wal", path + "-shm"):  # databases made by older versions were world-readable
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("CREATE TABLE IF NOT EXISTS samples (ts INTEGER PRIMARY KEY, data TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)")
    db.commit()
    return db, path


def bucketize(points, bucket):
    out, cur_b, sums, counts = [], None, {}, {}

    def flush():
        if cur_b is not None:
            out.append({"t": cur_b + bucket / 2,
                        "s": {k: round(sums[k] / counts[k], 3) for k in sums}})

    for p in points:
        b = int(p["t"] // bucket) * bucket
        if b != cur_b:
            flush()
            cur_b, sums, counts = b, {}, {}
        for k, v in p["s"].items():
            sums[k] = sums.get(k, 0.0) + v
            counts[k] = counts.get(k, 0) + 1
    flush()
    return out


class Monitor:
    def __init__(self):
        self.info = host_info()
        self.collector = Collector()
        self.live = deque(maxlen=int(LIVE_SECONDS / INTERVAL) + 5)
        self.latest, self.seq = None, 0
        self.lock = threading.Lock()
        self.db, self.db_path = open_db(DB_PATH)
        self.db_lock = threading.Lock()
        history = [dict(zip(("ts", "kind", "severity", "title", "detail"), r)) for r in
                   self.db.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 100").fetchall()][::-1]
        self.alerts = AlertEngine(self.info["hostname"], self.info["cores"],
                                  on_event=self._store_event, history=history)
        self._acc, self._acc_n, self._acc_min = {}, {}, None
        self._slopes, self._slopes_at, self._pruned_at = {}, 0.0, 0.0

    def start(self):
        self.collector.start()
        threading.Thread(target=self._loop, daemon=True, name="sampler").start()

    def _loop(self):
        nxt = time.time() + INTERVAL
        while True:
            time.sleep(max(0.0, nxt - time.time()))
            nxt += INTERVAL
            if nxt < time.time():
                nxt = time.time() + INTERVAL
            try:
                self._tick()
            except Exception:  # noqa: BLE001
                traceback.print_exc()

    def _tick(self):
        now = time.time()
        series, state = self.collector.sample()
        if now - self._slopes_at > 600:
            self._slopes, self._slopes_at = self._fill_slopes(now), now
        for d in state["drives"]:
            slope = self._slopes.get(d["mount"], "unknown")
            if slope == "unknown" or d.get("free") is None:
                d["days_to_full"] = None
            elif slope <= 0:
                d["days_to_full"] = -1
            else:
                d["days_to_full"] = round(d["free"] / slope / 86400, 1)
        state["alerts"] = self.alerts.evaluate(series, state, now)
        state["uptime"] = now - psutil.boot_time()
        point = {"t": round(now, 3), "s": {k: round(v, 3) for k, v in series.items()}}
        msg = json.dumps({"t": point["t"], "s": point["s"], "state": state}, default=str)
        with self.lock:
            self.live.append(point)
            self.latest = msg
            self.seq += 1
        self._accumulate(now, series)

    # ---------- storage ----------
    def _accumulate(self, now, series):
        minute = int(now // 60) * 60
        if self._acc_min is not None and minute != self._acc_min and self._acc:
            data = {k: round(self._acc[k] / self._acc_n[k], 3) for k in self._acc}
            with self.db_lock:
                self.db.execute("INSERT OR REPLACE INTO samples VALUES (?, ?)",
                                (self._acc_min, json.dumps(data)))
                self.db.commit()
            self._acc, self._acc_n = {}, {}
        self._acc_min = minute
        for k, v in series.items():
            self._acc[k] = self._acc.get(k, 0.0) + v
            self._acc_n[k] = self._acc_n.get(k, 0) + 1
        if now - self._pruned_at > 3600:
            self._pruned_at = now
            with self.db_lock:
                self.db.execute("DELETE FROM samples WHERE ts < ?", (now - RETENTION_DAYS * 86400,))
                self.db.execute("DELETE FROM events WHERE ts < ?", (now - 90 * 86400,))
                self.db.commit()

    def _store_event(self, ev):
        with self.db_lock:
            self.db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)",
                            (ev["ts"], ev["kind"], ev["severity"], ev["title"], ev["detail"]))
            self.db.commit()

    def _rows(self, since):
        with self.db_lock:
            rows = self.db.execute("SELECT ts, data FROM samples WHERE ts >= ? ORDER BY ts",
                                   (int(since),)).fetchall()
        return [{"t": ts, "s": json.loads(data)} for ts, data in rows]

    def _fill_slopes(self, now):
        """Least-squares growth rate (bytes/second) of each drive over the last 7 days."""
        pts = {}
        for row in self._rows(now - 7 * 86400):
            for k, v in row["s"].items():
                if k.startswith("drive:") and k.endswith(":used"):
                    pts.setdefault(k[6:-5], []).append((row["t"], v))
        slopes = {}
        for mount, xy in pts.items():
            if len(xy) < 30 or xy[-1][0] - xy[0][0] < 6 * 3600:
                continue
            n = len(xy)
            mx = sum(x for x, _ in xy) / n
            my = sum(y for _, y in xy) / n
            var = sum((x - mx) ** 2 for x, _ in xy)
            if var:
                slopes[mount] = sum((x - mx) * (y - my) for x, y in xy) / var
        return slopes

    # ---------- api helpers ----------
    def summary(self):
        """The small status block the overview cards show (also what a hub polls from agents)."""
        with self.lock:
            msg = self.latest
        if msg is None:
            return None
        m = json.loads(msg)
        s, st = m["s"], m["state"]
        active = st["alerts"]["active"]
        pcts = [d["pct"] for d in st["drives"] if d.get("pct") is not None and d["fs"] not in DISC_FS]
        ctrs = st["containers"] if st["docker"]["available"] else None
        return {
            "hostname": self.info["hostname"], "os": self.info["os"], "t": m["t"], "uptime": st["uptime"],
            "cpu": s.get("cpu:total"), "mem": s.get("mem:pct"), "disk": max(pcts, default=None),
            "containers": None if ctrs is None else {
                "running": sum(c["state"] == "running" for c in ctrs), "total": len(ctrs)},
            "alerts": {
                "critical": sum(a["severity"] == "critical" for a in active),
                "warning": sum(a["severity"] == "warning" for a in active),
                "top": [{"severity": a["severity"], "title": a["title"]} for a in active[:3]]},
        }

    def recent(self, seconds=600):
        cutoff = time.time() - seconds
        with self.lock:
            return [p for p in self.live if p["t"] >= cutoff]

    def history(self, rng):
        span = SPANS[rng]
        now = time.time()
        if rng == "1h":
            pts, bucket = self.recent(span), 10
        else:
            pts, bucket = self._rows(now - span), max(60, round(span / 360 / 60) * 60)
        return {"bucket": bucket, "points": bucketize(pts, bucket)}


CLI_FLAGS = ("--healthcheck", "--hash-password", "--new-token")
monitor = None if any(f in __import__("sys").argv for f in CLI_FLAGS) else Monitor()
auth = Auth(Path(monitor.db_path).parent) if monitor else None
remotes = Remotes(monitor.db, monitor.db_lock) if monitor else None


def server_name(sid):
    return monitor.info["hostname"] if sid == "local" else remotes.servers.get(sid, {}).get("name")


checks = Checks(monitor.db, monitor.db_lock, server_name) if monitor else None
docker = Docker(DOCKER_SOCK) if monitor else None
PUBLIC = {"/login.html", "/icon.svg", "/api/login", "/healthz"}


@asynccontextmanager
async def lifespan(_app):
    monitor.start()
    tasks = [asyncio.create_task(remotes.run()), asyncio.create_task(checks.run())]
    yield
    for t in tasks:
        t.cancel()
    await remotes.client.aclose()
    await checks.close()
    await docker.close()


app = FastAPI(title="Monitorr", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
page_csp = PageCSP(HERE / "static")
login_slots = asyncio.Semaphore(4)  # password checks cost ~50 ms of CPU each; cap them


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC or auth.valid(request.cookies.get(COOKIE)):
        return await call_next(request)
    if path[5:] in AGENT_PATHS and path.startswith("/api/") and auth.agent_ok(request.headers.get("authorization")):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Not signed in"}, status_code=401)
    return RedirectResponse("login.html", status_code=303)


@app.middleware("http")
async def harden(request: Request, call_next):
    bad = refuse(request)
    resp = JSONResponse({"detail": bad[1]}, status_code=bad[0]) if bad else await call_next(request)
    for k, v in BASE_HEADERS.items():
        resp.headers.setdefault(k, v)
    if resp.headers.get("content-type", "").startswith("text/html"):
        resp.headers["Content-Security-Policy"] = page_csp.value()
    else:
        resp.headers.setdefault("Content-Security-Policy", API_CSP)
    if request.url.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
    return resp


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/api/login")
async def api_login(request: Request):
    ip = request.client.host if request.client else "?"
    if auth.locked(ip):
        raise HTTPException(429, "Too many attempts. Wait a few minutes and try again.")
    try:
        body = await request.json()
        user, password = str(body["user"]), str(body["password"])
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, "Send user and password") from None
    if len(user) > 200 or len(password) > 1024:
        raise HTTPException(400, "That's too long")
    if login_slots.locked():
        raise HTTPException(429, "Busy, try again in a moment")
    async with login_slots:
        ok = await asyncio.to_thread(auth.login, ip, user, password)
    if not ok:
        raise HTTPException(401, "Wrong username or password")
    resp = JSONResponse({"ok": True})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(COOKIE, auth.issue(), max_age=int(SESSION_DAYS * 86400),
                    httponly=True, samesite="lax", secure=https)
    return resp


@app.post("/api/logout")
def api_logout(request: Request):
    auth.revoke(request.cookies.get(COOKIE))  # the cookie stops working even if someone copied it
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/info")
def api_info():
    return {**monitor.info, "auth": auth.enabled,
            "features": {"logs": ALLOW_LOGS, "actions": ALLOW_ACTIONS}}


@app.get("/api/summary")
def api_summary():
    sm = monitor.summary()
    if sm is None:
        raise HTTPException(503, "Collecting the first sample")
    return sm


# ---------- multiple servers (this instance is the hub) ----------
@app.get("/api/servers")
def api_servers():
    here = {"id": "local", "name": monitor.info["hostname"], "url": None, "local": True,
            "online": True, "error": None, "summary": monitor.summary(), "checked": time.time()}
    out = []
    for srv in (here, *remotes.listing()):
        # a server's alerts are its own plus those of the service checks filed under it
        svc = checks.summary(srv["id"])
        own = (srv["summary"] or {}).get("alerts") or {"critical": 0, "warning": 0, "top": []}
        sa = svc.pop("alerts")
        srv["services"] = svc
        srv["alerts"] = {
            "critical": own["critical"] + sum(a["severity"] == "critical" for a in sa),
            "warning": own["warning"] + sum(a["severity"] == "warning" for a in sa),
            "top": ([{"severity": a["severity"], "title": a["title"]} for a in sa] + own["top"])[:3]}
        out.append(srv)
    return out


@app.post("/api/servers")
async def api_add_server(request: Request):
    try:
        body = await request.json()
        sid = await remotes.add(str(body.get("name", "")), str(body.get("url", "")), str(body.get("token", "")))
    except AgentError as e:
        raise HTTPException(400, str(e)) from None
    except (ValueError, AttributeError):
        raise HTTPException(400, "Send name, url and token") from None
    return {"id": sid}


@app.delete("/api/servers/{sid}")
def api_remove_server(sid: str):
    if not remotes.remove(sid):
        raise HTTPException(404, "No such server")
    checks.delete_server(sid)
    return {"ok": True}


# ---------- overview layout (kept on the hub, so every device shows the same order) ----------
LAYOUT_DEFAULT = {"order": [], "pinned": [], "density": "detailed"}


def _ids(v):
    return [x for x in v if isinstance(x, str) and 0 < len(x) <= 32][:200] if isinstance(v, list) else []


@app.get("/api/prefs/overview")
def api_get_layout():
    with monitor.db_lock:
        monitor.db.execute("CREATE TABLE IF NOT EXISTS prefs (key TEXT PRIMARY KEY, value TEXT)")
        row = monitor.db.execute("SELECT value FROM prefs WHERE key = 'overview'").fetchone()
    return {**LAYOUT_DEFAULT, **(json.loads(row[0]) if row else {})}


@app.put("/api/prefs/overview")
async def api_put_layout(request: Request):
    _require_json(request)
    body = await _json(request)
    layout = {"order": _ids(body.get("order")), "pinned": _ids(body.get("pinned")),
              "density": "compact" if body.get("density") == "compact" else "detailed"}
    with monitor.db_lock:
        monitor.db.execute("CREATE TABLE IF NOT EXISTS prefs (key TEXT PRIMARY KEY, value TEXT)")
        monitor.db.execute("INSERT OR REPLACE INTO prefs VALUES ('overview', ?)", (json.dumps(layout),))
        monitor.db.commit()
    return layout


# ---------- service checks (run by this instance, filed under a server) ----------
def _check_or_404(cid):
    if cid not in checks.checks:
        raise HTTPException(404, "No such check")
    return checks.checks[cid]


@app.get("/api/checks")
def api_checks(server: str = "local"):
    return {"checks": checks.listing(server), "alerts": checks.summary(server)["alerts"]}


@app.post("/api/checks")
async def api_add_check(request: Request):
    body = await _json(request)
    server = str(body.get("server", "local"))
    if server_name(server) is None:
        raise HTTPException(400, "No such server")
    try:
        cid = checks.create(server, body)
    except CheckError as e:
        raise HTTPException(400, str(e)) from None
    await checks.run_now(cid)  # so the user sees straight away whether it works
    return next(c for c in checks.listing(server) if c["id"] == cid)


@app.put("/api/checks/{cid}")
async def api_edit_check(cid: str, request: Request):
    c = _check_or_404(cid)
    try:
        checks.update(cid, await _json(request))
    except CheckError as e:
        raise HTTPException(400, str(e)) from None
    await checks.run_now(cid)
    return next(x for x in checks.listing(c["server"]) if x["id"] == cid)


@app.delete("/api/checks/{cid}")
def api_delete_check(cid: str):
    _check_or_404(cid)
    checks.delete(cid)
    return {"ok": True}


async def _json(request):
    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(400, "Send a JSON object")
    return body


@app.get("/api/s/{sid}/{path}")
async def api_relay(sid: str, path: str, request: Request):
    """The dashboard of a remote server calls these; they're forwarded to its agent."""
    if sid not in remotes.servers or path not in AGENT_PATHS or path == "container-action":
        raise HTTPException(404, "No such server")
    try:
        if path in STREAM_PATHS:
            resp = await remotes.stream(sid, path, request.query_params)
        else:
            r = await remotes.get(sid, path, request.query_params)
    except AgentError as e:
        # 502, not 401: a rejected agent token must not look like "you are signed out" to the page
        raise HTTPException(502, str(e)) from None
    if path == "info":
        try:
            info = r.json()
            assert isinstance(info, dict)
        except (ValueError, AssertionError):
            raise HTTPException(502, "The agent answered, but not with server info") from None
        return {**info, "auth": auth.enabled, "name": remotes.servers[sid]["name"]}
    if path not in STREAM_PATHS:
        # never pass the agent's Content-Type through: text/html from a hacked agent would run on this origin
        return Response(r.content, status_code=r.status_code, media_type="application/json")

    async def relay():
        try:
            async for chunk in resp.aiter_raw():
                if await request.is_disconnected():
                    break
                yield chunk
        except httpx.HTTPError:
            pass  # agent went away; the browser reconnects
        finally:
            await resp.aclose()

    return StreamingResponse(relay(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/s/{sid}/container-action")
async def api_relay_action(sid: str, request: Request):
    _require_json(request)
    if sid not in remotes.servers:
        raise HTTPException(404, "No such server")
    try:
        r = await remotes.post(sid, "container-action", await _json(request))
    except AgentError as e:
        raise HTTPException(502, str(e)) from None
    return Response(r.content, media_type="application/json")


# ---------- container logs and actions (this server's Docker) ----------
def _require_json(request):
    # Browsers can't send JSON to another site without its permission (a CORS preflight), so
    # requiring it means a page elsewhere can't use your session to press these buttons.
    if not request.headers.get("content-type", "").startswith("application/json"):
        raise HTTPException(415, "Send JSON")


def _need_logs():
    if not ALLOW_LOGS:
        raise HTTPException(403, "Logs are turned off on this server (ALLOW_LOGS=false)")


@app.get("/api/logs")
async def api_logs(container: str = "", since: float | None = None, until: float | None = None,
                   tail: int = 500, q: str = ""):
    _need_logs()
    try:
        return await docker.logs(container, since, until, tail, q[:200])
    except DockerError as e:
        raise HTTPException(e.status, str(e)) from None


@app.get("/api/logstream")
async def api_logstream(request: Request, container: str = ""):
    """New lines of one container's log as they're written (server-sent events)."""
    _need_logs()
    try:
        await docker.inspect(container)  # fail now with a proper status, not inside the stream
    except DockerError as e:
        raise HTTPException(e.status, str(e)) from None
    queue = asyncio.Queue(maxsize=5000)

    async def pump():
        try:
            async for line in docker.follow(container):
                await queue.put(line)
        except (DockerError, httpx.HTTPError):
            pass
        await queue.put(None)

    async def sse():
        task = asyncio.create_task(pump())
        try:
            yield "retry: 3000\n\n"
            while not await request.is_disconnected():
                try:
                    line = await asyncio.wait_for(queue.get(), 15)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"  # quiet container: keep proxies from closing the connection
                    continue
                if line is None:
                    break
                yield f"data: {json.dumps(line)}\n\n"
        finally:
            task.cancel()

    return StreamingResponse(sse(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/container-action")
async def api_container_action(request: Request):
    _require_json(request)
    if not ALLOW_ACTIONS:
        raise HTTPException(403, "Container actions are off on this server. "
                                 "Set ALLOW_CONTAINER_ACTIONS=true there to allow them.")
    body = await _json(request)
    try:
        name, done = await docker.action(str(body.get("container", "")), str(body.get("action", "")))
    except DockerError as e:
        raise HTTPException(e.status, str(e)) from None
    via = "the hub" if request.headers.get("authorization") else (request.client.host if request.client else "?")
    monitor.alerts.note(f"Container {name} {done}", f"Done from Monitorr (request from {via}).")
    return {"ok": True, "message": f"{name} {done}"}


@app.get("/api/recent")
def api_recent():
    return monitor.recent()


@app.get("/api/state")
def api_state():
    if monitor.latest is None:
        raise HTTPException(503, "Collecting the first sample")
    return JSONResponse(content=json.loads(monitor.latest))


@app.get("/api/history")
def api_history(range: str = "1h"):  # noqa: A002
    if range not in SPANS:
        raise HTTPException(400, f"range must be one of {', '.join(SPANS)}")
    return monitor.history(range)


@app.get("/api/stream")
async def api_stream(request: Request):
    async def gen():
        last = -1
        yield "retry: 3000\n\n"
        while not await request.is_disconnected():
            if monitor.seq != last and monitor.latest:
                last = monitor.seq
                yield f"data: {monitor.latest}\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


app.mount("/", StaticFiles(directory=HERE / "static", html=True), name="static")

if __name__ == "__main__":
    import sys
    if "--new-token" in sys.argv:
        from auth import new_token
        new_token()
        sys.exit(0)
    if "--hash-password" in sys.argv:
        from auth import prompt_hash
        prompt_hash()
        sys.exit(0)
    if "--healthcheck" in sys.argv:  # used by the Docker HEALTHCHECK
        import urllib.request
        target = "127.0.0.1" if HOST in ("0.0.0.0", "::", "") else HOST
        try:
            urllib.request.urlopen(f"http://{target}:{PORT}/healthz", timeout=4)
        except Exception:  # noqa: BLE001
            sys.exit(1)
        sys.exit(0)
    auth.check_config()
    if not auth.enabled:
        print("WARNING: AUTH_DISABLED=true. Anyone who can reach this port"
              + (" can stop and restart your containers" if ALLOW_ACTIONS else " can see this server")
              + ". Only use it behind a proxy that does its own login, and set ALLOWED_HOSTS.", flush=True)
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
