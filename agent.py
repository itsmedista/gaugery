"""Monitorr agent: collects one server's data and answers only the hub (Bearer token).

It is the only part of Monitorr with host access. It listens either on a Unix socket that only
the hub's group may open (the hub on the same machine), or on TLS with its own certificate
(a remote hub, which pins that certificate via the pairing code).
"""
import asyncio
import json
import os
import socket
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
from fastapi.responses import JSONResponse, StreamingResponse

import tlsutil
from alerts import DISC_FS, AlertEngine
from auth import token_ok
from collectors import Collector, host_info
from common import harden, open_db, read_json
from dockerops import ACTIONS_PERMIT, LOGS, Docker, DockerError

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8088"))
INTERVAL = float(os.environ.get("SAMPLE_INTERVAL", "2"))
RETENTION_DAYS = float(os.environ.get("RETENTION_DAYS", "14"))
DB_PATH = os.environ.get("DB_PATH", "/var/lib/monitorr/metrics.db")
LISTEN = os.environ.get("AGENT_LISTEN", "tcp")   # "tcp" (TLS on HOST:PORT) or "unix:/run/monitorr/agent.sock"
LIVE_SECONDS = 3600
SPANS = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
LEGACY_TABLES = ("servers", "checks", "check_results", "prefs")  # hub data from before the hub/agent split


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
        self.db.execute("CREATE TABLE IF NOT EXISTS samples (ts INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)")
        self.db.commit()
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
        """The small status block the overview cards show (what the hub polls)."""
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

    # ---------- hub data from before the split ----------
    def legacy_tables(self):
        with self.db_lock:
            names = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        return [t for t in LEGACY_TABLES if t in names]

    def legacy_export(self):
        out, tables = {}, self.legacy_tables()  # before taking the lock: legacy_tables() takes it too
        with self.db_lock:
            for t in tables:
                cur = self.db.execute(f"SELECT * FROM {t}" + (" WHERE ts > ?" if t == "check_results" else ""),
                                      (time.time() - 30 * 86400,) if t == "check_results" else ())
                cols = [c[0] for c in cur.description]
                out[t] = [dict(zip(cols, r)) for r in cur.fetchall()]
        return out

    def legacy_drop(self):
        tables = self.legacy_tables()
        with self.db_lock:
            for t in tables:
                self.db.execute(f"DROP TABLE {t}")  # agent tokens must not linger here
            self.db.commit()
            self.db.execute("VACUUM")
        for f in ("secret.key", "revoked-sessions.json"):
            try:
                (Path(self.db_path).parent / f).unlink()
            except OSError:
                pass


def create_app(token):
    monitor = Monitor()
    docker = Docker()

    @asynccontextmanager
    async def lifespan(_app):
        monitor.start()
        yield
        await docker.close()

    app = FastAPI(title="Monitorr agent", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def require_token(request: Request, call_next):
        if request.url.path == "/healthz" or token_ok(request.headers.get("authorization"), token):
            return await call_next(request)
        return JSONResponse({"detail": "Not authorized"}, status_code=401)

    harden(app)

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/api/info")
    def api_info():
        return {**monitor.info, "features": {
            "logs": LOGS.on, "logs_for": LOGS.describe(),
            "actions": ACTIONS_PERMIT.on, "actions_for": ACTIONS_PERMIT.describe()}}

    @app.get("/api/summary")
    def api_summary():
        sm = monitor.summary()
        if sm is None:
            raise HTTPException(503, "Collecting the first sample")
        return sm

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

    # ---------- container logs and actions ----------
    @app.get("/api/logs")
    async def api_logs(container: str = "", since: float | None = None, until: float | None = None,
                       tail: int = 500, q: str = ""):
        try:
            return await docker.logs(container, since, until, tail, q[:200])
        except DockerError as e:
            raise HTTPException(e.status, str(e)) from None

    @app.get("/api/logstream")
    async def api_logstream(request: Request, container: str = ""):
        """New lines of one container's log as they're written (server-sent events)."""
        try:
            await docker.check_follow(container)  # fail now with a proper status, not inside the stream
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
        body = await read_json(request)
        try:
            name, done = await docker.action(str(body.get("container", "")), str(body.get("action", "")))
        except DockerError as e:
            raise HTTPException(e.status, str(e)) from None
        by = str(body.get("by") or "the hub")[:120]
        monitor.alerts.note(f"Container {name} {done}", f"Done from Monitorr by {by}.")
        return {"ok": True, "message": f"{name} {done}"}

    # ---------- one-time hand-over of the hub's data from before the split ----------
    @app.get("/api/legacy-export")
    def api_legacy_export():
        if not monitor.legacy_tables():
            raise HTTPException(404, "Nothing to hand over")
        return monitor.legacy_export()

    @app.post("/api/legacy-export/done")
    def api_legacy_done():
        monitor.legacy_drop()
        return {"ok": True}

    return app


def _unix_socket(path):
    """A listening socket only root and the hub's group can open."""
    p = Path(path)
    gid = int(os.environ.get("AGENT_SOCKET_GROUP", "10001"))
    if not p.parent.exists():
        p.parent.mkdir(parents=True)
        os.chown(p.parent, -1, gid)
        p.parent.chmod(0o750)
    try:
        p.unlink()
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    try:
        os.chown(path, -1, gid)
    except PermissionError:
        print(f"Can't give group {gid} access to {path}; the hub may not be able to connect.", flush=True)
    os.chmod(path, 0o660)
    return s


def serve():
    token = os.environ.get("AGENT_TOKEN", "").strip()
    if len(token) < 24:
        raise SystemExit("The agent needs AGENT_TOKEN (24+ characters). Make one with `python app.py --new-token`.")
    app = create_app(token)
    if LISTEN.startswith("unix:"):
        sock = _unix_socket(LISTEN[5:])
        uvicorn.Server(uvicorn.Config(app, log_level="warning")).run(sockets=[sock])
        return
    cert, key = tlsutil.ensure_cert(Path(DB_PATH).parent)
    print(f"Monitorr agent on https://{HOST}:{PORT}. Pairing code for the hub:\n  {tlsutil.pairing_code(cert, token)}",
          flush=True)
    uvicorn.run(app, host=HOST, port=PORT, ssl_certfile=cert, ssl_keyfile=key, log_level="warning")
