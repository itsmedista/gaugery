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

import psutil
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from alerts import AlertEngine
from auth import COOKIE, SESSION_DAYS, Auth
from collectors import Collector, host_info

HERE = Path(__file__).resolve().parent
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


CLI_FLAGS = ("--healthcheck", "--hash-password")
monitor = None if any(f in __import__("sys").argv for f in CLI_FLAGS) else Monitor()
auth = Auth(Path(monitor.db_path).parent) if monitor else None
PUBLIC = {"/login.html", "/icon.svg", "/api/login", "/healthz"}


@asynccontextmanager
async def lifespan(_app):
    monitor.start()
    yield


app = FastAPI(title="Monitorr", lifespan=lifespan, docs_url=None, redoc_url=None)


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC or auth.valid(request.cookies.get(COOKIE)):
        return await call_next(request)
    if path.startswith("/api/"):
        return JSONResponse({"detail": "Not signed in"}, status_code=401)
    return RedirectResponse("login.html", status_code=303)


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
    if not auth.login(ip, user, password):
        raise HTTPException(401, "Wrong username or password")
    resp = JSONResponse({"ok": True})
    https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    resp.set_cookie(COOKIE, auth.issue(), max_age=int(SESSION_DAYS * 86400),
                    httponly=True, samesite="lax", secure=https)
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/info")
def api_info():
    return {**monitor.info, "auth": auth.enabled}


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
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
