"""Monitorr hub: the web interface, sign-in, service checks and the list of servers.

It runs unprivileged: no host access and no Docker. This machine's data comes from the local
agent over a Unix socket; other servers' data from their agents over pinned TLS.
"""
import asyncio
import ipaddress
import json
import os
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles

import tlsutil
from alerts import AlertEngine
from auth import COOKIE, FREE_TRIES, SESSION_DAYS, Auth, totp_match, totp_secret, totp_uri
from checks import CheckError, Checks, guard_target, validate
from common import HERE, harden, open_db, read_json
from remote import AGENT_PATHS, STREAM_PATHS, AgentError, Remotes
from security import PageCSP

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8088"))
HUB_DB = os.environ.get("HUB_DB", "/var/lib/monitorr-hub/hub.db")
LOCAL_AGENT = os.environ.get("LOCAL_AGENT", "").strip()        # unix:/run/monitorr/agent.sock
TRUSTED_PROXIES = os.environ.get("TRUSTED_PROXIES", "").strip()  # only these may set X-Forwarded-For
ALLOW_HTTP_LOGIN = os.environ.get("ALLOW_HTTP_LOGIN", "").lower() in ("1", "true", "yes")
TLS = os.environ.get("TLS", "").lower()                         # "auto": serve HTTPS with its own certificate
PUBLIC = {"/login.html", "/icon.svg", "/api/login", "/api/auth-config", "/healthz"}
# Where signing in over plain HTTP is still allowed: this machine, private networks, Tailscale.
NEARBY = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                            "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]


class ReauthRequired(Exception):
    pass


def _nearby(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    a = getattr(a, "ipv4_mapped", None) or a
    return any(a in n for n in NEARBY)


class Hub:
    def __init__(self):
        self.db, path = open_db(HUB_DB)
        self.data_dir = Path(path).parent
        self.db_lock = threading.Lock()
        with self.db_lock:
            self.db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS prefs (key TEXT PRIMARY KEY, value TEXT)")
            self.db.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)")
            self.db.commit()
            history = [dict(zip(("ts", "kind", "severity", "title", "detail"), r)) for r in
                       self.db.execute("SELECT * FROM events ORDER BY ts DESC LIMIT 100").fetchall()][::-1]
        self.auth = Auth(self.data_dir)
        self.remotes = Remotes(self.db, self.db_lock, LOCAL_AGENT or None, os.environ.get("AGENT_TOKEN", "").strip())
        self.checks = Checks(self.db, self.db_lock, self.remotes.name)
        # security-relevant events: kept here and sent to ntfy (NTFY_URL)
        self.activity = AlertEngine("Monitorr", 0, on_event=self._store_event, history=history)

    def _store_event(self, ev):
        with self.db_lock:
            self.db.execute("INSERT INTO events VALUES (?, ?, ?, ?, ?)",
                            (ev["ts"], ev["kind"], ev["severity"], ev["title"], ev["detail"]))
            self.db.execute("DELETE FROM events WHERE ts < ?", (time.time() - 180 * 86400,))
            self.db.commit()

    def note(self, title, detail):
        self.activity.note(title, detail)

    def get(self, key, default=None):
        with self.db_lock:
            row = self.db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def set(self, key, value):
        with self.db_lock:
            if value is None:
                self.db.execute("DELETE FROM settings WHERE key = ?", (key,))
            else:
                self.db.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (key, json.dumps(value)))
            self.db.commit()

    # ---------- the hub's data from before the hub/agent split ----------
    async def import_legacy(self):
        if self.get("legacy_import") or "local" not in self.remotes.servers:
            return
        for _ in range(60):
            try:
                data = (await self.remotes.get("local", "legacy-export", None)).json()
            except AgentError as e:
                if "Nothing to hand over" in str(e):
                    self.set("legacy_import", "nothing")
                    return
                await asyncio.sleep(5)  # the agent may still be starting
                continue
            self.remotes.import_rows(data.get("servers", []))
            self.checks.import_rows(data.get("checks", []), data.get("check_results", []))
            with self.db_lock:
                if not self.db.execute("SELECT 1 FROM prefs WHERE key = 'overview'").fetchone():
                    for p in data.get("prefs", []):
                        self.db.execute("INSERT OR IGNORE INTO prefs VALUES (?, ?)", (p["key"], p["value"]))
                self.db.commit()
            await self.remotes.post("local", "legacy-export/done", {})
            self.set("legacy_import", "done")
            self.note("Imported servers and checks", "Moved from the previous version's database. "
                      "Servers added before encrypted connections need their pairing code once.")
            return


def create_app():
    hub = Hub()
    auth, remotes, checks = hub.auth, hub.remotes, hub.checks
    login_slots = asyncio.Semaphore(4)  # password checks cost ~50 ms of CPU each; cap them

    @asynccontextmanager
    async def lifespan(_app):
        tasks = [asyncio.create_task(remotes.run()), asyncio.create_task(checks.run()),
                 asyncio.create_task(hub.import_legacy())]
        yield
        for t in tasks:
            t.cancel()
        await remotes.close()
        await checks.close()

    app = FastAPI(title="Monitorr", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    @app.exception_handler(ReauthRequired)
    async def _reauth(_request, _exc):
        return JSONResponse({"detail": "Enter your password to confirm this change", "reauth": True}, status_code=403)

    @app.middleware("http")
    async def require_login(request: Request, call_next):
        path = request.url.path
        if path in PUBLIC or auth.valid(request.cookies.get(COOKIE)):
            return await call_next(request)
        if path.startswith("/api/"):
            return JSONResponse({"detail": "Not signed in"}, status_code=401)
        return RedirectResponse("login.html", status_code=303)

    harden(app, PageCSP(HERE / "static"))

    def ip_of(request):
        return request.client.host if request.client else "?"

    def need_recent(request):
        """Sensitive changes need the password entered in the last 15 minutes."""
        if not auth.recent(request.cookies.get(COOKIE)):
            raise ReauthRequired()

    def who(request):
        return f"{auth.user} from {ip_of(request)}"

    async def verify(request, body):
        """Password (and code, when two-factor is on) from a sign-in or confirmation form."""
        ip = ip_of(request)
        if request.url.scheme != "https" and not _nearby(ip) and not ALLOW_HTTP_LOGIN:
            raise HTTPException(403, "Sign in over HTTPS or Tailscale: plain HTTP would send your password "
                                     "across the internet unencrypted.")
        wait = auth.wait(ip)
        if wait:
            raise HTTPException(429, f"Too many wrong tries. Wait {wait} s and try again.")
        user, password = str(body.get("user", auth.user)), str(body.get("password", ""))
        if len(user) > 200 or len(password) > 1024:
            raise HTTPException(400, "That's too long")
        if login_slots.locked():
            raise HTTPException(429, "Busy, try again in a moment")
        async with login_slots:
            ok = await asyncio.to_thread(auth.password_ok, user, password)
        secret = hub.get("totp_secret")
        if ok and secret:
            step = totp_match(secret, body.get("code"), hub.get("totp_last", 0))
            ok = step is not None
            if ok:
                hub.set("totp_last", step)
        if not ok:
            n = auth.failed(ip)
            if n == FREE_TRIES + 2 or n % 25 == 0:
                hub.note(f"{n} wrong sign-in attempts from {ip}", "Each further try from there now waits longer.")
            raise HTTPException(401, "Wrong username, password or code" if secret else "Wrong username or password")
        auth.succeeded(ip)
        return ip

    def set_session(resp, request, exp=None):
        resp.set_cookie(COOKIE, auth.issue(exp), max_age=int(SESSION_DAYS * 86400), httponly=True,
                        samesite="strict", secure=request.url.scheme == "https")

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # ---------- sign-in ----------
    @app.get("/api/auth-config")
    def api_auth_config():
        return {"totp": bool(hub.get("totp_secret"))}

    @app.post("/api/login")
    async def api_login(request: Request):
        ip = await verify(request, await read_json(request))
        known = hub.get("known_ips", [])
        if ip not in known:
            hub.note(f"Sign-in from a new address: {ip}", "If this wasn't you, change your password (that signs "
                     "everyone out) and turn on two-factor sign-in.")
            hub.set("known_ips", (known + [ip])[-50:])
        resp = JSONResponse({"ok": True})
        set_session(resp, request)
        return resp

    @app.post("/api/reauth")
    async def api_reauth(request: Request):
        old = auth.session(request.cookies.get(COOKIE))
        await verify(request, {**await read_json(request), "user": auth.user})
        auth.revoke(request.cookies.get(COOKIE))
        resp = JSONResponse({"ok": True})
        set_session(resp, request, old["exp"] if old else None)
        return resp

    @app.post("/api/logout")
    def api_logout(request: Request):
        auth.revoke(request.cookies.get(COOKIE))  # the cookie stops working even if someone copied it
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/api/info")
    def api_info():
        return {"auth": True, "user": auth.user, "totp": bool(hub.get("totp_secret"))}

    # ---------- two-factor sign-in and activity ----------
    @app.get("/api/security")
    def api_security():
        with hub.db_lock:
            rows = hub.db.execute("SELECT ts, kind, title, detail FROM events ORDER BY ts DESC LIMIT 100").fetchall()
        return {"user": auth.user, "totp": bool(hub.get("totp_secret")),
                "activity": [dict(zip(("ts", "kind", "title", "detail"), r)) for r in rows]}

    @app.post("/api/2fa/start")
    def api_2fa_start(request: Request):
        need_recent(request)
        secret = totp_secret()
        hub.set("totp_pending", secret)
        return {"secret": secret, "uri": totp_uri(secret, auth.user)}

    @app.post("/api/2fa/confirm")
    async def api_2fa_confirm(request: Request):
        need_recent(request)
        pending = hub.get("totp_pending")
        step = totp_match(pending, (await read_json(request)).get("code"))
        if not pending or step is None:
            raise HTTPException(400, "That code doesn't match. Check the time on your phone and try the next code.")
        hub.set("totp_secret", pending)
        hub.set("totp_last", step)
        hub.set("totp_pending", None)
        hub.note("Two-factor sign-in turned on", f"By {who(request)}.")
        return {"ok": True}

    @app.post("/api/2fa/disable")
    async def api_2fa_disable(request: Request):
        need_recent(request)
        secret = hub.get("totp_secret")
        step = totp_match(secret, (await read_json(request)).get("code"), hub.get("totp_last", 0))
        if not secret or step is None:
            raise HTTPException(400, "Enter a current code from your authenticator app to turn this off")
        hub.set("totp_secret", None)
        hub.set("totp_last", None)
        hub.note("Two-factor sign-in turned off", f"By {who(request)}.")
        return {"ok": True}

    # ---------- servers ----------
    @app.get("/api/servers")
    def api_servers():
        out = []
        for srv in remotes.listing():
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
        need_recent(request)
        body = await read_json(request)
        try:
            sid = await remotes.add(str(body.get("name", "")), str(body.get("address", "")),
                                    str(body.get("pairing", "")))
        except AgentError as e:
            raise HTTPException(400, str(e)) from None
        srv = remotes.servers[sid]
        hub.note(f"Server added: {srv['name']}", f"{srv['url']}, by {who(request)}.")
        return {"id": sid}

    @app.delete("/api/servers/{sid}")
    async def api_remove_server(sid: str, request: Request):
        need_recent(request)
        name = remotes.name(sid)
        if not await remotes.remove(sid):
            raise HTTPException(404 if name is None else 400, "No such server" if name is None
                                else "This machine's own agent can't be removed")
        checks.delete_server(sid)
        hub.note(f"Server removed: {name}", f"By {who(request)}.")
        return {"ok": True}

    # ---------- overview layout (kept on the hub, so every device shows the same order) ----------
    def _ids(v):
        return [x for x in v if isinstance(x, str) and 0 < len(x) <= 32][:200] if isinstance(v, list) else []

    @app.get("/api/prefs/overview")
    def api_get_layout():
        with hub.db_lock:
            row = hub.db.execute("SELECT value FROM prefs WHERE key = 'overview'").fetchone()
        return {"order": [], "pinned": [], "density": "detailed", **(json.loads(row[0]) if row else {})}

    @app.put("/api/prefs/overview")
    async def api_put_layout(request: Request):
        body = await read_json(request)
        layout = {"order": _ids(body.get("order")), "pinned": _ids(body.get("pinned")),
                  "density": "compact" if body.get("density") == "compact" else "detailed"}
        with hub.db_lock:
            hub.db.execute("INSERT OR REPLACE INTO prefs VALUES ('overview', ?)", (json.dumps(layout),))
            hub.db.commit()
        return layout

    # ---------- service checks (run by the hub, filed under a server) ----------
    def _check_or_404(cid):
        if cid not in checks.checks:
            raise HTTPException(404, "No such check")
        return checks.checks[cid]

    async def _vetted(body):
        try:
            clean = validate(body)
            await guard_target(clean["kind"], clean["target"])
        except CheckError as e:
            raise HTTPException(400, str(e)) from None

    @app.get("/api/checks")
    def api_checks(server: str = "local"):
        return {"checks": checks.listing(server), "alerts": checks.summary(server)["alerts"]}

    @app.post("/api/checks")
    async def api_add_check(request: Request):
        need_recent(request)
        body = await read_json(request)
        server = str(body.get("server", "local"))
        if remotes.name(server) is None:
            raise HTTPException(400, "No such server")
        await _vetted(body)
        cid = checks.create(server, body)
        c = checks.checks[cid]
        hub.note(f"Service check added: {c['name']}", f"{c['kind']} {c['target']} on {remotes.name(server)}, by {who(request)}.")
        await checks.run_now(cid)  # so the user sees straight away whether it works
        return next(x for x in checks.listing(server) if x["id"] == cid)

    @app.put("/api/checks/{cid}")
    async def api_edit_check(cid: str, request: Request):
        need_recent(request)
        c = _check_or_404(cid)
        body = await read_json(request)
        await _vetted(body)
        checks.update(cid, body)
        hub.note(f"Service check changed: {c['name']}", f"{c['kind']} {c['target']}, by {who(request)}.")
        await checks.run_now(cid)
        return next(x for x in checks.listing(c["server"]) if x["id"] == cid)

    @app.delete("/api/checks/{cid}")
    def api_delete_check(cid: str, request: Request):
        need_recent(request)
        c = _check_or_404(cid)
        checks.delete(cid)
        hub.note(f"Service check deleted: {c['name']}", f"By {who(request)}.")
        return {"ok": True}

    # ---------- a server's own data, relayed from its agent ----------
    @app.get("/api/s/{sid}/{path}")
    async def api_relay(sid: str, path: str, request: Request):
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
            return {**info, "auth": True, "name": remotes.name(sid), "local": remotes.servers[sid]["local"]}
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
        need_recent(request)
        if sid not in remotes.servers:
            raise HTTPException(404, "No such server")
        body = await read_json(request)
        req = {"container": str(body.get("container", ""))[:128], "action": str(body.get("action", ""))[:16],
               "by": who(request)}
        try:
            r = await remotes.post(sid, "container-action", req)
        except AgentError as e:
            raise HTTPException(502, str(e)) from None
        hub.note(f"Container {req['container']} {req['action']} on {remotes.name(sid)}", f"By {who(request)}.")
        return Response(r.content, media_type="application/json")

    app.mount("/", StaticFiles(directory=HERE / "static", html=True), name="static")
    app.state.hub = hub
    return app


def serve():
    app = create_app()
    app.state.hub.auth.check_config()
    kw = {"host": HOST, "port": PORT, "log_level": "warning", "proxy_headers": bool(TRUSTED_PROXIES)}
    if TRUSTED_PROXIES:
        kw["forwarded_allow_ips"] = TRUSTED_PROXIES
    if os.environ.get("TLS_CERT") and os.environ.get("TLS_KEY"):
        kw.update(ssl_certfile=os.environ["TLS_CERT"], ssl_keyfile=os.environ["TLS_KEY"])
    elif TLS == "auto":
        cert, key = tlsutil.ensure_cert(app.state.hub.data_dir, "monitorr-hub")
        kw.update(ssl_certfile=cert, ssl_keyfile=key)
    uvicorn.run(app, **kw)
