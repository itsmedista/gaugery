"""Container logs and actions for Monitorr, straight from the Docker API.

Both are off unless this server's settings allow them, per container:
  ALLOW_LOGS=all | plex,nginx          (logs often contain secrets)
  ALLOW_CONTAINER_ACTIONS=all | plex   (start/stop/restart change the server)
Log lines are also scrubbed of obvious secrets before they leave this server.
"""
import os
import re
import struct
import time
from datetime import datetime

import httpx

from collectors import DOCKER_HOST

ACTIONS = ("start", "stop", "restart")
MAX_LINES = 2000        # per request; the page asks for more by narrowing the window
SCAN_LINES = 20000      # how far back a search looks inside the window
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")  # Docker's own rule; keeps "/", "?", "#" out of URLs
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d) ")


class Permit:
    """Which containers a feature may touch: none, all, or a list of names."""

    def __init__(self, env):
        v = os.environ.get(env, "").strip()
        if not v or v.lower() in ("0", "false", "no", "off"):
            self.names = None
        elif v.lower() in ("1", "true", "yes", "on", "all", "*"):
            self.names = True
        else:
            self.names = {x.strip() for x in v.split(",") if x.strip()}

    @property
    def on(self):
        return self.names is not None

    def allows(self, name):
        return self.names is True or (isinstance(self.names, set) and name in self.names)

    def describe(self):
        return sorted(self.names) if isinstance(self.names, set) else None


LOGS, ACTIONS_PERMIT = Permit("ALLOW_LOGS"), Permit("ALLOW_CONTAINER_ACTIONS")
REDACT = os.environ.get("LOG_REDACT", "true").lower() not in ("0", "false", "no", "off")

# Best-effort secret scrubbing. It can't catch everything, so logs stay opt-in per container.
SECRETS = [
    (re.compile(r"([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+@", re.I), r"\1***@"),           # user:pass@ in URLs
    (re.compile(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 ***"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "***"),     # JWTs
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), r"\1***"),                                  # AWS key ids
    (re.compile(r"\b((?:[a-z0-9_]*[_-])?(?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
                r"private[_-]?key|client[_-]?secret|auth(?:orization)?|cookie|session[_-]?id))"
                r"(\"?'?\s*[:=]\s*\"?'?)([^\s\"',;&]{3,})", re.I), r"\1\2***"),
]


def redact(text):
    for pattern, repl in SECRETS:
        text = pattern.sub(repl, text)
    return text


class DockerError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _parse_line(raw, stream):
    text = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip("\r\n")
    m = TS.match(text)
    body, t = (text[m.end():], m) if m else (text, None)
    if REDACT:
        body = redact(body)
    if not t:
        return {"t": None, "s": stream, "m": body}
    frac = (t.group(2) or "0")[:6].ljust(6, "0")
    zone = "+00:00" if t.group(3) == "Z" else t.group(3)
    ts = datetime.fromisoformat(f"{t.group(1)}.{frac}{zone}").timestamp()
    return {"t": round(ts, 3), "s": stream, "m": body}


class _Frames:
    """Docker multiplexes stdout/stderr as frames with an 8-byte header, unless the container
    has a TTY (then it's one plain stream). Feed bytes in, get whole lines out."""

    def __init__(self, tty):
        self.tty, self.buf, self.partial = tty, b"", {"out": b"", "err": b""}

    def feed(self, data):
        self.buf += data
        chunks = []
        if self.tty:
            chunks.append(("out", self.buf))
            self.buf = b""
        else:
            while len(self.buf) >= 8:
                kind, size = self.buf[0], struct.unpack(">I", self.buf[4:8])[0]
                if len(self.buf) < 8 + size:
                    break
                chunks.append(("err" if kind == 2 else "out", self.buf[8:8 + size]))
                self.buf = self.buf[8 + size:]
        lines = []
        for stream, chunk in chunks:
            data = self.partial[stream] + chunk
            *whole, self.partial[stream] = data.split(b"\n")
            lines += [_parse_line(w, stream) for w in whole]
        return lines

    def flush(self):
        rest = [_parse_line(v, k) for k, v in self.partial.items() if v]
        self.partial = {"out": b"", "err": b""}
        return rest


class Docker:
    def __init__(self, host=DOCKER_HOST):
        if host.startswith("tcp://"):
            transport, base = httpx.AsyncHTTPTransport(), "http://" + host[6:].rstrip("/")
        else:
            transport, base = httpx.AsyncHTTPTransport(uds=host.removeprefix("unix://")), "http://docker"
        self.client = httpx.AsyncClient(transport=transport, base_url=base, timeout=httpx.Timeout(20, read=60))

    async def inspect(self, name):
        if not NAME.match(name or ""):
            raise DockerError("Pick a container")
        try:
            r = await self.client.get(f"/containers/{name}/json")
        except httpx.HTTPError as e:
            raise DockerError(f"Docker isn't reachable ({type(e).__name__})", 503) from None
        if r.status_code == 404:
            raise DockerError(f"No container named {name}", 404)
        if r.status_code >= 400:
            raise DockerError(f"Docker answered {r.status_code}", 502)
        j = r.json()
        return {"id": j["Id"], "name": j["Name"].lstrip("/"), "tty": bool(j["Config"].get("Tty")),
                "image": j["Config"].get("Image", ""), "running": j["State"].get("Running", False)}

    async def _permitted(self, name, permit, what):
        c = await self.inspect(name)
        if not permit.allows(c["name"]):
            raise DockerError(f"{what} for {c['name']} aren't allowed on this server", 403)
        return c

    async def logs(self, name, since=None, until=None, tail=500, q=""):
        c = await self._permitted(name, LOGS, "Logs")
        tail = max(1, min(MAX_LINES, int(tail)))
        params = {"stdout": 1, "stderr": 1, "timestamps": 1, "tail": SCAN_LINES if q or since else tail}
        if since:
            params["since"] = f"{float(since):.3f}"
        if until:
            params["until"] = f"{float(until):.3f}"
        lines, frames = [], _Frames(c["tty"])
        async with self.client.stream("GET", f"/containers/{c['id']}/logs", params=params) as r:
            if r.status_code >= 400:
                raise DockerError(f"Docker answered {r.status_code} for the logs", 502)
            async for chunk in r.aiter_raw():
                lines += frames.feed(chunk)
        lines += frames.flush()
        if q:
            ql = q.lower()
            lines = [ln for ln in lines if ql in ln["m"].lower()]
        return {"container": c["name"], "lines": lines[-tail:], "truncated": len(lines) > tail}

    async def check_follow(self, name):
        return await self._permitted(name, LOGS, "Logs")

    async def follow(self, name):
        """Yields new log lines as they're written, until the caller stops iterating."""
        c = await self._permitted(name, LOGS, "Logs")
        frames = _Frames(c["tty"])
        params = {"stdout": 1, "stderr": 1, "timestamps": 1, "follow": 1, "tail": 0, "since": f"{time.time():.3f}"}
        async with self.client.stream("GET", f"/containers/{c['id']}/logs", params=params,
                                      timeout=httpx.Timeout(20, read=None)) as r:
            if r.status_code >= 400:
                raise DockerError(f"Docker answered {r.status_code} for the logs", 502)
            async for chunk in r.aiter_raw():
                for line in frames.feed(chunk):
                    yield line

    async def action(self, name, action):
        if action not in ACTIONS:
            raise DockerError("Action must be start, stop or restart")
        c = await self._permitted(name, ACTIONS_PERMIT, "Container actions")
        if action == "stop" and "monitorr" in c["image"].lower():
            raise DockerError("That's Monitorr itself. Stopping it would take this page down; stop it on the server.")
        try:
            r = await self.client.post(f"/containers/{c['id']}/{action}", params={"t": 10},
                                       timeout=httpx.Timeout(40))
        except httpx.HTTPError as e:
            raise DockerError(f"Docker didn't answer ({type(e).__name__})", 504) from None
        if r.status_code == 304:
            return c["name"], "already " + ("running" if action == "start" else "stopped")
        if r.status_code == 403:
            raise DockerError("The Docker proxy refused this action. Allow it there too (DOCKER_PROXY_ACTIONS=1).", 403)
        if r.status_code >= 400:
            raise DockerError((r.json().get("message") if r.headers.get("content-type", "").startswith(
                "application/json") else None) or f"Docker answered {r.status_code}", 502)
        return c["name"], {"start": "started", "stop": "stopped", "restart": "restarted"}[action]

    async def close(self):
        await self.client.aclose()
