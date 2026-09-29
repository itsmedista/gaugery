"""Container logs and actions for Monitorr, straight from the Docker API.

Logs are on unless ALLOW_LOGS=false. Start/stop/restart are off unless
ALLOW_CONTAINER_ACTIONS=true, because they change the server, not just read it.
"""
import os
import re
import struct
import time
from datetime import datetime

import httpx

ALLOW_LOGS = os.environ.get("ALLOW_LOGS", "true").lower() not in ("0", "false", "no")
ALLOW_ACTIONS = os.environ.get("ALLOW_CONTAINER_ACTIONS", "").lower() in ("1", "true", "yes")
ACTIONS = ("start", "stop", "restart")
MAX_LINES = 2000        # per request; the page asks for more by narrowing the window
SCAN_LINES = 20000      # how far back a search looks inside the window
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")  # Docker's own rule; keeps "/", "?", "#" out of URLs
TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d) ")


class DockerError(Exception):
    def __init__(self, msg, status=400):
        super().__init__(msg)
        self.status = status


def _parse_line(raw, stream):
    text = ANSI.sub("", raw.decode("utf-8", "replace")).rstrip("\r\n")
    m = TS.match(text)
    if not m:
        return {"t": None, "s": stream, "m": text}
    frac = (m.group(2) or "0")[:6].ljust(6, "0")
    zone = "+00:00" if m.group(3) == "Z" else m.group(3)
    t = datetime.fromisoformat(f"{m.group(1)}.{frac}{zone}").timestamp()
    return {"t": round(t, 3), "s": stream, "m": text[m.end():]}


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
    def __init__(self, sock):
        self.client = httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=sock), base_url="http://docker",
                                        timeout=httpx.Timeout(20, read=60))

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

    async def logs(self, name, since=None, until=None, tail=500, q=""):
        c = await self.inspect(name)
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

    async def follow(self, name):
        """Yields new log lines as they're written, until the caller stops iterating."""
        c = await self.inspect(name)
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
        c = await self.inspect(name)
        if action == "stop" and "monitorr" in c["image"].lower():
            raise DockerError("That's Monitorr itself. Stopping it would take this page down; stop it on the server.")
        try:
            r = await self.client.post(f"/containers/{c['id']}/{action}", params={"t": 10},
                                       timeout=httpx.Timeout(40))
        except httpx.HTTPError as e:
            raise DockerError(f"Docker didn't answer ({type(e).__name__})", 504) from None
        if r.status_code == 304:
            return c["name"], "already " + ("running" if action == "start" else "stopped")
        if r.status_code >= 400:
            raise DockerError((r.json().get("message") if r.headers.get("content-type", "").startswith(
                "application/json") else None) or f"Docker answered {r.status_code}", 502)
        return c["name"], {"start": "started", "stop": "stopped", "restart": "restarted"}[action]

    async def close(self):
        await self.client.aclose()
