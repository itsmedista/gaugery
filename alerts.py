"""Threshold alerts with hold times, an event log, and optional ntfy/webhook notifications."""
import json
import os
import threading
import time
import urllib.request
from collections import deque


def _env(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


DISC_FS = ("iso9660", "udf")  # CD/DVD images: read-only and always 100% used

CFG = {
    "cpu_warn": _env("ALERT_CPU", 90),          # % for 5 minutes
    "mem_warn": _env("ALERT_MEM", 90),          # %
    "disk_warn": _env("ALERT_DISK_WARN", 85),   # % full
    "disk_crit": _env("ALERT_DISK_CRIT", 95),
    "temp_warn": _env("ALERT_TEMP_WARN", 80),   # °C
    "temp_crit": _env("ALERT_TEMP_CRIT", 90),
    "fill_days": _env("ALERT_FILL_DAYS", 14),   # warn when a drive fills sooner than this
}


def _gib(v):
    return f"{v / 1024 ** 3:.1f} GiB" if v < 1024 ** 4 else f"{v / 1024 ** 4:.2f} TiB"


class AlertEngine:
    def __init__(self, host, cores, on_event=None, history=None):
        self.host, self.cores, self.on_event = host, cores, on_event
        self.pending, self.active = {}, {}
        self.log = deque(history or [], maxlen=100)
        self.ntfy_url = os.environ.get("NTFY_URL", "").strip()
        self.ntfy_token = os.environ.get("NTFY_TOKEN", "").strip()
        self.webhook_url = os.environ.get("WEBHOOK_URL", "").strip()
        self.webhook_secret = os.environ.get("WEBHOOK_SECRET", "").strip()
        self._seen = set()

    def _check(self, now, aid, cond, severity, title, detail, hold=0):
        self._seen.add(aid)
        if not cond:
            self.pending.pop(aid, None)
            a = self.active.pop(aid, None)
            if a:
                self._event(now, "resolved", a)
            return
        first = self.pending.setdefault(aid, now)
        if now - first < hold:
            return
        a = self.active.get(aid)
        if a is None:
            a = {"id": aid, "severity": severity, "title": title, "detail": detail, "since": now}
            self.active[aid] = a
            self._event(now, "raised", a)
        else:
            escalated = a["severity"] == "warning" and severity == "critical"
            a.update(severity=severity, title=title, detail=detail)
            if escalated:
                self._event(now, "raised", a)

    def evaluate(self, s, state, now=None):
        now = now or time.time()
        self._seen = set()
        c = CFG
        cpu = s.get("cpu:total", 0)
        self._check(now, "cpu", cpu >= c["cpu_warn"], "warning",
                    f"CPU above {c['cpu_warn']:.0f}% for 5 minutes",
                    f"Currently at {cpu:.0f}%.", hold=300)
        mem = s.get("mem:pct", 0)
        self._check(now, "mem", mem >= c["mem_warn"], "critical" if mem >= 97 else "warning",
                    f"Memory at {mem:.0f}%",
                    f"{_gib(s.get('mem:used', 0))} in use.", hold=120)
        load = s.get("load:5", 0)
        self._check(now, "load", load >= self.cores * 2, "warning",
                    "Load is more than twice the core count",
                    f"5-minute load {load:.2f} on {self.cores} threads.", hold=300)
        for k, v in state.get("temps", {}).items():
            sev = "critical" if v >= c["temp_crit"] else "warning"
            self._check(now, f"temp:{k}", v >= c["temp_warn"], sev,
                        f"{k} is at {v:.0f}°C", f"Warning threshold is {c['temp_warn']:.0f}°C.", hold=60)

        for d in state.get("drives", []):
            m = d["mount"]
            self._check(now, f"unresp:{m}", d["status"] == "unresponsive", "critical",
                        f"{m} is not responding",
                        "Reading this mount timed out. For network shares, check the server and connection.",
                        hold=10)
            self._check(now, f"ro:{m}", d["readonly"] and not d["network"]
                        and d["fs"] not in DISC_FS, "critical",
                        f"{m} is mounted read-only",
                        "The kernel may have remounted it after disk errors. Check dmesg.")
            pct = d.get("pct")
            if pct is not None and d["fs"] not in DISC_FS:  # disc images are always 100% "full"
                self._check(now, f"full:{m}", pct >= c["disk_warn"],
                            "critical" if pct >= c["disk_crit"] else "warning",
                            f"{m} is {pct:.0f}% full",
                            f"{_gib(d['free'])} free of {_gib(d['total'])}.")
            days = d.get("days_to_full")
            self._check(now, f"fill:{m}", days is not None and 0 <= days < c["fill_days"], "warning",
                        f"{m} will fill in about {max(days or 0, 0):.0f} days",
                        "Based on how fast usage grew over the last week.")
            sm = d.get("smart")
            if sm and d.get("disk"):
                disk = d["disk"]
                bad = sm["status"] in ("failed", "warning")
                parts = []
                if sm.get("reallocated"):
                    parts.append(f"{sm['reallocated']} reallocated sectors")
                if sm.get("pending"):
                    parts.append(f"{sm['pending']} pending sectors")
                if sm.get("media_errors"):
                    parts.append(f"{sm['media_errors']} media errors")
                if sm.get("wear") is not None and sm["wear"] >= 90:
                    parts.append(f"{sm['wear']}% of rated life used")
                title = f"SMART reports {disk} is failing" if sm["status"] == "failed" \
                    else f"SMART warning on {disk}"
                self._check(now, f"smart:{disk}", bad,
                            "critical" if sm["status"] == "failed" else "warning", title,
                            (", ".join(parts) or "Overall health check failed") + ". Back up this drive.")

        for ct in state.get("containers", []):
            n = ct["name"]
            self._check(now, f"ctr-restart:{n}", ct["state"] == "restarting", "critical",
                        f"Container {n} is restart-looping", f"Restarted {ct['restarts']} times.", hold=20)
            crashed = ct["state"] == "exited" and ct.get("exit_code") not in (0, None)
            self._check(now, f"ctr-exit:{n}", crashed, "warning",
                        f"Container {n} exited with code {ct.get('exit_code')}",
                        "Check its logs with docker logs " + n + ".")
            self._check(now, f"ctr-health:{n}", ct.get("health") == "unhealthy", "warning",
                        f"Container {n} is unhealthy", "Its health check is failing.", hold=30)

        return self._finish(now)

    def evaluate_items(self, items, now=None):
        """Alerts computed elsewhere (service checks): each item is the arguments of one
        _check() call after `now`. Anything not listed any more is resolved."""
        now = now or time.time()
        self._seen = set()
        for item in items:
            self._check(now, *item)
        return self._finish(now)

    def _finish(self, now):
        for aid in list(self.active):
            if aid not in self._seen:  # the thing it was about disappeared
                self._event(now, "resolved", self.active.pop(aid))
        for aid in list(self.pending):
            if aid not in self._seen:
                self.pending.pop(aid)

        order = {"critical": 0, "warning": 1}
        active = sorted(self.active.values(), key=lambda a: (order[a["severity"]], -a["since"]))
        return {"active": active, "log": list(self.log)[-40:][::-1]}

    def note(self, title, detail, now=None):
        """Record something a person did (e.g. restarted a container) in the log and on ntfy."""
        self._event(now or time.time(), "action", {"severity": "info", "title": title, "detail": detail})

    def _event(self, now, kind, a):
        ev = {"ts": now, "kind": kind, "severity": a["severity"], "title": a["title"], "detail": a["detail"]}
        self.log.append(ev)
        if self.on_event:
            self.on_event(ev)
        if self.ntfy_url:
            threading.Thread(target=self._notify, args=(ev,), daemon=True).start()
        if self.webhook_url:
            threading.Thread(target=self._webhook, args=(ev, a.get("id")), daemon=True).start()

    def _notify(self, ev):
        resolved, action = ev["kind"] == "resolved", ev["kind"] == "action"
        headers = {
            "Title": f"[{self.host}] " + ("Resolved: " if resolved else "") + ev["title"],
            "Priority": "default" if resolved or action else ("urgent" if ev["severity"] == "critical" else "high"),
            "Tags": "white_check_mark" if resolved else "gear" if action else (
                "rotating_light" if ev["severity"] == "critical" else "warning"),
        }
        if self.ntfy_token:
            headers["Authorization"] = f"Bearer {self.ntfy_token}"
        # one line each (a mount name can contain a newline), and latin-1 as HTTP headers require
        headers = {k: " ".join(v.split()).encode("latin-1", "replace").decode("latin-1") for k, v in headers.items()}
        try:
            req = urllib.request.Request(self.ntfy_url, data=ev["detail"].encode(), headers=headers)
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:  # noqa: BLE001
            pass

    def _webhook(self, ev, alert_id):
        """POST the event as JSON, e.g. to an n8n webhook that triages it with Claude."""
        body = json.dumps({"host": self.host, "id": alert_id, **ev}).encode()
        headers = {"Content-Type": "application/json"}
        if self.webhook_secret:
            headers["X-Webhook-Secret"] = self.webhook_secret
        try:
            req = urllib.request.Request(self.webhook_url, data=body, headers=headers, method="POST")
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:  # noqa: BLE001
            pass
