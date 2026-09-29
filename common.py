"""Pieces the hub and the agent share."""
import os
import sqlite3
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from security import API_CSP, BASE_HEADERS, refuse

HERE = Path(__file__).resolve().parent


def open_db(path):
    """SQLite in WAL mode, readable by this process's user only (it can hold tokens)."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(path, check_same_thread=False)
    except (OSError, sqlite3.OperationalError):
        path = str(HERE / Path(path).name)  # fallback when the default location isn't writable
        db = sqlite3.connect(path, check_same_thread=False)
    for f in (path, path + "-wal", path + "-shm"):  # databases made by older versions were world-readable
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
    db.execute("PRAGMA journal_mode=WAL")
    return db, path


async def read_json(request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = None
    if not isinstance(body, dict):
        raise HTTPException(400, "Send a JSON object")
    return body


def harden(app, page_csp=None, hsts=True):
    """Outermost middleware (add it after all others): turn away bad requests, add security headers.
    hsts=False for a self-signed certificate: HSTS would stop browsers from letting you click past its warning."""

    @app.middleware("http")
    async def _harden(request: Request, call_next):
        bad = refuse(request)
        resp = JSONResponse({"detail": bad[1]}, status_code=bad[0]) if bad else await call_next(request)
        for k, v in BASE_HEADERS.items():
            resp.headers.setdefault(k, v)
        # Chosen by where the request went, not by the answer's type: a "304 Not Modified" for a page
        # has no type, and browsers merge its headers into the cached page. Giving it the API's
        # lock-everything policy broke every page on reload.
        if page_csp and not request.url.path.startswith("/api/"):
            resp.headers["Content-Security-Policy"] = page_csp.value()
        else:
            resp.headers.setdefault("Content-Security-Policy", API_CSP)
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        if hsts and request.url.scheme == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return resp
