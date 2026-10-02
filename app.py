"""Gaugery entry point.

  python app.py hub        the web interface (unprivileged)
  python app.py agent      collects one server's data for a hub
  (or set ROLE=hub / ROLE=agent)

Tools:
  python app.py --hash-password    make AUTH_PASSWORD_HASH
  python app.py --new-token        make an AGENT_TOKEN
  python app.py --pairing-code     print this agent's pairing code for "Add server"
  python app.py --disable-2fa      turn off two-factor sign-in (if you lost your phone)
  python app.py --reset-password   set a new password (if you forgot it); signs everyone out
  python app.py --healthcheck      used by Docker's HEALTHCHECK
"""
import os
import sys

os.umask(0o077)  # everything Gaugery writes (databases, keys, tokens) is for its own user only

if hasattr(__import__("signal"), "SIGUSR1"):  # `docker kill -s USR1 <container>` prints every thread's stack
    import faulthandler
    import signal
    faulthandler.register(signal.SIGUSR1, all_threads=True)


def role():
    for arg in sys.argv[1:]:
        if arg in ("hub", "agent"):
            return arg
    return os.environ.get("ROLE", "hub").lower()


def healthcheck():
    import http.client
    import socket
    import ssl
    listen = os.environ.get("AGENT_LISTEN", "tcp")
    try:
        if role() == "agent" and listen.startswith("unix:"):
            class Unix(http.client.HTTPConnection):
                def connect(self):
                    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    self.sock.settimeout(4)
                    self.sock.connect(listen[5:])
            conn = Unix("agent", timeout=4)
        else:
            port = int(os.environ.get("PORT", "8088"))
            tls = role() == "agent" or os.environ.get("TLS", "").lower() == "auto" or os.environ.get("TLS_CERT")
            host = os.environ.get("HOST", "0.0.0.0")
            host = "127.0.0.1" if host in ("0.0.0.0", "::", "") else host
            conn = (http.client.HTTPSConnection(host, port, timeout=4, context=ssl._create_unverified_context())
                    if tls else http.client.HTTPConnection(host, port, timeout=4))
        conn.request("GET", "/healthz")
        sys.exit(0 if conn.getresponse().status == 200 else 1)
    except Exception:  # noqa: BLE001
        sys.exit(1)


def main():
    args = sys.argv[1:]
    if "--hash-password" in args:
        from auth import prompt_hash
        return prompt_hash()
    if "--new-token" in args:
        from auth import new_token
        return new_token()
    if "--healthcheck" in args:
        return healthcheck()
    if "--pairing-code" in args:
        import tlsutil
        from agent import DB_PATH
        from pathlib import Path
        cert, _ = tlsutil.ensure_cert(Path(DB_PATH).parent)
        return print(tlsutil.pairing_code(cert, os.environ.get("AGENT_TOKEN", "").strip()))
    if "--reset-password" in args:
        import json
        import time
        from auth import prompt_hash
        from common import open_db
        from hub import HUB_DB
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            prompt_hash()          # asks twice, checks the length, prints the hash
        db, _ = open_db(HUB_DB)
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)")
        db.execute("INSERT OR REPLACE INTO settings VALUES ('password_hash', ?)", (json.dumps(buf.getvalue().strip()),))
        db.execute("INSERT INTO events VALUES (?, 'action', 'info', ?, ?)",
                   (time.time(), "Password reset", "From the command line on the server. Everyone was signed out."))
        db.commit()
        return print("Password changed. Restart Gaugery's web interface to use it (everyone is signed out).")
    if "--disable-2fa" in args:
        import time
        from common import open_db
        from hub import HUB_DB
        db, _ = open_db(HUB_DB)
        db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS events (ts REAL, kind TEXT, severity TEXT, title TEXT, detail TEXT)")
        db.execute("DELETE FROM settings WHERE key IN ('totp_secret', 'totp_last', 'totp_pending')")
        db.execute("INSERT INTO events VALUES (?, 'action', 'info', ?, ?)",
                   (time.time(), "Two-factor sign-in turned off", "From the command line on the server."))
        db.commit()
        return print("Two-factor sign-in is off. Sign in with your password and turn it on again.")
    if role() == "agent":
        from agent import serve
    else:
        from hub import serve
    serve()


if __name__ == "__main__":
    main()
