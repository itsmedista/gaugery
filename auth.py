"""Login for Monitorr: one user, a scrypt password hash, and a signed session cookie.

Create the hash with:  python app.py --hash-password

A server that another Monitorr watches runs as an agent: it sets AGENT_TOKEN, and the hub
sends that token as a Bearer header. The token only unlocks the read-only data endpoints.
"""
import base64
import getpass
import json
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

COOKIE = "monitorr_session"
SESSION_DAYS = float(os.environ.get("SESSION_DAYS", "30"))
MAX_FAILS, FAIL_WINDOW = 5, 300  # per client IP: 5 wrong passwords in 5 minutes locks it out
MAX_TRACKED = 10000              # addresses remembered for that, so a flood can't eat memory
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hash_password(password):
    # Colons, not "$", as separators so the hash survives docker compose variable interpolation.
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{_b64(salt)}:{_b64(dk)}"


def verify_password(password, stored):
    try:
        algo, n, r, p, salt, dk = stored.split(":")
        if algo != "scrypt":
            return False
        want = _unb64(dk)
        got = hashlib.scrypt(password.encode(), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
                             dklen=len(want))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(got, want)


def prompt_hash():
    pw = getpass.getpass("New Monitorr password: ")
    if len(pw) < 8:
        raise SystemExit("Use at least 8 characters.")
    if getpass.getpass("Repeat it: ") != pw:
        raise SystemExit("The passwords don't match.")
    print(hash_password(pw))


def new_token():
    print(secrets.token_urlsafe(32))


class Auth:
    def __init__(self, data_dir):
        self.user = os.environ.get("AUTH_USER", "admin")
        self.pw_hash = os.environ.get("AUTH_PASSWORD_HASH", "").strip()
        self.enabled = os.environ.get("AUTH_DISABLED", "").lower() not in ("1", "true", "yes")
        self.agent_token = os.environ.get("AGENT_TOKEN", "").strip()
        self._fails = {}
        # Sessions are signed with a key derived from the password hash, so changing the
        # password signs everyone out.
        self._key = hmac.new(self._secret(Path(data_dir)), self.pw_hash.encode(), hashlib.sha256).digest()
        # Signed-out sessions (id -> expiry), so a copied cookie stops working at logout.
        self._revoked_path = Path(data_dir) / "revoked-sessions.json"
        try:
            self._revoked = {k: float(v) for k, v in json.loads(self._revoked_path.read_text()).items()}
        except (OSError, ValueError, AttributeError):
            self._revoked = {}

    def check_config(self):
        if self.agent_token and len(self.agent_token) < 24:
            raise SystemExit("AGENT_TOKEN is too short. Make one with `python app.py --new-token`.")
        if self.enabled and not self.pw_hash and not self.agent_token:
            raise SystemExit(
                "Monitorr needs a password. Run `python app.py --hash-password` (or "
                "`docker compose run --rm monitorr python app.py --hash-password`) and set "
                "AUTH_PASSWORD_HASH to the result. For an agent that only a hub reads, set "
                "AGENT_TOKEN instead. To run without login, set AUTH_DISABLED=true.")

    def agent_ok(self, header):
        if not self.agent_token or not header or not header.startswith("Bearer "):
            return False
        return hmac.compare_digest(header[7:].strip().encode(), self.agent_token.encode())

    @staticmethod
    def _secret(data_dir):
        if os.environ.get("SECRET_KEY"):
            return os.environ["SECRET_KEY"].encode()
        path = data_dir / "secret.key"
        try:
            return path.read_bytes()
        except OSError:
            key = secrets.token_bytes(32)
            try:
                path.write_bytes(key)
                path.chmod(0o600)
            except OSError:
                pass  # not persisted: sessions end when the process restarts
            return key

    # ---------- sessions ----------
    def issue(self):
        exp = int(time.time() + SESSION_DAYS * 86400)
        payload = _b64(f"{self.user}|{exp}|{secrets.token_urlsafe(12)}".encode())
        return f"{payload}.{self._sign(payload)}"

    def _session(self, token):
        """(session id, expiry) of a genuine, unexpired session token, else None."""
        if not token or "." not in token or len(token) > 512:
            return None
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig.encode(), self._sign(payload).encode()):
            return None
        try:
            user, exp, sid = _unb64(payload).decode().split("|")
            exp = int(exp)
        except ValueError:
            return None
        return (sid, exp) if user == self.user and exp > time.time() else None

    def valid(self, token):
        if not self.enabled:
            return True
        if not self.pw_hash:  # agent-only: nobody signs in here
            return False
        s = self._session(token)
        return s is not None and s[0] not in self._revoked

    def revoke(self, token):
        s = self._session(token)
        if not s:
            return
        now = time.time()
        self._revoked = {k: v for k, v in self._revoked.items() if v > now}
        self._revoked[s[0]] = s[1]
        try:
            self._revoked_path.write_text(json.dumps(self._revoked))
        except OSError:
            pass  # still revoked until the process restarts

    def _sign(self, payload):
        return _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())

    # ---------- login ----------
    def locked(self, ip):
        now = time.time()
        if len(self._fails) > MAX_TRACKED:
            self._fails = {k: v for k, v in self._fails.items() if v and now - v[-1] < FAIL_WINDOW}
        fails = [t for t in self._fails.get(ip, []) if now - t < FAIL_WINDOW]
        if fails:
            self._fails[ip] = fails
        else:
            self._fails.pop(ip, None)
        return len(fails) >= MAX_FAILS

    def login(self, ip, user, password):
        if not self.pw_hash:
            return False
        ok = hmac.compare_digest(user.encode(), self.user.encode()) & verify_password(password, self.pw_hash)
        if ok:
            self._fails.pop(ip, None)
        else:
            self._fails.setdefault(ip, []).append(time.time())
        return ok
