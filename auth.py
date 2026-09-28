"""Login for Monitorr: one user, a scrypt password hash, and a signed session cookie.

Create the hash with:  python app.py --hash-password
"""
import base64
import getpass
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

COOKIE = "monitorr_session"
SESSION_DAYS = float(os.environ.get("SESSION_DAYS", "30"))
MAX_FAILS, FAIL_WINDOW = 5, 300  # per client IP: 5 wrong passwords in 5 minutes locks it out
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


class Auth:
    def __init__(self, data_dir):
        self.user = os.environ.get("AUTH_USER", "admin")
        self.pw_hash = os.environ.get("AUTH_PASSWORD_HASH", "").strip()
        self.enabled = os.environ.get("AUTH_DISABLED", "").lower() not in ("1", "true", "yes")
        self._fails = {}
        # Sessions are signed with a key derived from the password hash, so changing the
        # password signs everyone out.
        self._key = hmac.new(self._secret(Path(data_dir)), self.pw_hash.encode(), hashlib.sha256).digest()

    def check_config(self):
        if self.enabled and not self.pw_hash:
            raise SystemExit(
                "Monitorr needs a password. Run `python app.py --hash-password` (or "
                "`docker compose run --rm monitorr python app.py --hash-password`) and set "
                "AUTH_PASSWORD_HASH to the result. To run without login, set AUTH_DISABLED=true.")

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
        payload = _b64(f"{self.user}|{int(time.time() + SESSION_DAYS * 86400)}".encode())
        return f"{payload}.{self._sign(payload)}"

    def valid(self, token):
        if not self.enabled:
            return True
        if not token or "." not in token:
            return False
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, self._sign(payload)):
            return False
        try:
            user, exp = _unb64(payload).decode().split("|")
            return user == self.user and int(exp) > time.time()
        except ValueError:
            return False

    def _sign(self, payload):
        return _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())

    # ---------- login ----------
    def locked(self, ip):
        now = time.time()
        fails = [t for t in self._fails.get(ip, []) if now - t < FAIL_WINDOW]
        self._fails[ip] = fails
        return len(fails) >= MAX_FAILS

    def login(self, ip, user, password):
        ok = hmac.compare_digest(user.encode(), self.user.encode()) & verify_password(password, self.pw_hash)
        if ok:
            self._fails.pop(ip, None)
        else:
            self._fails.setdefault(ip, []).append(time.time())
        return ok
