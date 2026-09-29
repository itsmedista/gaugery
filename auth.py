"""Login for the Monitorr hub: one user, a scrypt password hash, optional two-factor codes (TOTP),
and signed session cookies that can be revoked.

Create the hash with:  python app.py --hash-password
"""
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote

COOKIE = "monitorr_session"
SESSION_DAYS = float(os.environ.get("SESSION_DAYS", "30"))
REAUTH_AFTER = 15 * 60           # sensitive actions ask for the password again after this long
FREE_TRIES, MAX_DELAY, FAIL_WINDOW = 3, 30, 900
MAX_TRACKED = 10000              # addresses remembered for slowing down guesses, so a flood can't eat memory
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
    if len(pw) < 10:
        raise SystemExit("Use at least 10 characters.")
    if getpass.getpass("Repeat it: ") != pw:
        raise SystemExit("The passwords don't match.")
    print(hash_password(pw))


def new_token():
    print(secrets.token_urlsafe(32))


def password_problem(new, user="", current=""):
    """Why a new password isn't acceptable, or None."""
    if len(new) < 10:
        return "Use at least 10 characters."
    if len(new) > 1024:
        return "That's too long."
    if new == current:
        return "That's the password you have now."
    if user and len(user) >= 3 and user.lower() in new.lower():
        return "Don't use your username in your password."
    return None


# ---------- recovery codes: one-time stand-ins for a two-factor code, if the phone is lost ----------
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no 0/o, 1/l/i: easy to read back


def recovery_codes(n=8):
    """(codes to show once, their hashes to store). 10 random characters each (about 50 bits)."""
    codes = ["".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10)) for _ in range(n)]
    codes = [f"{c[:5]}-{c[5:]}" for c in codes]
    return codes, [recovery_hash(c) for c in codes]


def recovery_hash(code):
    return hashlib.sha256("".join(ch for ch in str(code).lower() if ch.isalnum()).encode()).hexdigest()


def token_ok(header, token):
    """A Bearer header carrying exactly this token."""
    if not token or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[7:].strip().encode(), token.encode())


# ---------- two-factor codes (RFC 6238: 30-second, 6-digit, SHA-1, as every authenticator app does) ----------
def totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_uri(secret, user):
    return f"otpauth://totp/Monitorr:{quote(user)}?secret={secret}&issuer=Monitorr"


def _totp(secret, counter):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return f"{(struct.unpack('>I', h[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def totp_match(secret, code, last_used=0):
    """The time step the code belongs to (now, or one step either side for clock drift),
    or None. A step at or before `last_used` is refused, so a code works only once."""
    code = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(code) != 6 or not secret:
        return None
    now = int(time.time() // 30)
    for step in (now, now - 1, now + 1):
        if step > last_used and hmac.compare_digest(_totp(secret, step), code):
            return step
    return None


class Auth:
    def __init__(self, data_dir):
        self.user = os.environ.get("AUTH_USER", "admin")
        self.pw_hash = os.environ.get("AUTH_PASSWORD_HASH", "").strip()
        self._fails = {}
        self._master = self._secret(Path(data_dir))
        self.generation = 0    # "sign out everywhere else" moves this on; older sessions stop working
        self.set_hash(self.pw_hash)
        # Signed-out sessions (id -> expiry), so a copied cookie stops working at logout.
        self._revoked_path = Path(data_dir) / "revoked-sessions.json"
        try:
            self._revoked = {k: float(v) for k, v in json.loads(self._revoked_path.read_text()).items()}
        except (OSError, ValueError, AttributeError):
            self._revoked = {}

    def set_hash(self, pw_hash):
        """Use this password hash from now on. Sessions are signed with a key derived from it,
        so changing the password signs everyone out."""
        self.pw_hash = pw_hash
        self._key = hmac.new(self._master, pw_hash.encode(), hashlib.sha256).digest()

    def check_config(self):
        if os.environ.get("AUTH_DISABLED"):
            raise SystemExit("AUTH_DISABLED was removed: Monitorr always asks for a password. Remove the setting.")
        if not self.pw_hash:
            raise SystemExit(
                "Monitorr needs a password. Run `python app.py --hash-password` (or "
                "`docker compose run --rm monitorr python app.py --hash-password`) and set "
                "AUTH_PASSWORD_HASH to the result.")

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
    def issue(self, exp=None):
        """A session cookie value; its auth time (now) is when the password was last entered."""
        exp = int(exp or time.time() + SESSION_DAYS * 86400)
        payload = _b64(f"{self.user}|{exp}|{secrets.token_urlsafe(12)}|{int(time.time())}|{self.generation}".encode())
        return f"{payload}.{self._sign(payload)}"

    def session(self, token):
        """{"id", "exp", "auth_time"} of a genuine, unexpired, not revoked session, else None."""
        if not token or "." not in token or len(token) > 512:
            return None
        payload, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig.encode(), self._sign(payload).encode()):
            return None
        try:
            user, exp, sid, auth_time, generation = _unb64(payload).decode().split("|")
            exp, auth_time, generation = int(exp), int(auth_time), int(generation)
        except ValueError:
            return None
        if user != self.user or exp <= time.time() or sid in self._revoked or generation != self.generation:
            return None
        return {"id": sid, "exp": exp, "auth_time": auth_time}

    def valid(self, token):
        return self.session(token) is not None

    def recent(self, token):
        s = self.session(token)
        return s is not None and time.time() - s["auth_time"] < REAUTH_AFTER

    def revoke(self, token):
        s = self.session(token)
        if not s:
            return
        now = time.time()
        self._revoked = {k: v for k, v in self._revoked.items() if v > now}
        self._revoked[s["id"]] = s["exp"]
        try:
            self._revoked_path.write_text(json.dumps(self._revoked))
        except OSError:
            pass  # still revoked until the process restarts

    def _sign(self, payload):
        return _b64(hmac.new(self._key, payload.encode(), hashlib.sha256).digest())

    # ---------- guessing ----------
    def wait(self, ip):
        """Seconds this address must wait before its next try. Delays grow with each wrong
        password (1, 2, 4 ... 30 s) instead of locking anyone out, so an attacker can slow
        the owner down by at most half a minute."""
        now = time.time()
        if len(self._fails) > MAX_TRACKED:
            self._fails = {k: v for k, v in self._fails.items() if now - v[1] < FAIL_WINDOW}
        n, last = self._fails.get(ip, (0, 0.0))
        if now - last > FAIL_WINDOW:
            self._fails.pop(ip, None)
            return 0
        delay = 0 if n < FREE_TRIES else min(MAX_DELAY, 2 ** (n - FREE_TRIES))
        return max(0, int(last + delay - now + 0.999))

    def failed(self, ip):
        n, _ = self._fails.get(ip, (0, 0.0))
        self._fails[ip] = (n + 1, time.time())
        return n + 1

    def succeeded(self, ip):
        self._fails.pop(ip, None)

    def password_ok(self, user, password):
        # both compared every time, so neither the user name nor timing gives anything away
        return hmac.compare_digest(user.encode(), self.user.encode()) & verify_password(password, self.pw_hash)
