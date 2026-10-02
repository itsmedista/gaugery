"""Browser-facing hardening for Monitorr: security headers, a strict Content-Security-Policy,
cross-site request refusal, request size limits, and an optional Host allow-list."""
import base64
import hashlib
import os
import re
from pathlib import Path
from urllib.parse import urlsplit

MAX_BODY = 64 * 1024                     # every request body Monitorr accepts is tiny JSON
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
# Optional: the host names this instance answers to (e.g. "monitorr.lan,100.64.0.5"). Stops DNS
# rebinding, where a web page points its own domain at your server's IP to read it.
ALLOWED_HOSTS = {h.strip().lower() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()}

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",           # no framing, so no clickjacking of the Stop button
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
}
API_CSP = "default-src 'none'; frame-ancestors 'none'"


class PageCSP:
    """CSP for the HTML pages. Scripts may only come from this origin or be one of the pages'
    own inline scripts (allowed by hash), so injected markup can never run code."""

    def __init__(self, static_dir):
        self.dir, self._key, self._value = Path(static_dir), None, ""

    def value(self):
        files = sorted(self.dir.glob("*.html"))
        key = tuple((f.name, f.stat().st_mtime_ns) for f in files)
        if key != self._key:  # recompute when a page changes (e.g. after an update)
            hashes = []
            for f in files:
                for body in re.findall(r"<script>(.*?)</script>", f.read_text(encoding="utf-8"), re.S):
                    digest = base64.b64encode(hashlib.sha256(body.encode()).digest()).decode()
                    hashes.append(f"'sha256-{digest}'")
            self._key, self._value = key, "; ".join([
                "default-src 'self'",
                "script-src 'self' " + " ".join(sorted(set(hashes))),
                "style-src 'self' 'unsafe-inline'",
                "font-src 'self'",                  # fonts are served from here: no third party sees visitors
                "img-src 'self' data:",
                "connect-src 'self'",
                "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'",
            ])
        return self._value


def _host(value):
    value = (value or "").lower().strip()
    if value.startswith("["):  # [::1]:8088
        return value.split("]")[0] + "]"
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def refuse(request):
    """A reason to turn the request away before it reaches any route, or None."""
    h = request.headers
    browser = "authorization" not in h  # hub -> agent calls carry a Bearer token; browsers can't add one cross-site
    if browser and ALLOWED_HOSTS and request.url.path != "/healthz" and _host(h.get("host")) not in ALLOWED_HOSTS:
        return 421, "Unknown host name. Add it to ALLOWED_HOSTS."
    if request.method not in UNSAFE:
        return None
    try:
        if int(h.get("content-length") or 0) > MAX_BODY:
            return 413, "Request too large"
    except ValueError:
        return 400, "Bad Content-Length"
    if "chunked" in h.get("transfer-encoding", "").lower():
        return 411, "Send a Content-Length"
    if not browser:
        return None
    # Other apps on the same host count as the "same site" for SameSite cookies, so check the origin.
    site = h.get("sec-fetch-site")
    if site and site not in ("same-origin", "none"):
        return 403, "Cross-site request refused"
    origin = h.get("origin")
    if not site and origin and origin != "null":
        expected = h.get("x-forwarded-host") or h.get("host")
        if urlsplit(origin).netloc.lower() != (expected or "").lower():
            return 403, "Cross-site request refused"
    # A form or text/plain POST from elsewhere is a "simple" request; JSON would need a CORS preflight.
    if request.method == "POST" and request.url.path != "/api/logout" \
            and not h.get("content-type", "").startswith("application/json"):
        return 415, "Send JSON"
    return None
