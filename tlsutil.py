"""TLS for Monitorr without a certificate authority.

Each agent makes its own certificate once. The hub learns that certificate's fingerprint from
the pairing code and from then on trusts exactly that certificate, checked during the TLS
handshake, before any token is sent. Nobody in between can read or impersonate the agent.
"""
import asyncio
import base64
import datetime
import hashlib
import ssl
from pathlib import Path

PAIRING_PREFIX = "mtr1"


def ensure_cert(directory, name="monitorr"):
    """Paths of this machine's certificate and key, created on first use (valid 20 years)."""
    d = Path(directory)
    cert, key = d / "tls-cert.pem", d / "tls-key.pem"
    if cert.exists() and key.exists():
        return str(cert), str(key)
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    k = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    ski = x509.SubjectKeyIdentifier.from_public_key(k.public_key())
    c = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=7300))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False, content_commitment=False,
                                      data_encipherment=False, key_agreement=True, key_cert_sign=False,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
         .add_extension(ski, critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ski), critical=False)
         .sign(k, hashes.SHA256()))
    d.mkdir(parents=True, exist_ok=True)
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    key.chmod(0o600)
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return str(cert), str(key)


def fingerprint_der(der):
    return hashlib.sha256(der).digest()


def fingerprint_file(cert_path):
    return fingerprint_der(ssl.PEM_cert_to_DER_cert(Path(cert_path).read_text()))


def _b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def pairing_code(cert_path, token):
    """One string to paste into the hub: the certificate's fingerprint and the agent token."""
    return f"{PAIRING_PREFIX}.{_b64(fingerprint_file(cert_path))}.{token}"


def parse_pairing(code):
    """-> (fingerprint bytes, token) or ValueError."""
    parts = (code or "").strip().split(".", 2)
    if len(parts) != 3 or parts[0] != PAIRING_PREFIX:
        raise ValueError("That isn't a Monitorr pairing code (it starts with mtr1.)")
    fp = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
    if len(fp) != 32 or len(parts[2]) < 24:
        raise ValueError("The pairing code is incomplete. Copy the whole line.")
    return fp, parts[2]


async def fetch_cert(host, port, timeout=6):
    """The certificate a TLS server presents (DER), without trusting it. Only used to compare
    its fingerprint with the pairing code."""
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    _, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=None), timeout)
    try:
        return w.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        w.close()


def pinned_context(cert_pem):
    """A client context that accepts exactly this one certificate (host names don't matter)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=cert_pem)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN  # trust the pinned certificate itself
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx
