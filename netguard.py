"""Where the hub may connect for service checks and agents.

Blocked always: loopback (the hub itself), link-local (incl. cloud metadata at 169.254.169.254),
multicast and reserved ranges. Optionally, CHECK_ALLOWED_NETWORKS limits checks to your own
networks, e.g. "192.168.1.0/24,100.64.0.0/10".
"""
import asyncio
import ipaddress
import os
import socket

BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "100.100.100.200/32",                     # Alibaba Cloud metadata
    "::/128", "::1/128", "fe80::/10", "ff00::/8", "fd00:ec2::/32",  # incl. AWS IPv6 metadata
)]


def _networks(value):
    out = []
    for part in (value or "").split(","):
        if part.strip():
            out.append(ipaddress.ip_network(part.strip(), strict=False))
    return out


ALLOWED = _networks(os.environ.get("CHECK_ALLOWED_NETWORKS", ""))


class Blocked(Exception):
    pass


def check_ip(ip, host, limit_to_allowed=True):
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if any(a in n for n in BLOCKED):
        where = str(a) if host == str(a) else f"{host} ({a})"
        raise Blocked(f"Gaugery won't connect to {where}: loopback, link-local and cloud-metadata addresses are off limits")
    if limit_to_allowed and ALLOWED and not any(a in n for n in ALLOWED):
        raise Blocked(f"{host if host == str(a) else f'{host} ({a})'} is outside CHECK_ALLOWED_NETWORKS")
    return str(a)


async def resolve(host, port=0, limit_to_allowed=True):
    """The addresses `host` resolves to, if every one of them is allowed. Connect to one of these
    (not the name again), so a DNS answer can't change between the check and the connection."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise Blocked(f"Unknown host {host}") from None
        addrs = list(dict.fromkeys(i[4][0] for i in infos))
    return [check_ip(a, host, limit_to_allowed) for a in addrs]
