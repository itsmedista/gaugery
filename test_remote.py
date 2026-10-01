"""Hub reading agent replies. Run: python test_remote.py (inside the monitorr image)."""
import asyncio
import gzip

import httpx

import remote
from remote import AgentError, Remotes


async def reply(content, headers=None):
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=content, headers=headers)))
    async with client.stream("GET", "http://agent/api/info") as r:
        return await Remotes._read_capped(r)


async def main():
    r = await reply(b'{"ok": true}')
    assert r.json() == {"ok": True} and r.status_code == 200
    r = await reply(gzip.compress(b'{"zipped": 1}'), {"content-encoding": "gzip"})
    assert r.json() == {"zipped": 1}, r.content  # decompressed once, not twice
    remote.MAX_REPLY = 1000
    for big in (b"x" * 1001, gzip.compress(b"x" * 100_000)):  # plain and a small zip that unpacks big
        try:
            await reply(big, {"content-encoding": "gzip"} if big[:2] == b"\x1f\x8b" else None)
            raise SystemExit("an oversized reply was accepted")
        except AgentError as e:
            assert "stopped reading" in str(e)
    print("ok")


asyncio.run(main())
