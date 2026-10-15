"""Asynchronous client from the resolver frontend to the local Unbound.

Replaces the old blocking `dnslib.DNSRecord.send()` call, which froze the
asyncio event loop for the whole lookup and serialised all queries.

One UDP socket, a random 16-bit ID per in-flight query, TCP fallback when the
response is truncated. The original message ID is restored on the way back.
"""

import asyncio
import os
import struct
from typing import Dict, Tuple


class Backend(asyncio.DatagramProtocol):
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host, self.port, self.timeout = host, port, timeout
        self._pending: Dict[int, asyncio.Future] = {}
        self._transport = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: self, remote_addr=(self.host, self.port))

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) < 2:
            return
        (mid,) = struct.unpack("!H", data[:2])
        fut = self._pending.pop(mid, None)
        if fut is not None and not fut.done():
            fut.set_result(data)

    def error_received(self, exc) -> None:  # ICMP unreachable etc.
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    def _new_id(self) -> int:
        while True:
            mid = struct.unpack("!H", os.urandom(2))[0]
            if mid not in self._pending:
                return mid

    async def query(self, wire: bytes) -> Tuple[bytes, str]:
        """Return (response_wire_with_original_id, transport_used)."""
        orig = wire[:2]
        mid = self._new_id()
        msg = struct.pack("!H", mid) + wire[2:]
        fut = asyncio.get_running_loop().create_future()
        self._pending[mid] = fut
        self._transport.sendto(msg)
        try:
            resp = await asyncio.wait_for(fut, self.timeout)
        finally:
            self._pending.pop(mid, None)
        used = "udp"
        if len(resp) > 2 and resp[2] & 0x02:  # TC bit
            resp = await self._query_tcp(msg)
            used = "tcp"
        return orig + resp[2:], used

    async def _query_tcp(self, msg: bytes) -> bytes:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port), self.timeout)
        try:
            writer.write(struct.pack("!H", len(msg)) + msg)
            await writer.drain()
            (n,) = struct.unpack("!H", await asyncio.wait_for(
                reader.readexactly(2), self.timeout))
            return await asyncio.wait_for(reader.readexactly(n), self.timeout)
        finally:
            writer.close()
