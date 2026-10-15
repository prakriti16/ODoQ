"""Minimal HTTP/3 request/response plumbing for ODoH (RFC 9230 over H3).

ODoH uses POST with content-type application/oblivious-dns-message. We need
only: a client that sends one POST and awaits the full body, and a server that
dispatches a POST body to a handler and replies. Both buffer each H3 stream
until it ends, matching the stream-buffering we use for raw QUIC.

Built on aioquic.h3; kept deliberately small so timing is dominated by the
protocol under test, not an HTTP framework.
"""

import asyncio
from typing import Awaitable, Callable, Dict, Optional

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived, H3Event
from aioquic.quic.events import ConnectionTerminated, QuicEvent

from .common import now_ns

CONTENT_TYPE = b"application/oblivious-dns-message"


class H3ClientProtocol(QuicConnectionProtocol):
    """Sends POSTs, returns the full response body for each."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._bufs: Dict[int, bytearray] = {}
        self._status: Dict[int, int] = {}
        self._waiters: Dict[int, asyncio.Future] = {}
        self.terminated = None
        self.handshake = None

    def local_addr(self):
        try:
            return self._transport.get_extra_info("sockname")
        except AttributeError:
            return None

    def path_bytes(self):
        try:
            p = self._quic._network_paths[0]
            return p.bytes_sent, p.bytes_received
        except (AttributeError, IndexError):
            return None, None

    async def post(self, authority: str, path: str, body: bytes,
                   info: Optional[dict] = None):
        """Return (status, body_bytes). info['stream_id'] is set if given."""
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        h3 = self._h3
        sid = self._quic.get_next_available_stream_id()
        if info is not None:
            info["stream_id"] = sid
        h3.send_headers(sid, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
            (b"content-type", CONTENT_TYPE),
            (b"content-length", str(len(body)).encode()),
            (b"accept", CONTENT_TYPE),
        ], end_stream=False)
        h3.send_data(sid, body, end_stream=True)
        fut = self._loop.create_future()
        self._waiters[sid] = fut
        self.transmit()
        return await fut

    def quic_event_received(self, event: QuicEvent) -> None:
        # H3Connection must see every QUIC event from the start (control and
        # QPACK streams are set up during the handshake); creating it lazily in
        # post() would drop those and break later requests.
        from aioquic.quic.events import HandshakeCompleted
        if isinstance(event, HandshakeCompleted):
            self.handshake = event
        if isinstance(event, ConnectionTerminated):
            self.terminated = event
            err = ConnectionError(f"connection terminated: {event.reason_phrase}")
            for fut in self._waiters.values():
                if not fut.done():
                    fut.set_exception(err)
            self._waiters.clear()
            return
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for e in self._h3.handle_event(event):
            self._h3_event(e)

    def _h3_event(self, e: H3Event) -> None:
        if isinstance(e, HeadersReceived):
            for k, v in e.headers:
                if k == b":status":
                    self._status[e.stream_id] = int(v)
            self._bufs.setdefault(e.stream_id, bytearray())
            if e.stream_ended:
                self._finish(e.stream_id)
        elif isinstance(e, DataReceived):
            self._bufs.setdefault(e.stream_id, bytearray()).extend(e.data)
            if e.stream_ended:
                self._finish(e.stream_id)

    def _finish(self, sid: int) -> None:
        fut = self._waiters.pop(sid, None)
        if fut and not fut.done():
            fut.set_result((self._status.get(sid, 0),
                            bytes(self._bufs.pop(sid, b""))))


Handler = Callable[[bytes], Awaitable[tuple]]  # body -> (status, resp_body)


class H3ServerProtocol(QuicConnectionProtocol):
    """Dispatches each POST body to `handler`, replies with its result.

    handler(body) -> (status:int, resp_body:bytes). Set via the factory in
    serve_h3 below. t_recv (full request body received) is passed to the
    handler-wrapper through on_request for logging if needed.
    """

    def __init__(self, *args, handler: Handler = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = handler
        self._h3: Optional[H3Connection] = None
        self._bufs: Dict[int, bytearray] = {}
        self._hdrs: Dict[int, list] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for e in self._h3.handle_event(event):
            if isinstance(e, HeadersReceived):
                self._hdrs[e.stream_id] = e.headers
                self._bufs.setdefault(e.stream_id, bytearray())
                if e.stream_ended:
                    self._dispatch(e.stream_id)
            elif isinstance(e, DataReceived):
                self._bufs.setdefault(e.stream_id, bytearray()).extend(e.data)
                if e.stream_ended:
                    self._dispatch(e.stream_id)

    def _dispatch(self, sid: int) -> None:
        body = bytes(self._bufs.pop(sid, b""))
        headers = self._hdrs.pop(sid, [])
        t_recv = now_ns()
        asyncio.ensure_future(self._run(sid, body, headers, t_recv))

    async def _run(self, sid: int, body: bytes, headers: list, t_recv: int) -> None:
        try:
            status, resp = await self.handler(body, headers, t_recv, sid)
        except Exception:  # noqa: BLE001
            status, resp = 500, b""
        self._h3.send_headers(sid, [
            (b":status", str(status).encode()),
            (b"content-type", CONTENT_TYPE),
            (b"content-length", str(len(resp)).encode()),
        ], end_stream=False)
        self._h3.send_data(sid, resp, end_stream=True)
        self.transmit()
