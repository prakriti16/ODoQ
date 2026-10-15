"""Minimal HTTP/2 over TLS 1.3 / TCP for ODoH (RFC 9230's standard transport).

Same interface as h3util so the ODoH relay, target and client are transport
agnostic:
  client:  async with h2_connect(...) as c: status, body = await c.post(...)
           c.terminated, c.local_addr(), c.path_bytes(), c.handshake (None)
  server:  await serve_h2(host, port, ssl_ctx, handler)
           handler(body, headers, t_recv, stream_id) -> (status, resp_body)

Notes for the paper:
* TLS 1.3, ALPN "h2". asyncio enables TCP_NODELAY on TCP transports, so small
  HTTP/2 frames are not held back by Nagle.
* Python's ssl module has no TLS early data, so there is no 0-RTT for HTTP/2.
  TLS 1.3 resumption without early data saves no round trips, so the "resume"
  connection mode is not run for odoh-h2.
* path_bytes() counts HTTP/2 frame bytes (TLS plaintext), not TCP/TLS wire
  bytes; use the pcaps for on-wire size comparisons with QUIC.
"""

import asyncio
import contextlib
import ssl
from typing import Dict, Optional

import h2.config
import h2.connection
import h2.events

from .common import now_ns

CONTENT_TYPE = b"application/oblivious-dns-message"


def client_ssl_context(ca: str, keylog: Optional[str] = None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2"])
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


def server_ssl_context(cert: str, key: str,
                       keylog: Optional[str] = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])
    if keylog:
        ctx.keylog_filename = keylog
    return ctx


class H2Client:
    """One HTTP/2 connection; concurrent POSTs on separate streams."""

    def __init__(self, reader, writer):
        self._r, self._w = reader, writer
        self._conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding=None))
        self._bufs: Dict[int, bytearray] = {}
        self._status: Dict[int, int] = {}
        self._waiters: Dict[int, asyncio.Future] = {}
        self.terminated = None
        self.handshake = None          # no QUIC-style handshake event over TCP
        self.bytes_sent = 0
        self.bytes_recv = 0
        self._conn.initiate_connection()
        self._flush()
        self._task = asyncio.ensure_future(self._read_loop())

    def _flush(self) -> None:
        data = self._conn.data_to_send()
        if data:
            self.bytes_sent += len(data)
            self._w.write(data)

    def _fail_all(self, exc: Exception) -> None:
        for fut in self._waiters.values():
            if not fut.done():
                fut.set_exception(exc)
        self._waiters.clear()

    async def _read_loop(self) -> None:
        reason = "connection closed"
        try:
            while True:
                data = await self._r.read(65536)
                if not data:
                    break
                self.bytes_recv += len(data)
                for ev in self._conn.receive_data(data):
                    self._event(ev)
                self._flush()
        except asyncio.CancelledError:
            reason = "cancelled"
        except Exception as e:  # noqa: BLE001
            reason = f"{type(e).__name__}: {e}"
        finally:
            if self.terminated is None:
                self.terminated = reason
            self._fail_all(ConnectionError(f"h2 connection ended: {reason}"))

    def _event(self, ev) -> None:
        if isinstance(ev, h2.events.ResponseReceived):
            for k, v in ev.headers:
                if k == b":status":
                    self._status[ev.stream_id] = int(v)
            self._bufs.setdefault(ev.stream_id, bytearray())
        elif isinstance(ev, h2.events.DataReceived):
            self._bufs.setdefault(ev.stream_id, bytearray()).extend(ev.data)
            self._conn.acknowledge_received_data(ev.flow_controlled_length,
                                                 ev.stream_id)
        elif isinstance(ev, h2.events.StreamEnded):
            fut = self._waiters.pop(ev.stream_id, None)
            if fut is not None and not fut.done():
                fut.set_result((self._status.pop(ev.stream_id, 0),
                                bytes(self._bufs.pop(ev.stream_id, b""))))
        elif isinstance(ev, h2.events.StreamReset):
            fut = self._waiters.pop(ev.stream_id, None)
            if fut is not None and not fut.done():
                fut.set_exception(ConnectionError(f"stream reset {ev.error_code}"))
        elif isinstance(ev, h2.events.ConnectionTerminated):
            self.terminated = f"GOAWAY {ev.error_code}"

    async def post(self, authority: str, path: str, body: bytes,
                   info: Optional[dict] = None):
        if self.terminated is not None:
            raise ConnectionError(f"h2 connection ended: {self.terminated}")
        sid = self._conn.get_next_available_stream_id()
        if info is not None:
            info["stream_id"] = sid
        fut = asyncio.get_running_loop().create_future()
        self._waiters[sid] = fut
        self._conn.send_headers(sid, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", authority.encode()), (b":path", path.encode()),
            (b"content-type", CONTENT_TYPE),
            (b"content-length", str(len(body)).encode()),
            (b"accept", CONTENT_TYPE),
        ], end_stream=False)
        self._conn.send_data(sid, body, end_stream=True)
        self._flush()
        return await fut

    def local_addr(self):
        return self._w.get_extra_info("sockname")

    def path_bytes(self):
        return self.bytes_sent, self.bytes_recv

    async def close(self) -> None:
        with contextlib.suppress(Exception):
            self._conn.close_connection()
            self._flush()
        self._task.cancel()
        self._w.close()
        with contextlib.suppress(Exception):
            await self._w.wait_closed()


@contextlib.asynccontextmanager
async def h2_connect(host: str, port: int, *, ssl_ctx: ssl.SSLContext,
                     server_name: str):
    reader, writer = await asyncio.open_connection(
        host, port, ssl=ssl_ctx, server_hostname=server_name)
    alpn = writer.get_extra_info("ssl_object").selected_alpn_protocol()
    if alpn != "h2":
        writer.close()
        raise ConnectionError(f"ALPN negotiated {alpn!r}, expected 'h2'")
    client = H2Client(reader, writer)
    try:
        yield client
    finally:
        await client.close()


async def serve_h2(host: str, port: int, ssl_ctx: ssl.SSLContext, handler):
    """Start an HTTP/2 server; each finished request goes to handler()."""

    async def on_conn(reader, writer):
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False, header_encoding=None))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        bufs: Dict[int, bytearray] = {}
        hdrs: Dict[int, list] = {}

        async def respond(sid, body, headers, t_recv):
            try:
                status, resp = await handler(body, headers, t_recv, sid)
            except Exception:  # noqa: BLE001
                status, resp = 500, b""
            try:
                conn.send_headers(sid, [
                    (b":status", str(status).encode()),
                    (b"content-type", CONTENT_TYPE),
                    (b"content-length", str(len(resp)).encode()),
                ], end_stream=False)
                conn.send_data(sid, resp, end_stream=True)
                writer.write(conn.data_to_send())
            except Exception:  # noqa: BLE001 - client went away
                pass

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        hdrs[ev.stream_id] = ev.headers
                        bufs[ev.stream_id] = bytearray()
                    elif isinstance(ev, h2.events.DataReceived):
                        bufs.setdefault(ev.stream_id, bytearray()).extend(ev.data)
                        conn.acknowledge_received_data(ev.flow_controlled_length,
                                                       ev.stream_id)
                    elif isinstance(ev, h2.events.StreamEnded):
                        t_recv = now_ns()
                        asyncio.ensure_future(respond(
                            ev.stream_id, bytes(bufs.pop(ev.stream_id, b"")),
                            hdrs.pop(ev.stream_id, []), t_recv))
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return
                out = conn.data_to_send()
                if out:
                    writer.write(out)
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
            pass
        finally:
            writer.close()

    return await asyncio.start_server(on_conn, host, port, ssl=ssl_ctx)
