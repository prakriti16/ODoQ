"""ODoQ proxy.

Listens on one port per upstream connection mode, so a campaign can compare
modes without restarting anything:

  persistent  one long-lived QUIC connection per upstream, reused for every
              query (what the paper claims ODoQ does)
  per-query   new upstream connection per query, response relayed as soon as
              it arrives, connection closed in the background
  legacy      reproduces the ORIGINAL code: new connection per query inside
              `async with connect()`, so the reply is relayed only after
              aioquic's closing period (3 x PTO) has elapsed

Destinations are restricted to an allowlist (the old proxy was an open relay:
it forwarded to any host:port the client named).

Per-query log fields (CLOCK_MONOTONIC ns): t_recv, t_split, t_up_conn_start /
t_up_conn_done (only when a connection was opened for this query), t_up_sent,
t_up_recv, t_tx (just before transmit), t_sent. `up_local` + `up_stream_id` join with the resolver log;
`peer` + `stream_id` join with the client log.
"""

import argparse
import asyncio
from typing import Dict, Tuple

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

from . import crypto
from .common import open_secrets, quic_connect, JsonLog, StreamBufferProtocol, frame, now_ns, unframe

MODES = ("persistent", "per-query", "legacy")


class UpstreamProtocol(StreamBufferProtocol):
    pass


class Upstreams:
    def __init__(self, args, log: JsonLog):
        self.args, self.log = args, log
        self.allow: Dict[Tuple[str, int], str] = {}
        for entry in args.allow:
            hp, name = entry.split("=")
            h, port = hp.rsplit(":", 1)
            self.allow[(h, int(port))] = name
        self._persistent: Dict[Tuple[str, int], StreamBufferProtocol] = {}
        self._locks: Dict[Tuple[str, int], asyncio.Lock] = {}
        self._secrets = (open_secrets(args.secrets_log)
                         if args.secrets_log else None)

    def config(self, server_name: str) -> QuicConfiguration:
        c = QuicConfiguration(alpn_protocols=["odoq"], is_client=True,
                              server_name=server_name,
                              idle_timeout=self.args.idle_timeout)
        c.load_verify_locations(self.args.ca)
        if self._secrets:
            c.secrets_log_file = self._secrets
        return c

    def _connect(self, key):
        return quic_connect(key[0], key[1], configuration=self.config(self.allow[key]),
                       create_protocol=UpstreamProtocol)

    async def _open(self, key, rec):
        rec["t_up_conn_start"] = now_ns()
        cm = self._connect(key)
        proto = await cm.__aenter__()
        rec["t_up_conn_done"] = now_ns()
        return cm, proto

    async def forward(self, mode, key, msg, rec) -> bytes:
        if key not in self.allow:
            raise PermissionError(f"destination {key} not in allowlist")
        info = {}
        if mode == "persistent":
            lock = self._locks.setdefault(key, asyncio.Lock())
            async with lock:
                proto = self._persistent.get(key)
                if proto is None or proto.terminated is not None:
                    cm, proto = await self._open(key, rec)
                    proto._cm = cm  # keep context manager alive
                    self._persistent[key] = proto
                    self.log.write("upstream_open", key=list(key),
                                   up_local=proto.local_addr(),
                                   handshake_ns=rec["t_up_conn_done"]
                                   - rec["t_up_conn_start"])
            rec["up_local"] = proto.local_addr()
            rec["t_up_sent"] = now_ns()
            resp = await proto.request(frame(msg), info)
        elif mode == "per-query":
            cm, proto = await self._open(key, rec)
            rec["up_local"] = proto.local_addr()
            rec["t_up_sent"] = now_ns()
            try:
                resp = await proto.request(frame(msg), info)
            finally:
                asyncio.ensure_future(cm.__aexit__(None, None, None))
        elif mode == "legacy":
            rec["t_up_conn_start"] = now_ns()
            async with self._connect(key) as proto:
                rec["t_up_conn_done"] = now_ns()
                rec["up_local"] = proto.local_addr()
                rec["t_up_sent"] = now_ns()
                resp = await proto.request(frame(msg), info)
                rec["t_up_recv_before_close"] = now_ns()
            # exiting the block waited for the closing period, as the old code did
        else:
            raise ValueError(mode)
        rec["t_up_recv"] = now_ns()
        rec["up_stream_id"] = info.get("stream_id")
        return resp


class ProxyProtocol(StreamBufferProtocol):
    def __init__(self, *args, mode, upstreams, log, **kwargs):
        super().__init__(*args, **kwargs)
        self.mode, self.upstreams, self.log = mode, upstreams, log

    def on_stream_complete(self, sid, data, t_ns):
        asyncio.ensure_future(self._handle(sid, data, t_ns))

    async def _handle(self, sid, data, t_recv):
        rec = {"mode": self.mode, "peer": self.peer_addr(), "stream_id": sid,
               "t_recv": t_recv, "req_stream_bytes": len(data)}
        try:
            host, port, to_target = crypto.proxy_split(unframe(data))
            rec["t_split"] = now_ns()
            rec["up_key"] = [host, port]
            resp = await self.upstreams.forward(self.mode, (host, port),
                                                to_target, rec)
            # resp is already framed by the target; relay bytes unchanged
            self._quic.send_stream_data(sid, resp, end_stream=True)
            rec["t_tx"] = now_ns()
            self.transmit()
            rec["t_sent"] = now_ns()
            rec["resp_stream_bytes"] = len(resp)
            rec["ok"] = True
        except Exception as e:  # noqa: BLE001
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                self._quic.reset_stream(sid, 0x2)
                self.transmit()
            except Exception:
                pass
        self.log.write("query", **rec)


async def run(args):
    log = JsonLog(args.log, "proxy")
    upstreams = Upstreams(args, log)
    for entry in args.listen:
        port_s, mode = entry.split(":")
        if mode not in MODES:
            raise SystemExit(f"unknown mode {mode}; choose from {MODES}")
        c = QuicConfiguration(alpn_protocols=["odoq"], is_client=False,
                              idle_timeout=args.idle_timeout)
        c.load_cert_chain(args.certificate, args.private_key)
        if args.secrets_log:
            c.secrets_log_file = open_secrets(args.secrets_log)
        tickets = {}
        await serve(
            args.host, int(port_s), configuration=c,
            create_protocol=lambda *a, _m=mode, **kw: ProxyProtocol(
                *a, mode=_m, upstreams=upstreams, log=log, **kw),
            session_ticket_fetcher=lambda label, _t=tickets: _t.pop(label, None),
            session_ticket_handler=lambda t, _t=tickets: _t.__setitem__(t.ticket, t),
        )
        log.write("listening", port=int(port_s), mode=mode)
    await asyncio.Future()


def main():
    p = argparse.ArgumentParser(description="ODoQ proxy")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--listen", action="append", required=True,
                   help="PORT:MODE, repeatable; MODE in " + ",".join(MODES))
    p.add_argument("--allow", action="append", required=True,
                   help="HOST:PORT=TLS_SERVER_NAME of an allowed target")
    p.add_argument("--certificate", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--ca", required=True, help="CA used to verify targets")
    p.add_argument("--idle-timeout", type=float, default=600.0)
    p.add_argument("--log", default=None)
    p.add_argument("--secrets-log", default=None)
    args = p.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
