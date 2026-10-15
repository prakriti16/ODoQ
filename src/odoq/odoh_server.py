"""ODoH target and relay over HTTP/3 and HTTP/2 (RFC 9230), for the testbed.

Two roles, selected by --role:

  target  terminates HPKE, resolves via Unbound, returns an encrypted answer.
          Path /dns-query. Shares the async Unbound backend with the DoQ/ODoQ
          resolver frontend.

  relay   forwards the opaque ODoH message to the target over its own H3
          connection and relays the reply. Reads targethost/targetpath from
          query parameters, consistent with RFC 9230, and restricts the target
          to an allowlist. Never sees plaintext (HPKE terminates at the target).

Per-request JSONL fields (CLOCK_MONOTONIC ns): t_recv, and for the target
t_opened/t_backend/t_sealed/t_sent, for the relay t_up_sent/t_up_recv/t_sent.
Join keys mirror the ODoQ pipeline (peer addr + stream id).
"""

import argparse
import asyncio
from urllib.parse import parse_qs, urlparse

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration

from . import odoh
from .backend import Backend
from .common import JsonLog, now_ns, open_secrets, pad_dns, has_padding
from .h2util import client_ssl_context, h2_connect, serve_h2, server_ssl_context
from .h3util import H3ClientProtocol, H3ServerProtocol
from .common import quic_connect


def make_config_server(args, alpn="h3"):
    c = QuicConfiguration(alpn_protocols=[alpn], is_client=False,
                          idle_timeout=args.idle_timeout)
    c.load_cert_chain(args.certificate, args.private_key)
    if args.secrets_log:
        c.secrets_log_file = open_secrets(args.secrets_log)
    return c


class TargetApp:
    def __init__(self, args):
        self.log = JsonLog(args.log, "odoh-target")
        self.backend = Backend(args.backend_host, args.backend_port)
        self.priv = odoh.load_private(args.hpke_key)
        self.pad_block = args.pad_response_block

    async def handle(self, body, headers, t_recv, sid, transport="h3"):
        rec = {"role": "target", "transport": transport, "stream_id": sid,
               "t_recv": t_recv, "req_bytes": len(body)}
        try:
            dns_q, rctx = odoh.target_decrypt_query(self.priv, body)
            rec["t_opened"] = now_ns()
            resp, used = await self.backend.query(dns_q)
            rec["t_backend"] = now_ns()
            rec["backend_transport"] = used
            if self.pad_block and has_padding(dns_q):
                resp = pad_dns(resp, self.pad_block)
            rec["dns_resp_bytes"] = len(resp)
            out = odoh.target_encrypt_response(rctx, resp)
            rec["t_sealed"] = now_ns()
            rec["resp_bytes"] = len(out)
            rec["ok"] = True
            self.log.write("query", **rec)
            return 200, out
        except Exception as e:  # noqa: BLE001
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            self.log.write("query", **rec)
            return 400, b""


class RelayApp:
    """Relay for one transport. Reached over H3, it forwards over H3; reached
    over H2, it forwards over H2, so each ODoH variant uses one transport end
    to end. Each instance keeps one persistent upstream connection."""

    def __init__(self, args, transport="h3", log=None):
        self.log = log or JsonLog(args.log, "odoh-relay")
        self.transport = transport
        self.args = args
        self.allow = {}
        for entry in args.allow:  # host:port=server_name
            hp, name = entry.split("=")
            h, p = hp.rsplit(":", 1)
            self.allow[(h, int(p))] = name
        self._conns = {}
        self._locks = {}
        self._secrets = open_secrets(args.secrets_log)
        self._h2_ctx = (client_ssl_context(args.ca, args.secrets_log)
                        if transport == "h2" else None)

    def _config(self, server_name):
        c = QuicConfiguration(alpn_protocols=["h3"], is_client=True,
                              server_name=server_name,
                              idle_timeout=self.args.idle_timeout)
        c.load_verify_locations(self.args.ca)
        if self._secrets:
            c.secrets_log_file = self._secrets
        return c

    async def _get_conn(self, key):
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            proto = self._conns.get(key)
            if proto is not None and proto.terminated is None:
                return proto
            if self.transport == "h2":
                cm = h2_connect(key[0], key[1], ssl_ctx=self._h2_ctx,
                                server_name=self.allow[key])
            else:
                cm = quic_connect(key[0], key[1],
                                  configuration=self._config(self.allow[key]),
                                  create_protocol=H3ClientProtocol)
            proto = await cm.__aenter__()
            proto._cm = cm
            self._conns[key] = proto
            self.log.write("upstream_open", key=list(key), transport=self.transport)
            return proto

    async def handle(self, body, headers, t_recv, sid):
        rec = {"role": "relay", "transport": self.transport, "stream_id": sid,
               "t_recv": t_recv, "req_bytes": len(body)}
        try:
            path = next((v for k, v in headers if k == b":path"), b"").decode()
            qs = parse_qs(urlparse(path).query)
            host = qs.get("targethost", ["10.77.6.60"])[0]
            port = int(qs.get("targetport", ["8553"])[0])
            key = (host, port)
            if key not in self.allow:
                raise PermissionError(f"target {key} not allowed")
            proto = await self._get_conn(key)
            rec["t_up_sent"] = now_ns()
            info = {}
            status, resp = await proto.post(self.allow[key], "/dns-query", body, info)
            rec["t_up_recv"] = now_ns()
            rec["up_stream_id"] = info.get("stream_id")
            rec["status"] = status
            rec["ok"] = status == 200
            rec["resp_bytes"] = len(resp)
            self.log.write("query", **rec)
            return status, resp
        except Exception as e:  # noqa: BLE001
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            self.log.write("query", **rec)
            return 502, b""


async def run(args):
    """Serve HTTP/3 (UDP) and HTTP/2 (TCP) on the same port number."""
    if args.role == "target":
        app = TargetApp(args)
        await app.backend.start()
        h3_handler = app.handle

        async def h2_handler(body, headers, t_recv, sid):
            return await app.handle(body, headers, t_recv, sid, transport="h2")
        log = app.log
    else:
        h3_app = RelayApp(args, "h3")
        h2_app = RelayApp(args, "h2", log=h3_app.log)
        h3_handler, h2_handler, log = h3_app.handle, h2_app.handle, h3_app.log
    tickets = {}
    await serve(
        args.host, args.port, configuration=make_config_server(args),
        create_protocol=lambda *a, **kw: H3ServerProtocol(*a, handler=h3_handler, **kw),
        session_ticket_fetcher=lambda label, _t=tickets: _t.pop(label, None),
        session_ticket_handler=lambda t, _t=tickets: _t.__setitem__(t.ticket, t),
    )
    await serve_h2(args.host, args.port,
                   server_ssl_context(args.certificate, args.private_key,
                                      args.secrets_log), h2_handler)
    log.write("listening", role=args.role, port=args.port, transports=["h3", "h2"])
    await asyncio.Future()


def main():
    p = argparse.ArgumentParser(description="ODoH target/relay over HTTP/3 and HTTP/2")
    p.add_argument("--role", choices=["target", "relay"], required=True)
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--certificate", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--hpke-key", help="target: HPKE private key (PEM)")
    p.add_argument("--backend-host", default="127.0.0.1")
    p.add_argument("--backend-port", type=int, default=5353)
    p.add_argument("--pad-response-block", type=int, default=468)
    p.add_argument("--ca", help="relay: CA to verify the target")
    p.add_argument("--allow", action="append", default=[],
                   help="relay: HOST:PORT=SERVER_NAME of allowed target")
    p.add_argument("--idle-timeout", type=float, default=600.0)
    p.add_argument("--log", default=None)
    p.add_argument("--secrets-log", default=None)
    args = p.parse_args()
    if args.role == "target" and not args.hpke_key:
        p.error("target needs --hpke-key")
    if args.role == "relay" and not (args.ca and args.allow):
        p.error("relay needs --ca and --allow")
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
