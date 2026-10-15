"""Resolver frontend: DoQ (RFC 9250) and the ODoQ target in one process.

Both protocols share the same backend (local Unbound), the same QUIC stack and
the same TLS certificate, so the only difference between them is the
oblivious layer itself.

Per-query JSONL log fields (all times CLOCK_MONOTONIC ns):
  t_recv      full stream received
  t_opened    ODoQ only: RSA + AES-GCM decryption done
  t_backend   Unbound answered
  t_sealed    response encrypted (ODoQ) / framed (DoQ)
  t_tx        just before transmit() (use for network-hop arithmetic)
  t_sent      after transmit() returned
"""

import argparse
import asyncio
from typing import Dict, Optional

from aioquic.asyncio import serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.tls import SessionTicket

from . import crypto
from .backend import Backend
from .common import (open_secrets, JsonLog, StreamBufferProtocol, frame, has_padding,
                     now_ns, pad_dns, unframe)


class TicketStore:
    def __init__(self):
        self.tickets: Dict[bytes, SessionTicket] = {}

    def add(self, t: SessionTicket) -> None:
        self.tickets[t.ticket] = t

    def pop(self, label: bytes) -> Optional[SessionTicket]:
        return self.tickets.pop(label, None)


class FrontendProtocol(StreamBufferProtocol):
    def __init__(self, *args, kind, app, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = kind  # "doq" or "odoq"
        self.app = app

    def on_stream_complete(self, stream_id, data, t_ns):
        asyncio.ensure_future(self._handle(stream_id, data, t_ns))

    async def _handle(self, sid, data, t_recv):
        app, rec = self.app, {"proto": self.kind, "stream_id": sid,
                              "peer": self.peer_addr(), "t_recv": t_recv,
                              "req_stream_bytes": len(data)}
        try:
            msg = unframe(data)
            if self.kind == "odoq":
                dns_q, k_r, nonce = crypto.target_open(app.priv, msg)
                rec["t_opened"] = now_ns()
            else:
                dns_q = msg
            resp, used = await app.backend.query(dns_q)
            rec["t_backend"] = now_ns()
            rec["backend_transport"] = used
            # RFC 8467: pad responses only when the query was padded
            if app.pad_block and has_padding(dns_q):
                resp = pad_dns(resp, app.pad_block)
            rec["dns_resp_bytes"] = len(resp)
            if self.kind == "odoq":
                out = frame(crypto.target_seal(k_r, nonce, resp))
            else:
                out = frame(resp)
            rec["t_sealed"] = now_ns()
            self._quic.send_stream_data(sid, out, end_stream=True)
            rec["t_tx"] = now_ns()   # just before the datagram is sent
            self.transmit()
            rec["t_sent"] = now_ns()  # after transmit() returned
            rec["resp_stream_bytes"] = len(out)
            rec["ok"] = True
        except Exception as e:  # noqa: BLE001 - logged, stream reset
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            try:
                self._quic.reset_stream(sid, 0x2)  # DOQ_INTERNAL_ERROR
                self.transmit()
            except Exception:
                pass
        app.log.write("query", **rec)


class App:
    def __init__(self, args):
        self.log = JsonLog(args.log, "resolver")
        self.backend = Backend(args.backend_host, args.backend_port)
        self.priv = crypto.load_private_key(args.target_key)
        self.pad_block = args.pad_response_block
        self.args = args

    def config(self, alpn: str) -> QuicConfiguration:
        c = QuicConfiguration(alpn_protocols=[alpn], is_client=False,
                              idle_timeout=self.args.idle_timeout)
        c.load_cert_chain(self.args.certificate, self.args.private_key)
        if self.args.secrets_log:
            c.secrets_log_file = open_secrets(self.args.secrets_log)
        return c

    async def run(self):
        await self.backend.start()
        for kind, port, alpn in (("doq", self.args.doq_port, "doq"),
                                 ("odoq", self.args.odoq_port, "odoq")):
            store = TicketStore()
            await serve(
                self.args.host, port, configuration=self.config(alpn),
                create_protocol=lambda *a, _k=kind, **kw: FrontendProtocol(
                    *a, kind=_k, app=self, **kw),
                session_ticket_fetcher=store.pop,
                session_ticket_handler=store.add,
            )
            self.log.write("listening", proto=kind, port=port, alpn=alpn)
        await asyncio.Future()


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--doq-port", type=int, default=853)
    p.add_argument("--odoq-port", type=int, default=8853)
    p.add_argument("--certificate", required=True)
    p.add_argument("--private-key", required=True, help="TLS key")
    p.add_argument("--target-key", required=True,
                   help="dedicated ODoQ RSA private key (not the TLS key)")
    p.add_argument("--backend-host", default="127.0.0.1")
    p.add_argument("--backend-port", type=int, default=5353)
    p.add_argument("--pad-response-block", type=int, default=468,
                   help="RFC 7830 block for responses, applied only when the "
                        "query was padded (RFC 8467 policy); 0 disables")
    p.add_argument("--idle-timeout", type=float, default=600.0)
    p.add_argument("--log", default=None)
    p.add_argument("--secrets-log", default=None)
    args = p.parse_args()
    try:
        asyncio.run(App(args).run())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
