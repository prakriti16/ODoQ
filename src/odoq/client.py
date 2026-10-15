"""Measurement client for DoQ and ODoQ.

Connection modes (what the per-query latency includes):
  warm    one connection opened before the run (handshake logged separately,
          not in per-query latency); queries reuse it
  cold    new connection per query: latency includes the full QUIC handshake
  resume  new connection per query using a TLS session ticket and 0-RTT
          (a priming connection fetches the first ticket, not measured)

For ODoQ the connection is to the proxy; the proxy's own upstream behaviour is
chosen by which proxy port is used (see proxy.py).

Every query writes one JSON line with timestamps (CLOCK_MONOTONIC ns), sizes
at each layer, validation result and join keys (local address + stream id).
Errors are logged with ok=false and counted, never dropped.
"""

import argparse
import asyncio
import json
import random
import secrets
from typing import Optional


from aioquic.quic.configuration import QuicConfiguration

from . import crypto, odoh
from .h2util import client_ssl_context, h2_connect
from .h3util import H3ClientProtocol
from .common import (open_secrets, quic_connect, JsonLog, StreamBufferProtocol, build_query,
                     check_response, frame, now_ns, unframe)


class ClientProtocol(StreamBufferProtocol):
    pass


class Client:
    def __init__(self, a):
        self.a = a
        self.log = JsonLog(a.out, "client")
        self.ticket = None
        self._secrets = open_secrets(a.secrets_log)
        self.pub = None
        if a.protocol == "odoq":
            self.pub = crypto.load_public_key(a.target_pub)
            self.host, self.port, self.name, self.alpn = (
                a.proxy_host, a.proxy_port, a.proxy_name, "odoq")
        elif a.protocol == "odoh":
            self.pub = odoh.load_public(a.target_pub)
            # client connects to the RELAY over H3; relay forwards to target
            self.host, self.port, self.name, self.alpn = (
                a.proxy_host, a.proxy_port, a.proxy_name, "h3")
            self.odoh_path = (f"/dns-query?targethost={a.target_host}"
                              f"&targetport={a.target_port}")
            self.h2_ctx = (client_ssl_context(a.ca, a.secrets_log)
                           if a.transport == "h2" else None)
        else:
            self.host, self.port, self.name, self.alpn = (
                a.target_host, a.target_port, a.target_name, "doq")

    # -- connections -------------------------------------------------------
    def config(self, use_ticket: bool) -> QuicConfiguration:
        c = QuicConfiguration(alpn_protocols=[self.alpn], is_client=True,
                              server_name=self.name, idle_timeout=600.0)
        c.load_verify_locations(self.a.ca)
        if self._secrets:
            c.secrets_log_file = self._secrets
        if use_ticket and self.ticket is not None:
            c.session_ticket = self.ticket
        return c

    def _save_ticket(self, t):
        self.ticket = t

    def open_conn(self, use_ticket=False, wait=True):
        if self.a.protocol == "odoh" and self.a.transport == "h2":
            # TCP + TLS 1.3; no early data in Python ssl, so no 0-RTT
            return h2_connect(self.host, self.port, ssl_ctx=self.h2_ctx,
                              server_name=self.name)
        proto_cls = H3ClientProtocol if self.a.protocol == "odoh" else ClientProtocol
        return quic_connect(self.host, self.port, configuration=self.config(use_ticket),
                       create_protocol=proto_cls,
                       session_ticket_handler=self._save_ticket,
                       wait_connected=wait)

    # -- one query ---------------------------------------------------------
    def make_qname(self, qname: str) -> str:
        if self.a.cache_bust:
            return f"cb{secrets.token_hex(4)}.{qname}"
        return qname

    async def one(self, proto: Optional[ClientProtocol], seq: int, qname: str):
        rec = {"run_id": self.a.run_id, "seq": seq, "protocol": self.a.protocol,
               "mode": self.a.mode, "proxy_port": self.port
               if self.a.protocol == "odoq" else None,
               "qtype": self.a.qtype, "cache_bust": self.a.cache_bust,
               "transport": (self.a.transport if self.a.protocol == "odoh"
                             else "quic"),
               "bytes_layer": ("h2-frames" if self.a.protocol == "odoh"
                               and self.a.transport == "h2" else "udp-payload")}
        cm = None
        t_start = now_ns()
        rec["t_start"] = t_start
        try:
            qn = self.make_qname(qname)
            rec["qname"], rec["base_qname"] = qn, qname
            dns_q = build_query(qn, self.a.qtype, pad_block=self.a.pad_query_block)
            rec["dns_query_bytes"] = len(dns_q)
            if self.a.protocol == "odoq":
                msg, pending, sizes = crypto.client_build(
                    self.pub, dns_q, self.a.target_host, self.a.target_port)
                rec.update(sizes)
                payload = frame(msg)
            elif self.a.protocol == "odoh":
                msg, pending, sizes = odoh.client_encrypt_query(self.pub, dns_q)
                rec.update(sizes)
                payload = msg  # H3 body, no stream framing
            else:
                msg, pending = dns_q, None
                payload = frame(msg)
            rec["req_stream_bytes"] = len(payload)
            rec["t_built"] = now_ns()

            if proto is None:  # cold or resume
                resume = self.a.mode == "resume"
                rec["ticket_available"] = resume and self.ticket is not None
                cm = self.open_conn(use_ticket=resume, wait=not resume)
                proto = await cm.__aenter__()
                rec["t_connected"] = now_ns()
            rec["local"] = proto.local_addr()
            sent0, recv0 = proto.path_bytes()

            info = {}
            rec["t_sent"] = now_ns()
            if self.a.protocol == "odoh":
                status, raw = await asyncio.wait_for(
                    proto.post(self.name, self.odoh_path, payload, info),
                    self.a.timeout)
                rec["http_status"] = status
                if status != 200:
                    raise RuntimeError(f"ODoH relay returned HTTP {status}")
                rec["t_resp"] = now_ns()
                rec["stream_id"] = info.get("stream_id")
                rec["resp_stream_bytes"] = len(raw)
                dns_r = odoh.client_decrypt_response(pending, raw)
            else:
                raw = await asyncio.wait_for(proto.request(payload, info),
                                             self.a.timeout)
                rec["t_resp"] = now_ns()
                rec["stream_id"] = info.get("stream_id")
                rec["resp_stream_bytes"] = len(raw)
                body = unframe(raw)
                dns_r = crypto.client_open(pending, body) if pending else body
            rec.update(check_response(dns_q, dns_r))
            rec["t_done"] = now_ns()
            rec["latency_ns"] = rec["t_done"] - t_start

            sent1, recv1 = proto.path_bytes()
            if sent1 is not None:
                rec["udp_sent_bytes"] = sent1 - (0 if cm else sent0)
                rec["udp_recv_bytes"] = recv1 - (0 if cm else recv0)
            if proto.handshake is not None:
                rec["session_resumed"] = proto.handshake.session_resumed
                rec["early_data_accepted"] = proto.handshake.early_data_accepted
        except Exception as e:  # noqa: BLE001
            rec["ok"] = False
            rec["error"] = f"{type(e).__name__}: {e}"
            rec["t_done"] = now_ns()
        finally:
            if cm is not None:
                # closing (3 x PTO) is outside the timed region
                try:
                    await cm.__aexit__(None, None, None)
                except Exception:
                    pass
        self.log.write("query", **rec)
        return rec.get("ok", False)

    # -- run ---------------------------------------------------------------
    def schedule(self):
        rng = random.Random(self.a.seed)
        domains = list(self.a.qname)
        order = []
        for _ in range(self.a.per_domain):
            rng.shuffle(domains)
            order.extend(domains)
        return order

    async def run(self):
        a = self.a
        order = self.schedule()
        self.log.write("run_start", run_id=a.run_id, args=vars(a), n=len(order))
        ok = 0
        if a.prewarm:
            # one untimed query per domain so the timed run measures cache hits
            async with self.open_conn() as proto:
                for qn in a.qname:
                    q = build_query(qn, a.qtype)
                    if a.protocol == "odoh":
                        m, pend, _ = odoh.client_encrypt_query(self.pub, q)
                        _, raw = await asyncio.wait_for(
                            proto.post(self.name, self.odoh_path, m), a.timeout)
                        odoh.client_decrypt_response(pend, raw)
                    else:
                        if a.protocol == "odoq":
                            m, pend, _ = crypto.client_build(
                                self.pub, q, a.target_host, a.target_port)
                        else:
                            m, pend = q, None
                        raw = await asyncio.wait_for(proto.request(frame(m)), a.timeout)
                        if pend:
                            crypto.client_open(pend, unframe(raw))
            self.log.write("prewarm_done", run_id=a.run_id, n=len(a.qname))
        if a.mode == "warm":
            t0 = now_ns()
            async with self.open_conn() as proto:
                self.log.write("connection", run_id=a.run_id,
                               handshake_ns=now_ns() - t0, local=proto.local_addr())
                for i, qn in enumerate(order):
                    ok += await self.one(proto, i, qn)
                    await asyncio.sleep(a.gap_ms / 1000)
        else:
            if a.mode == "resume":
                async with self.open_conn() as proto:  # priming, not measured
                    await asyncio.sleep(0.05)       # let the ticket arrive
                self.log.write("priming_done", run_id=a.run_id,
                               have_ticket=self.ticket is not None)
            for i, qn in enumerate(order):
                ok += await self.one(None, i, qn)
                await asyncio.sleep(a.gap_ms / 1000)
        self.log.write("run_end", run_id=a.run_id, n=len(order), ok=ok)
        print(json.dumps({"run_id": a.run_id, "n": len(order), "ok": ok}))


def main():
    p = argparse.ArgumentParser(description="DoQ / ODoQ measurement client")
    p.add_argument("--protocol", choices=["doq", "odoq", "odoh"], required=True)
    p.add_argument("--transport", choices=["h3", "h2"], default="h3",
                   help="ODoH only: HTTP/3 over QUIC or HTTP/2 over TLS/TCP")
    p.add_argument("--mode", choices=["warm", "cold", "resume"], required=True)
    p.add_argument("--target-host", required=True)
    p.add_argument("--target-port", type=int, required=True)
    p.add_argument("--target-name", default="resolver.odoq.test")
    p.add_argument("--target-pub", help="ODoQ target RSA public key")
    p.add_argument("--proxy-host")
    p.add_argument("--proxy-port", type=int)
    p.add_argument("--proxy-name", default="proxy.odoq.test")
    p.add_argument("--ca", required=True)
    p.add_argument("--qname", action="append", required=True)
    p.add_argument("--qtype", default="A")
    p.add_argument("--per-domain", type=int, default=10)
    p.add_argument("--gap-ms", type=float, default=50.0)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--cache-bust", action="store_true",
                   help="prefix a random label so every query misses the cache")
    p.add_argument("--pad-query-block", type=int, default=0,
                   help="RFC 7830 padding block for queries (RFC 8467: 128)")
    p.add_argument("--prewarm", action="store_true",
                   help="query each domain once (untimed) before the run")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--run-id", default="adhoc")
    p.add_argument("--out", default=None)
    p.add_argument("--secrets-log", default=None)
    a = p.parse_args()
    if a.protocol in ("odoq", "odoh") and not (a.proxy_host and a.proxy_port
                                               and a.target_pub):
        p.error(f"{a.protocol} needs --proxy-host, --proxy-port and --target-pub")
    if a.protocol == "odoh" and a.transport == "h2" and a.mode == "resume":
        p.error("resume is not supported for ODoH over HTTP/2: Python's ssl has "
                "no TLS early data, so resumption saves no round trips")
    asyncio.run(Client(a).run())


if __name__ == "__main__":
    main()
