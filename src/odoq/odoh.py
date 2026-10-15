"""ODoH (RFC 9230) message encoding, HPKE per RFC 9180.

Suite: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM, the mandatory
ODoH suite. This is deliberately the same AEAD (AES-128-GCM) as the ODoQ
implementation, so a size/latency comparison between ODoH and ODoQ reflects
the key-transport choice (HPKE's 65-byte encapsulated key vs RSA-OAEP's
256-byte ciphertext), not a different symmetric cipher.

RFC 9230 message formats:
  ObliviousDoHMessage = msg_type(1) | key_id_len(2) | key_id | enc_msg
  Query:    the client HPKE-seals (query | padding) to the target's public key.
  Response: the target derives a fresh AEAD key from the HPKE context's
            exporter secret and seals (response | padding). The client holds
            the same context, so it derives the same key. No second public-key
            operation and no key material on the wire for the response.

We encode the target config as a raw uncompressed P-256 point (65 bytes); a
real deployment wraps this in an ObliviousDoHConfig, which does not change the
measured sizes materially and is not needed for a controlled testbed.
"""

import os
import struct

import hpke
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SUITE = hpke.Suite__DHKEM_P256_HKDF_SHA256__HKDF_SHA256__AES_128_GCM
KEM = SUITE.KEM
MSG_TYPE_QUERY = 0x01
MSG_TYPE_RESPONSE = 0x02
INFO_QUERY = b"odoh query"          # HPKE info string
EXPORT_LABEL = b"odoh response"     # exporter context for the response key
AEAD_KEY_LEN = 16
AEAD_NONCE_LEN = 12
KEY_ID = b"\x00"                    # single config in the testbed


def generate_keypair():
    sk = KEM.generate_private_key()
    return sk, sk.public_key()


def save_public(pub, path: str) -> None:
    with open(path, "wb") as f:
        f.write(KEM._encode_public_key(pub))


def load_public(path: str):
    with open(path, "rb") as f:
        return KEM.decode_public_key(f.read())


def save_private(priv, path: str) -> None:
    from cryptography.hazmat.primitives import serialization
    with open(path, "wb") as f:
        f.write(priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))


def load_private(path: str):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _wrap(msg_type: int, enc_msg: bytes) -> bytes:
    return struct.pack("!BH", msg_type, len(KEY_ID)) + KEY_ID + enc_msg


def _unwrap(blob: bytes):
    msg_type = blob[0]
    (kid_len,) = struct.unpack("!H", blob[1:3])
    return msg_type, blob[3 + kid_len:]


# ----------------------------- client -------------------------------------

class PendingQuery:
    """Holds the HPKE send context so the response can be opened."""
    __slots__ = ("context",)

    def __init__(self, context):
        self.context = context


def client_encrypt_query(pub, dns_query: bytes):
    """Return (odoh_message_bytes, PendingQuery, sizes)."""
    enc, ctx = SUITE.setup_send(pub, info=INFO_QUERY)
    ct = ctx.aead.seal(b"", dns_query)
    enc_msg = struct.pack("!H", len(enc)) + enc + ct
    sizes = {"hpke_enc_bytes": len(enc), "hpke_ct_bytes": len(ct)}
    return _wrap(MSG_TYPE_QUERY, enc_msg), PendingQuery(ctx), sizes


def client_decrypt_response(pending: PendingQuery, odoh_response: bytes) -> bytes:
    msg_type, enc_msg = _unwrap(odoh_response)
    if msg_type != MSG_TYPE_RESPONSE:
        raise ValueError("not an ODoH response")
    key = pending.context.export(EXPORT_LABEL, AEAD_KEY_LEN)
    nonce = enc_msg[:AEAD_NONCE_LEN]
    return AESGCM(key).decrypt(nonce, enc_msg[AEAD_NONCE_LEN:], b"")


# ----------------------------- target -------------------------------------

def target_decrypt_query(priv, odoh_message: bytes):
    """Return (dns_query, send_context_handle_for_response)."""
    msg_type, enc_msg = _unwrap(odoh_message)
    if msg_type != MSG_TYPE_QUERY:
        raise ValueError("not an ODoH query")
    (enc_len,) = struct.unpack("!H", enc_msg[:2])
    enc = enc_msg[2:2 + enc_len]
    ct = enc_msg[2 + enc_len:]
    ctx = SUITE.setup_recv(enc, priv, info=INFO_QUERY)
    dns_query = ctx.aead.open(b"", ct)
    return dns_query, ctx


def target_encrypt_response(recv_context, dns_response: bytes) -> bytes:
    key = recv_context.export(EXPORT_LABEL, AEAD_KEY_LEN)
    nonce = os.urandom(AEAD_NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, dns_response, b"")
    return _wrap(MSG_TYPE_RESPONSE, nonce + ct)


# ----------------------------- self-test ----------------------------------

def _selftest():
    sk, pk = generate_keypair()
    query = b"\x00\x00\x01\x00\x00\x01" + b"\x06google\x03com\x00\x00\x01\x00\x01"
    msg, pending, sizes = client_encrypt_query(pk, query)
    dns_q, rctx = target_decrypt_query(sk, msg)
    assert dns_q == query, "query round-trip failed"
    response = query + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22"
    enc_resp = target_encrypt_response(rctx, response)
    out = client_decrypt_response(pending, enc_resp)
    assert out == response, "response round-trip failed"
    req_overhead = len(msg) - len(query)
    resp_overhead = len(enc_resp) - len(response)
    print("ODoH self-test OK")
    print(f"  HPKE enc (encapsulated key): {sizes['hpke_enc_bytes']} B")
    print(f"  request  overhead vs raw DNS: {req_overhead} B")
    print(f"  response overhead vs raw DNS: {resp_overhead} B")
    print("  (compare ODoQ request overhead ~332 B with RSA-2048)")


if __name__ == "__main__":
    _selftest()
