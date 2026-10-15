"""ODoQ message format and cryptography (stage 1).

Same construction as the paper (RSA-OAEP key transport + AES-GCM), with the
fixes from the code review:

* The target's RSA key is a dedicated key, NOT the TLS private key.
* The query and response keys are both AES-128 (the old code mixed AES-256
  for the query with AES-128 for the response).
* The nonce is 16 random bytes, not a millisecond timestamp (which collided,
  was predictable, and leaked the client clock to the resolver).
* AES-GCM uses associated data that binds the message type and version, so
  a query ciphertext cannot be replayed as a response or vice versa.

Wire formats (every stream message is additionally framed with the RFC 9250
2-byte length prefix by the transport code):

  client -> proxy:   ver(1) | host_len(1) | host | port(2) | target_msg_body
  proxy  -> target:  ver(1) | target_msg_body
  target_msg_body:   ek_len(2) | RSA-OAEP(k_q) | iv(12) | AES-GCM(k_q, P_q) | tag(16)
  P_q:               k_r(16) | nonce(16) | dns_query
  target -> client:  iv(12) | AES-GCM(k_r, nonce | dns_response) | tag(16)

The proxy sees only host/port and opaque bytes. Field sizes are fixed so the
overhead over DoQ can be stated exactly in the paper:
  request overhead  = 1 + 1 + len(host) + 2 + 2 + |RSA| + 12 + 16 + 16 + 16
  response overhead = 12 + 16 + 16
"""

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = 1
KEY_LEN = 16     # AES-128
NONCE_LEN = 16
IV_LEN = 12
TAG_LEN = 16
AAD_QUERY = b"odoq/v1/query"
AAD_RESPONSE = b"odoq/v1/response"

_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)


def load_public_key(path: str) -> rsa.RSAPublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path: str) -> rsa.RSAPrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    iv = os.urandom(IV_LEN)
    return iv + AESGCM(key).encrypt(iv, plaintext, aad)  # ct || tag


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:IV_LEN], blob[IV_LEN:], aad)


@dataclass
class PendingQuery:
    """Client-side state needed to open the matching response."""
    response_key: bytes
    nonce: bytes


# ----------------------------- client side --------------------------------

def client_build(pub: rsa.RSAPublicKey, dns_query: bytes, host: str, port: int):
    """Return (message_to_proxy, PendingQuery, sizes_dict)."""
    k_q = os.urandom(KEY_LEN)
    k_r = os.urandom(KEY_LEN)
    nonce = os.urandom(NONCE_LEN)
    ek = pub.encrypt(k_q, _OAEP)
    ct = _seal(k_q, k_r + nonce + dns_query, AAD_QUERY)
    body = struct.pack("!H", len(ek)) + ek + ct
    hb = host.encode()
    if len(hb) > 255:
        raise ValueError("host too long")
    msg = struct.pack("!BB", VERSION, len(hb)) + hb + struct.pack("!H", port) + body
    sizes = {"rsa_ct_bytes": len(ek), "routing_bytes": 1 + 1 + len(hb) + 2,
             "target_body_bytes": len(body)}
    return msg, PendingQuery(k_r, nonce), sizes


def client_open(pending: PendingQuery, response: bytes) -> bytes:
    """Decrypt and nonce-check a response. Raises on any mismatch."""
    pt = _open(pending.response_key, response, AAD_RESPONSE)
    if pt[:NONCE_LEN] != pending.nonce:
        raise ValueError("nonce mismatch")
    return pt[NONCE_LEN:]


# ----------------------------- proxy side ---------------------------------

def proxy_split(msg: bytes):
    """Return (host, port, message_to_target). Never touches the ciphertext."""
    if len(msg) < 4 or msg[0] != VERSION:
        raise ValueError("bad version or short message")
    hl = msg[1]
    host = msg[2:2 + hl].decode()
    (port,) = struct.unpack("!H", msg[2 + hl:4 + hl])
    return host, port, bytes([VERSION]) + msg[4 + hl:]


# ----------------------------- target side --------------------------------

def target_open(priv: rsa.RSAPrivateKey, msg: bytes):
    """Return (dns_query, response_key, nonce)."""
    if not msg or msg[0] != VERSION:
        raise ValueError("bad version")
    (ek_len,) = struct.unpack("!H", msg[1:3])
    ek = msg[3:3 + ek_len]
    k_q = priv.decrypt(ek, _OAEP)
    pt = _open(k_q, msg[3 + ek_len:], AAD_QUERY)
    k_r = pt[:KEY_LEN]
    nonce = pt[KEY_LEN:KEY_LEN + NONCE_LEN]
    return pt[KEY_LEN + NONCE_LEN:], k_r, nonce


def target_seal(response_key: bytes, nonce: bytes, dns_response: bytes) -> bytes:
    return _seal(response_key, nonce + dns_response, AAD_RESPONSE)
