#!/usr/bin/env bash
# Generate the testbed PKI. Run once on the host: scripts/gen_certs.sh
#   - ca.pem/ca.key           private CA trusted by client and proxy
#   - proxy.{pem,key}         TLS cert for proxy.odoq.test    (ECDSA P-256)
#   - resolver.{pem,key}      TLS cert for resolver.odoq.test (ECDSA P-256)
#   - target_key.pem/_pub.pem dedicated ODoQ RSA key (separate from any TLS key)
# Certificates are now VERIFIED by every client (no --insecure anywhere).
set -euo pipefail
OUT="${1:-certs}"
RSA_BITS="${ODOQ_RSA_BITS:-2048}"
mkdir -p "$OUT"
cd "$OUT"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 730 -subj "/CN=ODoQ Testbed CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
for role in proxy resolver; do
  openssl ecparam -name prime256v1 -genkey -noout -out "$role.key"
  openssl req -new -key "$role.key" -subj "/CN=$role.odoq.test" -out "$role.csr"
  printf "subjectAltName=DNS:%s.odoq.test\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" "$role" > "$role.ext"
  openssl x509 -req -in "$role.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 730 -sha256 -extfile "$role.ext" -out "$role.pem" 2>/dev/null
  rm -f "$role.csr" "$role.ext"
done
openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$RSA_BITS" -out target_key.pem 2>/dev/null
openssl pkey -in target_key.pem -pubout -out target_pub.pem
chmod 644 ./*.pem ./*.key   # read by containers; testbed-only keys
# ODoH HPKE keypair (P-256), separate from any TLS key
python3 - "$PWD" <<'PY'
import sys; sys.path.insert(0, "src")
try:
    from odoq import odoh
except ImportError:
    sys.path.insert(0, f"{sys.argv[1]}/../src")
    from odoq import odoh
sk, pk = odoh.generate_keypair()
odoh.save_private(sk, "hpke_key.pem")
odoh.save_public(pk, "hpke_pub.bin")
print("ODoH HPKE keypair written")
PY

echo "certs written to $(pwd) (RSA target key: $RSA_BITS bits)"
