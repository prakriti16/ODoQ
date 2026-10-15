#!/bin/bash
# ODoH target container: shares an Unbound with the ODoQ resolver model but
# runs its own instance so the two oblivious protocols are independent.
set -euo pipefail
mkdir -p /results/components /results/keys
unbound -c /etc/odoq/unbound.conf &
for i in $(seq 1 50); do
  unbound-control -c /etc/odoq/unbound.conf status >/dev/null 2>&1 && break
  sleep 0.1
done
exec python3 -m odoq.odoh_server --role target \
  --host 0.0.0.0 --port 8553 \
  --certificate /certs/resolver.pem --private-key /certs/resolver.key \
  --hpke-key /certs/hpke_key.pem \
  --pad-response-block 468 \
  --log /results/components/odoh-target.jsonl \
  --secrets-log /results/keys/odoh-target.keys
