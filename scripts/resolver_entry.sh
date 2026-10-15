#!/bin/bash
# Resolver container: Unbound on 127.0.0.1:5353, then the DoQ/ODoQ frontend.
set -euo pipefail
mkdir -p /results/components /results/keys
unbound -c /etc/odoq/unbound.conf &
for i in $(seq 1 50); do
  unbound-control -c /etc/odoq/unbound.conf status >/dev/null 2>&1 && break
  sleep 0.1
done
exec python3 -m odoq.server \
  --doq-port 853 --odoq-port 8853 \
  --certificate /certs/resolver.pem --private-key /certs/resolver.key \
  --target-key /certs/target_key.pem \
  --pad-response-block 468 \
  --log /results/components/resolver.jsonl \
  --secrets-log /results/keys/resolver.keys
