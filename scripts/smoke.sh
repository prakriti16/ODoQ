#!/bin/bash
# End-to-end check on the server: build, start, two sanity queries, smoke
# campaign (~10 min), analysis. Run from the repo root, inside tmux.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f certs/ca.pem ] || scripts/gen_certs.sh certs
python3 tools/gen_zones.py config
mkdir -p results/components results/keys
docker compose build
docker compose up -d
sleep 3
echo "== DoQ sanity"; docker exec odoq-client python3 -m odoq.client --protocol doq \
  --mode warm --target-host 10.77.3.30 --target-port 853 --ca /certs/ca.pem \
  --qname google.com --per-domain 2 | tail -1
echo "== ODoQ sanity"; docker exec odoq-client python3 -m odoq.client --protocol odoq \
  --mode warm --target-host 10.77.2.30 --target-port 8853 --proxy-host 10.77.1.20 \
  --proxy-port 8853 --target-pub /certs/target_pub.pem --ca /certs/ca.pem \
  --qname google.com --per-domain 2 | tail -1
python3 tools/run_campaign.py campaigns/stage1_smoke.json
latest=$(ls -td results/stage1_smoke_* | head -1)
python3 tools/analyze.py "$latest"
