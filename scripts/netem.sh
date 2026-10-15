#!/bin/bash
# Runs INSIDE a container (needs NET_ADMIN). Shapes egress toward one peer.
#   netem.sh set PEER_IP DELAY_MS JITTER_MS LOSS_PCT
#   netem.sh clear
#   netem.sh show
# The runner applies half the link RTT on each endpoint. Loss is per direction.
# Note: netem jitter can reorder packets; keep jitter 0 unless studying that.
set -euo pipefail
ifaces() { ls /sys/class/net | grep -v '^lo$'; }
dev_for() { ip -o route get "$1" | sed -n 's/.* dev \([^ ]*\).*/\1/p'; }
case "${1:-}" in
  set)
    peer=$2 delay=$3 jitter=$4 loss=$5
    dev=$(dev_for "$peer")
    [ -n "$dev" ] || { echo "no route to $peer" >&2; exit 1; }
    ethtool -K "$dev" tso off gso off gro off >/dev/null 2>&1 || true
    args="delay ${delay}ms"
    [ "$jitter" != "0" ] && args="$args ${jitter}ms distribution normal"
    [ "$loss" != "0" ] && args="$args loss ${loss}%"
    tc qdisc replace dev "$dev" root netem $args limit 100000
    echo "$dev: netem $args"
    ;;
  clear)
    for d in $(ifaces); do tc qdisc del dev "$d" root 2>/dev/null || true; done
    ;;
  show)
    for d in $(ifaces); do echo "$d: $(tc qdisc show dev "$d" | head -1)"; done
    ;;
  *) echo "usage: $0 set PEER DELAY_MS JITTER_MS LOSS_PCT | clear | show" >&2; exit 2 ;;
esac
