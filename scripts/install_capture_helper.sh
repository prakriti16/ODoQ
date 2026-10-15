#!/bin/bash
# One-time setup on the host so long campaigns can capture without a cached
# sudo password. Grants passwordless sudo for exactly two commands.
set -euo pipefail
cd "$(dirname "$0")"
sudo install -o root -g root -m 0755 odoq-capture /usr/local/sbin/odoq-capture
rule="$USER ALL=(root) NOPASSWD: /usr/local/sbin/odoq-capture, /usr/bin/virsh list --all"
echo "$rule" | sudo tee /etc/sudoers.d/odoq-capture >/dev/null
sudo chmod 0440 /etc/sudoers.d/odoq-capture
sudo visudo -cf /etc/sudoers.d/odoq-capture
sudo -n /usr/local/sbin/odoq-capture --check
