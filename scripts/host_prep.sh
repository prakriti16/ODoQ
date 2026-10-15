#!/bin/bash
# Run on the HOST before a campaign. Needs sudo.
set -euo pipefail
sudo modprobe sch_netem
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
echo "governor:"; cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c
echo "load: $(cat /proc/loadavg)"
sudo virsh list --all
