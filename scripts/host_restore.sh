#!/bin/bash
# Run on the HOST after a campaign: give the CPU governor back.
set -euo pipefail
echo ondemand | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor >/dev/null
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort | uniq -c
