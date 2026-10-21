#!/usr/bin/env bash
# Registers the cs422cc congestion control algorithm with the kernel and
# lets unprivileged sockets select it. Run from anywhere; needs sudo.
#
# After this, "cs422cc" appears in tcp_available_congestion_control and the
# Python client can select it with setsockopt(TCP_CONGESTION).
set -euo pipefail

ALGORITHM=cs422cc
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OBJECT="$SCRIPT_DIR/cs422cc.bpf.o"

make -C "$SCRIPT_DIR"

# Refuse to register twice: the kernel would reject a duplicate name anyway,
# but this gives a clearer message.
if grep -qw "$ALGORITHM" /proc/sys/net/ipv4/tcp_available_congestion_control; then
    echo "$ALGORITHM is already loaded; run unload.sh first to reload it." >&2
    exit 1
fi

# Load the BPF programs and register the struct_ops map (cs422cc_ops) as a
# congestion control algorithm. The registration outlives this command:
# it stays until unload.sh unregisters it or the machine reboots.
sudo bpftool struct_ops register "$OBJECT"

# BBR is a module on Ubuntu and is not loaded by default; the experiments
# compare against it, so load it here too.
sudo modprobe tcp_bbr

# A non-root process may only select algorithms listed in
# tcp_allowed_congestion_control (otherwise setsockopt fails with EPERM).
# Add ours, plus the baselines, to that list.
sudo sysctl -q -w net.ipv4.tcp_allowed_congestion_control="reno cubic bbr $ALGORITHM"

echo "available: $(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
echo "allowed:   $(cat /proc/sys/net/ipv4/tcp_allowed_congestion_control)"
