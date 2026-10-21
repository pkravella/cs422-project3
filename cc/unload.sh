#!/usr/bin/env bash
# Unregisters the cs422cc congestion control algorithm. Needs sudo.
# Sockets already using it keep it until they close; new sockets can no
# longer select it.
set -euo pipefail

# Name of the struct_ops map in cs422cc.bpf.c (the struct variable name),
# which is how bpftool identifies the registration.
STRUCT_OPS_MAP=cs422cc_ops

sudo bpftool struct_ops unregister name "$STRUCT_OPS_MAP"
echo "available: $(cat /proc/sys/net/ipv4/tcp_available_congestion_control)"
