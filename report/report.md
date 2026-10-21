---
title: "CS 422 Assignment 3: TCP Congestion Control Implementation (Option 1: eBPF)"
author: TODO group members
date: Fall 2026
geometry: margin=1in
colorlinks: true
---

<!--
Build from the repository root (pandoc resolves image paths from there):

    pandoc report/report.md -o report/report.pdf

Before submitting:
  - Replace RESULTS_DIR with the committed results directory of the real
    Linux campaign.
  - Replace "blob/main" in code links with "blob/<final commit hash>" and
    re-check every line range.
  - Fill in every TODO.
-->

Repository: <https://github.com/pkravella/cs422-project3>

# 1. Algorithm implementation

TODO: how `cs422cc` updates the congestion window using RTT, the loss
estimate or proxy, and throughput, with links to each callback in
`cc/cs422cc.bpf.c`.

## Initial state and parameters

TODO: initial cwnd and ssthresh, every named constant and its value.

## Changes from the Assignment 2 pseudocode

TODO.

# 2. Kernel, build, and load

TODO: exact kernel version (`uname -r`) of the measurement host, required
features (BPF struct_ops for `tcp_congestion_ops`, Linux 5.6+,
`CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`), toolchain
versions (clang, bpftool, libbpf), and the build and load commands.

# 3. Experiments

TODO: destinations, duration (10 s), sampling interval, repetitions, test
order, and the exact command line from `metadata.json`. Confirm
`algorithm_used` matched the requested algorithm for every run.

## Time series and scatter plots

TODO: representative destination; `tcp_timeseries_<algorithm>.pdf` and
`tcp_scatter_<algorithm>.pdf` for `cs422cc`, cubic, reno, and bbr.

## Aggregate statistics

TODO: throughput and RTT (min / median / mean / p95) per algorithm.

## Observed differences

TODO.

# Reproducing the results

TODO.

# Use of AI tools

TODO.
