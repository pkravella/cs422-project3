# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

CS 422 (Computer Networks, Fall 2026) Assignment 3, **Option 1**: implement the congestion control algorithm designed in Assignment 2, Question 3(b), as an eBPF program, and compare it against CUBIC, Reno, and BBR. Full spec in `assignment-3.pdf`. Due Oct 21, 2026 11:45 PM ET (72-hour grace period); graded by oral exam the week of Oct 26, so the user must be able to explain every line. See **Code style** below: readability and documentation are the top priority.

Layout mirrors the Assignment 2 repo (github.com/ColinHermack/CS422-Project2):

- `cc/`: the algorithm. `cs422cc.bpf.c` is a BPF `struct_ops` implementation of `struct tcp_congestion_ops` registered under the name `cs422cc`; `Makefile` dumps `vmlinux.h` from the running kernel's BTF and compiles with `clang -target bpf`; `load.sh` registers it with `bpftool struct_ops register`, loads `tcp_bbr`, and adds both to `tcp_allowed_congestion_control`; `unload.sh` unregisters it. Currently a hand-written Reno placeholder until the Q3(b) design is final.
- `iperf3_client.py`, `destinations.py`, `run_experiments.py`, `report.py`: copied from Assignment 2 (the spec requires selecting the algorithm with the Assignment 2 client). "Part 1a/2b/3a" references in their docstrings refer to the Assignment 2 spec. `run_experiments.py` is the single entry point; it accepts any algorithm name the kernel lists, so `cs422cc` needs no special casing.
- `report/report.md`: the written report (markdown, converted to PDF with pandoc + LaTeX).

Commands:
- Build and load (Linux, needs sudo): `cc/load.sh`; unload: `cc/unload.sh`.
- Self-checks (any OS, no network): `python3 iperf3_client.py`, `python3 destinations.py`, `.venv/bin/python report.py`.
- Experiments (Linux, after `cc/load.sh`): `.venv/bin/python run_experiments.py listed_iperf3_servers.csv -n 10 --duration 10 --interval 1 --repetitions 3 --algorithms cs422cc cubic reno bbr`.
- Rebuild summary/plots from saved data: `.venv/bin/python run_experiments.py --report-only results/<dir> [--representative HOST:PORT]`.
- Build the report (from the repo root): `pandoc report/report.md -o report/report.pdf`.

## Code style

Code must be easy for a human to read and understand. The user will be orally examined on every line, so readability is the top priority and overrides brevity, cleverness, and minimal diffs.

- **Readability first.** Prefer plain, explicit code: descriptive names, short functions with one job, straightforward control flow. Avoid dense one-liners, nested comprehensions, clever tricks, and unnecessary abstraction. If a simpler version is a few lines longer but easier to follow, use it.
- **Comprehensive documentation.** Every module/file gets a header comment explaining its purpose and how it fits the pipeline. Every function gets a docstring or comment covering what it does, its arguments (with units), return value, and errors.
- **Explain the why.** Comment non-obvious logic, especially which kernel function or hook a BPF callback mirrors and when the kernel calls it, `struct` formats, socket options, timing math, and units (segments vs. bytes, microseconds vs. seconds).
- **Name constants.** No magic numbers: algorithm parameters, thresholds, and protocol values are named constants with a comment on their meaning.
- **BPF specifics.** Integer math only (no floating point in the kernel); use fixed-point with a named scale factor when fractions are needed. Mention the mirrored kernel function (e.g. `tcp_reno_ssthresh()` in `net/ipv4/tcp_cong.c`) so behavior can be checked against the source.

## Spec requirements (Option 1)

- Explain how the implementation updates cwnd using RTT, a loss estimate or proxy, and throughput; document initial state, parameters, and changes from the Assignment 2 pseudocode.
- Select the algorithm on the data socket in the Assignment 2 client and record the algorithm actually used.
- Each test logs cwnd, throughput, RTT, and a loss signal for **10 seconds**. Run `cs422cc`, CUBIC, Reno, and BBR with the same destinations, duration, sampling interval, multiple repetitions; report repetitions and test order.
- Repeat the Assignment 2 Q2(b) time-series and scatter plots for all four algorithms on the same representative destination, labeled, with consistent axes. Include throughput **and RTT** aggregate statistics and explain differences.
- Report: exact kernel version, required kernel features, build and load instructions, raw measurements, reproduction steps, AI-use acknowledgment. Graders review the code but will not load it; the user demonstrates it compiling and running on their own machine.

## Platform

Development VM: Ubuntu 24.04 arm64 in VMware Fusion on macOS, kernel `6.8.0-101-generic`, BTF and BPF JIT enabled, reachable as `ssh pravella@192.168.125.128` (passwordless sudo). The repo is private, so sync with `rsync -a --exclude .DS_Store ~/cs422-project3/ pravella@192.168.125.128:cs422-project3/` and build there; nothing in `cc/` builds or runs on macOS.

VMware's NAT ("Share with my Mac") proxies TCP: in the VM `min_rtt` is ~0.07 ms to servers that ping at 10+ ms, so measurements from the VM describe the hop to the Mac and are useless. The VM is for building, loading, and functional tests only. Bridged mode over Wi-Fi gets no DHCP lease. Real measurements run on group members' WSL2 machines (must have BTF: `/sys/kernel/btf/vmlinux`) or a wired/bridged Linux host.
