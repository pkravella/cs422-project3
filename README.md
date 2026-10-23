# cs422-project3

CS 422 Assignment 3, Option 1: our congestion control algorithm as an eBPF
`struct_ops` program, selected per socket by the Assignment 2 iperf3 client.

## Requirements

Linux 5.6+ with BTF (`/sys/kernel/btf/vmlinux`) and `CONFIG_BPF_SYSCALL`,
`CONFIG_BPF_JIT`, `CONFIG_DEBUG_INFO_BTF`. Developed on Ubuntu 24.04,
kernel `6.8.0-101-generic` (aarch64).

```sh
sudo apt install -y build-essential clang llvm libbpf-dev \
    linux-tools-common linux-tools-$(uname -r)
```

## Build and load

```sh
cc/load.sh      # builds cc/cs422cc.bpf.o, registers "cs422cc", loads bbr,
                # and adds both to tcp_allowed_congestion_control
cc/unload.sh    # unregisters it
```

Check: `cat /proc/sys/net/ipv4/tcp_available_congestion_control` lists `cs422cc`.

## Run the experiments

The client, destination selection, runner, and plotting are the Assignment 2
code (`iperf3_client.py`, `destinations.py`, `run_experiments.py`,
`report.py`). After `cc/load.sh`:

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python run_experiments.py listed_iperf3_servers.csv \
    -n 10 --duration 10 --interval 0.2 --repetitions 3 --seed 422 \
    --algorithms cs422cc cubic reno bbr
```

Results (raw samples, metadata, summary table, PDF plots) go to
`results/<timestamp>/`. See the Assignment 2 README for every option and
output file.

## Report

`report/report.md`, built from the repo root with
`pandoc report/report.md -o report/report.pdf`.
