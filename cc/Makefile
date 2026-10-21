# Builds the cs422cc congestion control eBPF program.
#
#   make         build cs422cc.bpf.o (generates vmlinux.h first if needed)
#   make clean   remove build outputs
#
# Needs: clang, bpftool, libbpf headers (Ubuntu: clang libbpf-dev
# linux-tools-$(uname -r)), and a kernel with BTF (/sys/kernel/btf/vmlinux).

CLANG   ?= clang
BPFTOOL ?= bpftool

# The running kernel's type information, exported by the kernel itself.
KERNEL_BTF := /sys/kernel/btf/vmlinux

all: cs422cc.bpf.o

# vmlinux.h: C definitions of every kernel struct, generated from this
# kernel's BTF. It is specific to the kernel it was dumped from, so it is
# generated at build time and not committed.
vmlinux.h:
	$(BPFTOOL) btf dump file $(KERNEL_BTF) format c > $@

# -target bpf: emit BPF bytecode instead of native machine code.
# -O2:         required; the BPF verifier rejects unoptimized code.
# -g:          keep BTF debug info, which libbpf needs for struct_ops
#              and CO-RE field relocations.
cs422cc.bpf.o: cs422cc.bpf.c vmlinux.h
	$(CLANG) -target bpf -O2 -g -Wall -c $< -o $@

clean:
	rm -f cs422cc.bpf.o vmlinux.h

.PHONY: all clean
