// SPDX-License-Identifier: GPL-2.0
/*
 * cs422cc.bpf.c: our TCP congestion control algorithm, written as an eBPF
 * struct_ops program (CS 422 Assignment 3, Option 1).
 *
 * How it fits the pipeline:
 *   1. `make` compiles this file into cs422cc.bpf.o (BPF bytecode).
 *   2. load.sh runs `bpftool struct_ops register cs422cc.bpf.o`, which
 *      registers the `cs422cc_ops` struct below with the kernel as a new
 *      congestion control algorithm named "cs422cc". From then on it appears
 *      in /proc/sys/net/ipv4/tcp_available_congestion_control, exactly like
 *      the built-in cubic, reno, and bbr.
 *   3. The Assignment 2 Python client selects it on its data socket with
 *      setsockopt(IPPROTO_TCP, TCP_CONGESTION, "cs422cc") before connect().
 *      The kernel then calls the functions below on that socket's ACKs and
 *      loss events.
 *
 * Current state: PLACEHOLDER. The callbacks implement classic TCP Reno
 * (slow start, additive increase, multiplicative decrease) by hand, mirroring
 * tcp_reno_cong_avoid() and tcp_reno_ssthresh() in net/ipv4/tcp_cong.c. This
 * lets us test the build, load, and selection steps end to end before the
 * real algorithm (Assignment 2, Question 3(b)) replaces the logic.
 *
 * Units: snd_cwnd, snd_ssthresh, and snd_cwnd_cnt are all in SEGMENTS
 * (MSS-sized packets), not bytes.
 *
 * Kernel requirements: Linux 5.6+ with CONFIG_BPF_SYSCALL, CONFIG_BPF_JIT,
 * and CONFIG_DEBUG_INFO_BTF (BPF struct_ops for tcp_congestion_ops).
 */

/*
 * vmlinux.h holds every kernel type (struct sock, struct tcp_sock, ...),
 * dumped from this kernel's BTF by the Makefile. Using it instead of kernel
 * headers is what lets libbpf relocate field offsets (CO-RE) at load time.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>     /* SEC(), license section */
#include <bpf/bpf_tracing.h>     /* BPF_PROG() argument-unpacking macro */
#include <bpf/bpf_core_read.h>   /* BPF_CORE_READ_BITFIELD() */

/* struct_ops programs that use kernel TCP functions must be GPL. */
char _license[] SEC("license") = "GPL";

/*
 * Smallest ssthresh after a loss, in segments. Same floor as the kernel's
 * tcp_reno_ssthresh(): a window of 2 still lets fast retransmit work.
 */
#define MIN_SSTHRESH_SEGMENTS 2

/*
 * Multiplicative decrease on loss: ssthresh = cwnd / LOSS_DIVISOR.
 * Reno halves the window (beta = 1/2).
 */
#define LOSS_DIVISOR 2

/*
 * The kernel passes us a struct sock *, but TCP sockets are really a
 * struct tcp_sock, which begins with a struct sock. This cast mirrors the
 * kernel's own tcp_sk() helper in include/linux/tcp.h.
 */
static struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

/* True while cwnd is below ssthresh (mirrors tcp_in_slow_start()). */
static bool in_slow_start(const struct tcp_sock *tp)
{
	return tp->snd_cwnd < tp->snd_ssthresh;
}

/*
 * Should we grow cwnd at all? Only if the sender is actually using the
 * window it has. If the application or the receiver window is the
 * bottleneck, growing cwnd would just make a big window we never tested.
 * Mirrors tcp_is_cwnd_limited() in include/net/tcp.h:
 *   - in slow start, allow growth while cwnd < 2 * the most packets we had
 *     in flight recently (max_packets_out);
 *   - otherwise use the kernel's is_cwnd_limited flag.
 * is_cwnd_limited is a 1-bit bit field, which BPF can't read with a normal
 * member access, so we use the BPF_CORE_READ_BITFIELD() macro.
 */
static bool is_cwnd_limited(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (in_slow_start(tp))
		return tp->snd_cwnd < 2 * tp->max_packets_out;

	return BPF_CORE_READ_BITFIELD(tp, is_cwnd_limited) != 0;
}

/*
 * Slow start: grow cwnd by one segment per segment acknowledged (so cwnd
 * doubles every RTT), but never past ssthresh. Returns how many of the
 * newly acked segments were NOT used up by slow start, so the caller can
 * spend them on congestion avoidance. Mirrors tcp_slow_start().
 */
static u32 slow_start(struct tcp_sock *tp, u32 acked_segments)
{
	u32 new_cwnd = tp->snd_cwnd + acked_segments;

	if (new_cwnd > tp->snd_ssthresh)
		new_cwnd = tp->snd_ssthresh;

	/* Segments of this ACK left over after reaching ssthresh. */
	acked_segments -= new_cwnd - tp->snd_cwnd;

	if (new_cwnd > tp->snd_cwnd_clamp)
		new_cwnd = tp->snd_cwnd_clamp;
	tp->snd_cwnd = new_cwnd;

	return acked_segments;
}

/*
 * Congestion avoidance (additive increase): grow cwnd by one segment per
 * RTT. One RTT is roughly one window's worth of ACKs, so we count acked
 * segments in snd_cwnd_cnt and add 1 to cwnd each time the count reaches
 * cwnd. Mirrors tcp_cong_avoid_ai() with w = cwnd.
 */
static void additive_increase(struct tcp_sock *tp, u32 acked_segments)
{
	tp->snd_cwnd_cnt += acked_segments;

	if (tp->snd_cwnd_cnt >= tp->snd_cwnd) {
		tp->snd_cwnd_cnt -= tp->snd_cwnd;
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd += 1;
	}
}

/*
 * cong_avoid: called by the kernel (tcp_cong_avoid() in tcp_input.c) on
 * every ACK that advances the window while the connection is not in loss
 * recovery.
 *   ack:   the cumulative ACK number (unused here)
 *   acked: how many segments this ACK newly acknowledged
 */
SEC("struct_ops")
void BPF_PROG(cs422cc_cong_avoid, struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!is_cwnd_limited(sk))
		return;

	if (in_slow_start(tp)) {
		acked = slow_start(tp, acked);
		/* Still below ssthresh: nothing left for additive increase. */
		if (acked == 0)
			return;
	}

	additive_increase(tp, acked);
}

/*
 * ssthresh: called when the kernel detects loss (entering fast recovery
 * after 3 duplicate ACKs / SACK, or on a retransmission timeout). Returns
 * the new slow-start threshold in segments; the kernel then shrinks cwnd
 * toward it. Mirrors tcp_reno_ssthresh(): half the current window, at
 * least 2 segments.
 */
SEC("struct_ops")
u32 BPF_PROG(cs422cc_ssthresh, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 reduced = tp->snd_cwnd / LOSS_DIVISOR;

	if (reduced < MIN_SSTHRESH_SEGMENTS)
		return MIN_SSTHRESH_SEGMENTS;
	return reduced;
}

/*
 * undo_cwnd: called when the kernel decides a loss was spurious (for
 * example, a DSACK shows the "lost" segment actually arrived). Returns the
 * window to restore: the larger of the current cwnd and the cwnd before
 * the reduction (prior_cwnd). Mirrors tcp_reno_undo_cwnd().
 */
SEC("struct_ops")
u32 BPF_PROG(cs422cc_undo_cwnd, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	if (tp->snd_cwnd > tp->prior_cwnd)
		return tp->snd_cwnd;
	return tp->prior_cwnd;
}

/*
 * The struct the kernel registers. Field names are the hooks in
 * struct tcp_congestion_ops (include/net/tcp.h). ssthresh, undo_cwnd, and
 * one of cong_avoid / cong_control are mandatory; the kernel refuses to
 * register the algorithm without them. `name` is what setsockopt
 * TCP_CONGESTION uses; it must be at most 15 characters (TCP_CA_NAME_MAX
 * is 16 including the terminating NUL).
 */
SEC(".struct_ops")
struct tcp_congestion_ops cs422cc_ops = {
	.cong_avoid = (void *)cs422cc_cong_avoid,
	.ssthresh   = (void *)cs422cc_ssthresh,
	.undo_cwnd  = (void *)cs422cc_undo_cwnd,
	.name       = "cs422cc",
};
