// SPDX-License-Identifier: GPL-2.0
/*
 * cs422cc.bpf.c: Delay-Gated Loss (DGL), the TCP congestion control
 * algorithm we designed in Assignment 2, Question 3(b), written as an eBPF
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
 * The algorithm:
 *   DGL is Reno-style AIMD (additive increase, multiplicative decrease) with
 *   two changes, both driven by our Assignment 2 measurements.
 *
 *   1. It reads the bottleneck queue from the RTT:
 *          queue_delay = srtt - min_rtt
 *      - queue_delay <= min_rtt / 8: no queue, grow cwnd by 1 segment per RTT
 *      - between min_rtt / 8 and min_rtt / 4: small queue, hold cwnd steady
 *      - queue_delay >  min_rtt / 4: long queue, cut cwnd by 1/8 (at most
 *        once per round trip) to drain it
 *      Slow start ends as soon as queue_delay passes min_rtt / 8.
 *
 *   2. It classifies every loss:
 *      - congestion (a long queue, or more than 5% of the last round's
 *        segments retransmitted): halve the window, like Reno;
 *      - random (no queue): cut only 1/8, and never below the window the
 *        path recently delivered at full rate, bw_max * min_rtt.
 *
 * Which kernel callback does what:
 *   init        connection start: reset our per-connection state
 *   pkts_acked  every ACK: take the RTT sample (min_rtt); once per round
 *               trip, measure the delivery rate (bw_max) and the loss rate
 *   cong_avoid  every ACK outside loss recovery: grow, hold, or back off
 *   ssthresh    on loss: classify it and return the reduced window
 *   undo_cwnd   when a loss turns out to be spurious: restore the window
 *
 * Units:
 *   windows and counters (snd_cwnd, snd_ssthresh, snd_cwnd_cnt, delivered,
 *   total_retrans, packets_out) .......... SEGMENTS (MSS-sized packets)
 *   times (RTTs, timestamps) .............. MICROSECONDS
 *   rates (bw_max) ........................ SEGMENTS PER SECOND
 *
 * The kernel has no floating point, so every fraction (1/8, 7/8, 15/16, 5%)
 * is written as an integer numerator and denominator.
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

/* ------------------------------------------------------------------------
 * Parameters (Assignment 2, Question 3(b), "constants")
 * ------------------------------------------------------------------------ */

/*
 * "No queue" threshold: grow only while queue_delay <= min_rtt / 8.
 * Also ends slow start once queue_delay passes it.
 */
#define GROW_DIVISOR 8

/*
 * "Congested" threshold: queue_delay > min_rtt / 4 means the bottleneck
 * queue is filling. Chosen between the srtt/min_rtt ratios we measured on
 * lossy-but-unqueued paths (1.04 to 1.09) and on paths where our own data
 * queued (1.4 to 2.5).
 */
#define CONGESTED_DIVISOR 4

/* Congestion loss: new window = cwnd * 1/2, Reno's multiplicative decrease. */
#define CONGESTION_BETA_NUMERATOR   1
#define CONGESTION_BETA_DENOMINATOR 2

/* Random loss (no queue): new window = cwnd * 7/8, a much smaller cut. */
#define RANDOM_LOSS_BETA_NUMERATOR   7
#define RANDOM_LOSS_BETA_DENOMINATOR 8

/* Delay backoff: while congested, remove cwnd / 8, at most once per round. */
#define DELAY_BACKOFF_DIVISOR 8

/*
 * Loss-rate guard: if more than 5% of the last round's segments were
 * retransmitted, treat a loss as congestion even with no queue (catches a
 * rate policer, which drops without queueing). Above every per-run loss
 * rate we measured (at most 3.7%).
 */
#define LOSS_RATE_LIMIT_NUMERATOR   5
#define LOSS_RATE_LIMIT_DENOMINATOR 100

/*
 * bw_max decays by 15/16 per round, so the throughput floor follows a real
 * drop in capacity within about 10 to 20 round trips.
 */
#define BW_DECAY_NUMERATOR   15
#define BW_DECAY_DENOMINATOR 16

#define MICROSECONDS_PER_SECOND 1000000ULL

/* Forget min_rtt after 10 s without a new minimum (e.g. after a route change). */
#define MIN_RTT_WINDOW_US (10 * MICROSECONDS_PER_SECOND)

/*
 * Smallest window we ever set, in segments. Same floor as the kernel's
 * tcp_reno_ssthresh(): a window of 2 still lets fast retransmit work.
 */
#define MIN_CWND 2

/* min_rtt value before the first RTT sample: the largest u32. */
#define MIN_RTT_UNSET 0xFFFFFFFFU

/* ------------------------------------------------------------------------
 * Per-connection state
 * ------------------------------------------------------------------------ */

/*
 * Our state for one connection. The kernel reserves a small scratch area in
 * every TCP socket for its congestion control (icsk_ca_priv); we store this
 * struct there, the same way the built-in algorithms do.
 *
 * Initial values (set in cs422cc_init): no min_rtt yet, bw_max = 0, no
 * completed round, and a first round starting at connection setup. The
 * kernel itself starts every connection with cwnd = 10 segments and
 * ssthresh = "infinity" (TCP_INFINITE_SSTHRESH), so we begin in slow start.
 *
 * The 64-bit fields come first so the struct has no padding.
 */
struct dgl_state {
	u64 min_rtt_stamp_us;      /* when min_rtt was last set (tp->tcp_mstamp clock) */
	u64 round_start_us;        /* when the current round trip began */
	u64 bw_max;                /* decaying maximum delivery rate, segments/s */

	u32 min_rtt_us;            /* lowest RTT sample in the last 10 s, or MIN_RTT_UNSET */

	/* Round-trip bookkeeping: snapshots of tcp_sock counters (segments). */
	u32 round_end_delivered;   /* the round ends once tp->delivered reaches this */
	u32 round_start_delivered; /* tp->delivered when the round began */
	u32 round_start_retrans;   /* tp->total_retrans when the round began */

	/* Loss proxy from the last completed round (segments). */
	u32 last_round_delivered;
	u32 last_round_retrans;

	/* Has the delay backoff already cut cwnd during this round? */
	bool backed_off_this_round;
};

/*
 * The state must fit in the scratch area. icsk_ca_priv's size is read from
 * the kernel's own type (in vmlinux.h), so this check follows the kernel.
 */
_Static_assert(sizeof(struct dgl_state) <=
	       sizeof(((struct inet_connection_sock *)0)->icsk_ca_priv),
	       "struct dgl_state does not fit in icsk_ca_priv");

/* ------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------ */

/*
 * The kernel passes us a struct sock *, but TCP sockets are really a
 * struct tcp_sock, which begins with a struct sock. This cast mirrors the
 * kernel's own tcp_sk() helper in include/linux/tcp.h.
 */
static struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

/*
 * Our per-connection state, stored in the socket's icsk_ca_priv area.
 * Mirrors the kernel's inet_csk_ca() in include/net/inet_connection_sock.h.
 */
static struct dgl_state *dgl(const struct sock *sk)
{
	return (struct dgl_state *)((struct inet_connection_sock *)sk)->icsk_ca_priv;
}

/*
 * True once `counter` has reached `target`, correct even when the u32
 * counter wraps around. Same trick as the kernel's before()/after() for
 * sequence numbers in include/net/tcp.h.
 */
static bool counter_reached(u32 counter, u32 target)
{
	return (s32)(counter - target) >= 0;
}

/*
 * Smoothed RTT in microseconds. The kernel stores srtt multiplied by 8
 * (tcp_sock.srtt_us is "smoothed round trip time << 3 in usecs"), so shift
 * it back.
 */
static u32 srtt_us(const struct tcp_sock *tp)
{
	return tp->srtt_us >> 3;
}

/*
 * Segments currently in the network: sent, minus those the receiver
 * reported (SACKed) or that we consider lost, plus retransmissions.
 * Mirrors tcp_packets_in_flight() in include/net/tcp.h.
 */
static u32 packets_in_flight(const struct tcp_sock *tp)
{
	u32 left_network = tp->sacked_out + tp->lost_out;

	return tp->packets_out - left_network + tp->retrans_out;
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

/* ------------------------------------------------------------------------
 * Signals: RTT (queue), throughput (bw_max), loss proxy (loss rate)
 * ------------------------------------------------------------------------ */

/*
 * Is the queue longer than min_rtt / divisor?
 *   queue_delay = srtt - min_rtt   (microseconds)
 * Called with GROW_DIVISOR (8) to ask "is any queue forming?" and with
 * CONGESTED_DIVISOR (4) to ask "is the queue long?". Before the first RTT
 * sample there is no min_rtt, so we report no queue and the connection
 * behaves like Reno.
 */
static bool queue_longer_than(const struct sock *sk, u32 divisor)
{
	const struct dgl_state *ca = dgl(sk);
	u32 srtt = srtt_us(tcp_sk(sk));
	u32 queue_delay;

	if (ca->min_rtt_us == MIN_RTT_UNSET)
		return false;

	/* srtt can dip below min_rtt briefly; that means no queue. */
	if (srtt <= ca->min_rtt_us)
		return false;

	queue_delay = srtt - ca->min_rtt_us;
	return queue_delay > ca->min_rtt_us / divisor;
}

/*
 * Feed one RTT sample (microseconds) into min_rtt. Take it if it is a new
 * minimum, or if the current minimum is older than 10 s (MIN_RTT_WINDOW_US)
 * so a route change to a longer path is eventually accepted.
 */
static void update_min_rtt(struct sock *sk, u32 rtt_us)
{
	struct dgl_state *ca = dgl(sk);
	u64 now_us = tcp_sk(sk)->tcp_mstamp;
	bool is_new_minimum = rtt_us < ca->min_rtt_us;  /* always true while unset */
	bool expired = now_us - ca->min_rtt_stamp_us > MIN_RTT_WINDOW_US;

	if (is_new_minimum || expired) {
		ca->min_rtt_us = rtt_us;
		ca->min_rtt_stamp_us = now_us;
	}
}

/*
 * Begin a new round trip. A round ends when everything in flight right now
 * has been delivered, i.e. once tp->delivered has grown by the current
 * number of packets in flight. Snapshots the counters so the round's
 * delivery rate and loss rate can be computed when it ends.
 */
static void start_round(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgl_state *ca = dgl(sk);

	ca->round_start_us = tp->tcp_mstamp;
	ca->round_start_delivered = tp->delivered;
	ca->round_start_retrans = tp->total_retrans;
	ca->round_end_delivered = tp->delivered + packets_in_flight(tp);
	ca->backed_off_this_round = false;
}

/*
 * End the current round: record its loss proxy and update bw_max.
 *   delivery rate = segments delivered this round / round duration
 *   bw_max        = max(delivery rate, bw_max * 15/16)
 * The decay lets bw_max follow a real capacity drop instead of holding on
 * to an old peak forever.
 */
static void finish_round(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgl_state *ca = dgl(sk);
	u32 delivered = tp->delivered - ca->round_start_delivered;
	u32 retrans = tp->total_retrans - ca->round_start_retrans;
	u64 duration_us = tp->tcp_mstamp - ca->round_start_us;
	u64 rate;
	u64 decayed_bw_max;

	ca->last_round_delivered = delivered;
	ca->last_round_retrans = retrans;

	if (delivered == 0 || duration_us == 0)
		return;

	/* segments per second; u64 so delivered * 10^6 cannot overflow */
	rate = (u64)delivered * MICROSECONDS_PER_SECOND / duration_us;
	decayed_bw_max = ca->bw_max * BW_DECAY_NUMERATOR / BW_DECAY_DENOMINATOR;

	if (rate > decayed_bw_max)
		ca->bw_max = rate;
	else
		ca->bw_max = decayed_bw_max;
}

/*
 * Loss-rate guard: did the last completed round retransmit more than 5% of
 * the segments it delivered?
 *   retrans / delivered > 5 / 100   is tested as
 *   retrans * 100 > delivered * 5   to stay in integers.
 */
static bool last_round_loss_heavy(const struct sock *sk)
{
	const struct dgl_state *ca = dgl(sk);
	u64 scaled_retrans = (u64)ca->last_round_retrans * LOSS_RATE_LIMIT_DENOMINATOR;
	u64 scaled_limit = (u64)ca->last_round_delivered * LOSS_RATE_LIMIT_NUMERATOR;

	return scaled_retrans > scaled_limit;
}

/*
 * The window the path recently delivered at full rate, in segments:
 *   bdp = bw_max (segments/s) * min_rtt (us) / 10^6
 * This is the floor after a random loss. Zero until we have both signals.
 */
static u32 bdp_floor_segments(const struct sock *sk)
{
	const struct dgl_state *ca = dgl(sk);
	u64 bdp;

	if (ca->min_rtt_us == MIN_RTT_UNSET || ca->bw_max == 0)
		return 0;

	bdp = ca->bw_max * ca->min_rtt_us / MICROSECONDS_PER_SECOND;
	if (bdp > 0xFFFFFFFFULL)
		return 0xFFFFFFFFU;
	return (u32)bdp;
}

/* ------------------------------------------------------------------------
 * Window changes
 * ------------------------------------------------------------------------ */

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
 * Delay backoff: the queue is long, so remove 1/8 of the window to drain
 * it. ssthresh moves down with cwnd; otherwise cwnd < ssthresh would put
 * the connection back into slow start on the next ACK and double the
 * window we just cut. (The Assignment 2 pseudocode left this implicit.)
 */
static void delay_backoff(struct tcp_sock *tp)
{
	u32 new_cwnd = tp->snd_cwnd - tp->snd_cwnd / DELAY_BACKOFF_DIVISOR;

	if (new_cwnd < MIN_CWND)
		new_cwnd = MIN_CWND;

	tp->snd_cwnd = new_cwnd;
	tp->snd_ssthresh = new_cwnd;
	tp->snd_cwnd_cnt = 0;
}

/* ------------------------------------------------------------------------
 * Kernel callbacks (struct tcp_congestion_ops)
 * ------------------------------------------------------------------------ */

/*
 * init: called once when the connection starts using this algorithm
 * (tcp_init_congestion_control(), when the handshake completes). Sets the
 * initial state described above struct dgl_state.
 */
SEC("struct_ops")
void BPF_PROG(cs422cc_init, struct sock *sk)
{
	struct dgl_state *ca = dgl(sk);

	ca->min_rtt_us = MIN_RTT_UNSET;
	ca->min_rtt_stamp_us = tcp_sk(sk)->tcp_mstamp;
	ca->bw_max = 0;
	ca->last_round_delivered = 0;
	ca->last_round_retrans = 0;
	start_round(sk);
}

/*
 * pkts_acked: called on every ACK that acknowledges new data
 * (tcp_clean_rtx_queue() in tcp_input.c), including during loss recovery,
 * and before cong_avoid. This is where we collect the signals:
 *   - sample->rtt_us is this ACK's RTT sample in microseconds, or negative
 *     when the ACK gave no valid sample (e.g. it covered a retransmission);
 *   - when the current round has been fully delivered, close it (delivery
 *     rate and loss rate) and start the next one.
 */
SEC("struct_ops")
void BPF_PROG(cs422cc_pkts_acked, struct sock *sk, const struct ack_sample *sample)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgl_state *ca = dgl(sk);

	if (sample->rtt_us > 0)
		update_min_rtt(sk, (u32)sample->rtt_us);

	if (counter_reached(tp->delivered, ca->round_end_delivered)) {
		finish_round(sk);
		start_round(sk);
	}
}

/*
 * cong_avoid: called by the kernel (tcp_cong_avoid() in tcp_input.c) on
 * every ACK that advances the window while the connection is not in loss
 * recovery. Grows, holds, or backs off cwnd based on the queue.
 *   ack:   the cumulative ACK number (unused)
 *   acked: how many segments this ACK newly acknowledged
 */
SEC("struct_ops")
void BPF_PROG(cs422cc_cong_avoid, struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct dgl_state *ca = dgl(sk);

	if (!is_cwnd_limited(sk))
		return;

	if (in_slow_start(tp)) {
		if (queue_longer_than(sk, GROW_DIVISOR)) {
			/*
			 * A queue is forming: stop doubling. Setting ssthresh to
			 * the current window ends slow start; the next ACK is
			 * handled by congestion avoidance below.
			 */
			tp->snd_ssthresh = tp->snd_cwnd;
			return;
		}

		acked = slow_start(tp, acked);
		/* Still below ssthresh: nothing left for congestion avoidance. */
		if (acked == 0)
			return;
	}

	/* No queue: probe for more bandwidth, +1 segment per RTT. */
	if (!queue_longer_than(sk, GROW_DIVISOR)) {
		additive_increase(tp, acked);
		return;
	}

	/* Long queue: drain it, but cut at most once per round trip. */
	if (queue_longer_than(sk, CONGESTED_DIVISOR) && !ca->backed_off_this_round) {
		delay_backoff(tp);
		ca->backed_off_this_round = true;
		return;
	}

	/* Small queue (between min_rtt / 8 and min_rtt / 4): hold cwnd. */
}

/*
 * ssthresh: called when the kernel detects loss (entering fast recovery
 * after 3 duplicate ACKs / SACK, or on a retransmission timeout). Returns
 * the new slow-start threshold in segments. After fast recovery the kernel
 * sets cwnd to this value; after a timeout it sets cwnd = 1 and slow-starts
 * back up to it.
 *
 * Congestion loss (long queue, or the loss-rate guard): halve, like Reno.
 * Random loss: cut by 1/8, but not below the recently measured BDP.
 */
SEC("struct_ops")
u32 BPF_PROG(cs422cc_ssthresh, struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 cwnd = tp->snd_cwnd;
	u32 new_ssthresh;
	u32 bdp_floor;

	if (queue_longer_than(sk, CONGESTED_DIVISOR) || last_round_loss_heavy(sk)) {
		new_ssthresh = cwnd * CONGESTION_BETA_NUMERATOR / CONGESTION_BETA_DENOMINATOR;
	} else {
		new_ssthresh = (u64)cwnd * RANDOM_LOSS_BETA_NUMERATOR / RANDOM_LOSS_BETA_DENOMINATOR;

		bdp_floor = bdp_floor_segments(sk);
		if (bdp_floor > new_ssthresh)
			new_ssthresh = bdp_floor;

		/*
		 * A loss must never raise the window. bw_max can be from an
		 * earlier, larger window, so cap the floor at the current cwnd.
		 * (The Assignment 2 pseudocode did not cap it.)
		 */
		if (new_ssthresh > cwnd)
			new_ssthresh = cwnd;
	}

	if (new_ssthresh < MIN_CWND)
		new_ssthresh = MIN_CWND;
	return new_ssthresh;
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
	.init       = (void *)cs422cc_init,
	.pkts_acked = (void *)cs422cc_pkts_acked,
	.cong_avoid = (void *)cs422cc_cong_avoid,
	.ssthresh   = (void *)cs422cc_ssthresh,
	.undo_cwnd  = (void *)cs422cc_undo_cwnd,
	.name       = "cs422cc",
};
