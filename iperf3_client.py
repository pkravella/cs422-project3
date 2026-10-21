"""From-scratch iperf3 TCP client that runs one throughput experiment.

This module talks to a standard public iperf3 server using only Python's
socket library (no iperf3 binary). It sends data for a fixed duration and,
at a regular interval, samples TCP statistics (TCP_INFO) from the data
socket to compute goodput and record congestion-control state.

iperf3 protocol, as implemented here (client sends, server receives, one
TCP stream). Message order mirrors iperf3's src/iperf_client_api.c:

    1. Open the control connection and send a 37-byte cookie.
    2. Wait for the server to send PARAM_EXCHANGE.
    3. Send the test parameters as length-prefixed JSON.
    4. Wait for CREATE_STREAMS.
    5. Open the data connection (congestion control chosen before connect)
       and send the same cookie on it.
    6. Wait for TEST_START, then TEST_RUNNING.
    7. Send data continuously for the test duration, sampling TCP_INFO.
    8. Send TEST_END.
    9. Wait for EXCHANGE_RESULTS, send our results JSON, receive the
       server's results JSON.
   10. Wait for DISPLAY_RESULTS, send IPERF_DONE, close both sockets.

Linux only: TCP_INFO and TCP_CONGESTION are Linux socket options, and the
struct tcp_info layout decoded below is Linux's. On macOS only the
self-check at the bottom of this file runs.
"""

import json
import random
import select
import socket
import string
import struct
import time


# ---------------------------------------------------------------------------
# iperf3 protocol constants
# ---------------------------------------------------------------------------

# Control-connection state codes, from iperf3's src/iperf_api.h. The server
# sends one of these as a single signed byte to tell the client what to do
# next; the client sends some of them back (TEST_END, IPERF_DONE, ...).
TEST_START = 1          # server: test is about to start
TEST_RUNNING = 2        # server: client may start sending data now
TEST_END = 4            # client: we finished sending data
PARAM_EXCHANGE = 9      # server: send me your test parameters
CREATE_STREAMS = 10     # server: params accepted, open the data connection(s)
SERVER_TERMINATE = 11   # server: test aborted on the server side
CLIENT_TERMINATE = 12   # client: test aborted on the client side
EXCHANGE_RESULTS = 13   # server: send me your results, then read mine
DISPLAY_RESULTS = 14    # server: results exchanged, test is complete
IPERF_DONE = 16         # client: we are done, closing connections
ACCESS_DENIED = -1      # server: busy with another client, go away
SERVER_ERROR = -2       # server: error; followed by two 4-byte error codes

# Names for the state codes above, used only to make error messages readable.
STATE_NAMES = {
    TEST_START: "TEST_START",
    TEST_RUNNING: "TEST_RUNNING",
    TEST_END: "TEST_END",
    PARAM_EXCHANGE: "PARAM_EXCHANGE",
    CREATE_STREAMS: "CREATE_STREAMS",
    SERVER_TERMINATE: "SERVER_TERMINATE",
    CLIENT_TERMINATE: "CLIENT_TERMINATE",
    EXCHANGE_RESULTS: "EXCHANGE_RESULTS",
    DISPLAY_RESULTS: "DISPLAY_RESULTS",
    IPERF_DONE: "IPERF_DONE",
    ACCESS_DENIED: "ACCESS_DENIED",
    SERVER_ERROR: "SERVER_ERROR",
}

# The cookie is a random 36-character string plus a NUL terminator (37 bytes
# total, COOKIE_SIZE in iperf_api.h). The client sends it first on every
# connection it opens; the server uses it to recognize that a new data
# connection belongs to the test started on our control connection.
COOKIE_SIZE = 37
COOKIE_CHARACTERS = string.ascii_lowercase + "234567"  # same alphabet iperf3 uses

# Size of each send() call on the data socket, in bytes. 128 KiB is iperf3's
# default TCP block size (DEFAULT_TCP_BLKSIZE); we report it to the server as
# the "len" parameter.
BLOCK_SIZE = 128 * 1024

# iperf3 version we claim to be in the parameter JSON. Informational only;
# servers do not reject clients based on it.
CLIENT_VERSION = "3.16"

# Default time, in seconds, to wait for a connection or a control message
# before deciding the server is unresponsive.
DEFAULT_TIMEOUT = 10.0

# Largest JSON message, in bytes, we accept from the server. Real results are
# a few KB; this guards against a broken server sending a garbage length.
MAX_JSON_SIZE = 1024 * 1024

# Linux limit on a congestion control name, including the NUL terminator
# (TCP_CA_NAME_MAX in include/net/tcp.h).
TCP_CA_NAME_MAX = 16


# ---------------------------------------------------------------------------
# TCP_INFO decoding
# ---------------------------------------------------------------------------

# Layout of Linux's struct tcp_info (include/uapi/linux/tcp.h), in order,
# up to and including tcpi_snd_wnd (the last field added in Linux 5.4;
# Ubuntu 22.04 ships 5.15). Each entry is (field name without the "tcpi_"
# prefix, struct format code, unit):
#   "B" = unsigned 8-bit, "I" = unsigned 32-bit, "Q" = unsigned 64-bit.
# The unit is saved with the measurements (metadata.json) so the raw data
# documents itself. Newer kernels append more fields after snd_wnd; we stop
# here because these are all we need.
TCP_INFO_FIELDS = [
    ("state", "B", "code"),              # TCP state (1 = ESTABLISHED)
    ("ca_state", "B", "code"),           # congestion state: 0 Open, 1 Disorder, 2 CWR, 3 Recovery, 4 Loss
    ("retransmits", "B", "count"),       # retransmissions of the oldest unacked segment (resets on ACK)
    ("probes", "B", "count"),            # zero-window probes sent
    ("backoff", "B", "count"),           # retransmission-timeout backoff count
    ("options", "B", "bit flags"),       # negotiated options (SACK, timestamps, ...)
    ("wscale", "B", "bit fields"),       # low 4 bits: send window scale, high 4 bits: receive window scale
    ("app_limited_flags", "B", "bit flags"),  # bit 0: delivery_rate_app_limited; bits 1-2: fastopen_client_fail
    ("rto", "I", "microseconds"),        # retransmission timeout
    ("ato", "I", "microseconds"),        # delayed-ACK timeout
    ("snd_mss", "I", "bytes"),           # sender maximum segment size
    ("rcv_mss", "I", "bytes"),           # receiver maximum segment size
    ("unacked", "I", "segments"),        # sent but not yet acknowledged
    ("sacked", "I", "segments"),         # selectively acknowledged (SACK)
    ("lost", "I", "segments"),           # currently presumed lost
    ("retrans", "I", "segments"),        # currently retransmitted and not yet acknowledged
    ("fackets", "I", "segments"),        # unused in modern kernels (always 0)
    ("last_data_sent", "I", "milliseconds"),  # time since last data sent
    ("last_ack_sent", "I", "milliseconds"),   # not implemented by Linux (always 0)
    ("last_data_recv", "I", "milliseconds"),  # time since last data received
    ("last_ack_recv", "I", "milliseconds"),   # time since last ACK received
    ("pmtu", "I", "bytes"),              # path MTU
    ("rcv_ssthresh", "I", "bytes"),      # receive-side slow start threshold
    ("rtt", "I", "microseconds"),        # smoothed RTT (srtt)
    ("rttvar", "I", "microseconds"),     # RTT variation
    ("snd_ssthresh", "I", "segments"),   # slow start threshold
    ("snd_cwnd", "I", "segments"),       # congestion window
    ("advmss", "I", "bytes"),            # advertised MSS
    ("reordering", "I", "segments"),     # estimated packet reordering
    ("rcv_rtt", "I", "microseconds"),    # receiver-side RTT estimate
    ("rcv_space", "I", "bytes"),         # receive buffer space estimate
    ("total_retrans", "I", "segments"),  # total retransmitted over the connection's life
    ("pacing_rate", "Q", "bytes/second"),      # current pacing rate
    ("max_pacing_rate", "Q", "bytes/second"),  # pacing rate cap (unlimited = 2^64 - 1)
    ("bytes_acked", "Q", "bytes"),       # cumulative bytes acknowledged by the receiver
    ("bytes_received", "Q", "bytes"),    # cumulative bytes received from the peer
    ("segs_out", "I", "segments"),       # total sent (including retransmits and pure ACKs)
    ("segs_in", "I", "segments"),        # total received
    ("notsent_bytes", "I", "bytes"),     # bytes in the send buffer not yet sent
    ("min_rtt", "I", "microseconds"),    # minimum RTT observed
    ("data_segs_in", "I", "segments"),   # received segments that carried data
    ("data_segs_out", "I", "segments"),  # sent segments that carried data
    ("delivery_rate", "Q", "bytes/second"),  # most recent delivery rate estimate
    # Added in Linux 4.10 to 4.19:
    ("busy_time", "Q", "microseconds"),       # time busy sending data
    ("rwnd_limited", "Q", "microseconds"),    # part of busy_time stalled by the receiver's window
    ("sndbuf_limited", "Q", "microseconds"),  # part of busy_time stalled by our send buffer
    ("delivered", "I", "segments"),      # total delivered to the receiver (acked or SACKed)
    ("delivered_ce", "I", "segments"),   # delivered segments marked ECN congestion-experienced
    ("bytes_sent", "Q", "bytes"),        # total data bytes sent, including retransmits
    ("bytes_retrans", "Q", "bytes"),     # total data bytes retransmitted
    ("dsack_dups", "I", "segments"),     # duplicate segments reported by D-SACK (spurious retransmits)
    ("reord_seen", "I", "count"),        # packet reordering events seen
    # Added in Linux 5.4:
    ("rcv_ooopack", "I", "segments"),    # out-of-order packets received
    ("snd_wnd", "I", "bytes"),           # receive window the server advertised (after scaling)
]


def build_tcp_info_format(fields):
    """Build the struct format string for a list of (name, code, unit) fields.

    Args:
        fields: list of (field_name, struct_code, unit) tuples, in struct order.

    Returns:
        A format string for the struct module. It starts with "=", meaning
        native byte order and no automatic padding. That matches the kernel
        struct because every field is already naturally aligned.
    """
    format_string = "="
    for _name, code, _unit in fields:
        format_string += code
    return format_string


TCP_INFO_FORMAT = build_tcp_info_format(TCP_INFO_FIELDS)
TCP_INFO_SIZE = struct.calcsize(TCP_INFO_FORMAT)  # 232 bytes

# Buffer size to request from getsockopt. Larger than TCP_INFO_SIZE because
# newer kernels return a longer struct; we only decode the first part.
TCP_INFO_BUFFER_SIZE = 256


def decode_tcp_info(raw):
    """Decode the raw bytes of a Linux struct tcp_info into a dict.

    Args:
        raw: bytes returned by getsockopt(IPPROTO_TCP, TCP_INFO, ...).

    Returns:
        Dict mapping each field name in TCP_INFO_FIELDS to its integer value.
        Units are the third element of each entry in TCP_INFO_FIELDS.

    Raises:
        RuntimeError: the kernel returned fewer bytes than we know how to
            decode (kernel older than 5.4). This is a host problem, not a
            server problem, so it is not an IperfError.
    """
    if len(raw) < TCP_INFO_SIZE:
        raise RuntimeError(
            f"kernel returned {len(raw)} bytes of tcp_info, need {TCP_INFO_SIZE} "
            "(Linux 5.4 or newer required)"
        )

    # Only decode the prefix we know; newer kernels append more fields.
    values = struct.unpack(TCP_INFO_FORMAT, raw[:TCP_INFO_SIZE])

    info = {}
    for (name, _code, _unit), value in zip(TCP_INFO_FIELDS, values):
        info[name] = value
    return info


def read_tcp_info(sock):
    """Read and decode TCP_INFO from a connected TCP socket (Linux only).

    Args:
        sock: a connected TCP socket.

    Returns:
        Dict of decoded tcp_info fields (see decode_tcp_info).
    """
    raw = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, TCP_INFO_BUFFER_SIZE)
    return decode_tcp_info(raw)


def compute_goodput_bps(previous_bytes_acked, previous_time, bytes_acked, sample_time):
    """Compute goodput between two samples, in bits per second.

    goodput = (change in cumulative bytes acknowledged) / (elapsed time) * 8

    Using acknowledged bytes (not bytes we handed to send()) measures data
    the receiver actually got, rather than data sitting in our send buffer.
    Using the real elapsed time (not the nominal interval) corrects for
    samples that were taken slightly late.

    Args:
        previous_bytes_acked: tcpi_bytes_acked at the previous sample, bytes.
        previous_time: time of the previous sample, seconds.
        bytes_acked: tcpi_bytes_acked at this sample, bytes.
        sample_time: time of this sample, seconds.

    Returns:
        Goodput over the interval, bits/second.
    """
    elapsed_seconds = sample_time - previous_time
    acked_bytes = bytes_acked - previous_bytes_acked
    return acked_bytes * 8 / elapsed_seconds


# ---------------------------------------------------------------------------
# Low-level control-connection helpers
# ---------------------------------------------------------------------------

class IperfError(Exception):
    """A test against one server failed (timeout, busy, rejected, or cut off).

    The caller should log the message and try a different server.
    """


class ServerBusyError(IperfError):
    """The server answered ACCESS_DENIED because another test is running.

    A separate class because the fix differs: hosts that list a port range
    run one iperf3 server per port, so another port on the same host may be
    free, whereas other failures mean the whole host should be skipped.
    """


def recv_exact(sock, num_bytes):
    """Receive exactly num_bytes from sock.

    socket.recv() may return fewer bytes than requested, so we loop until we
    have all of them.

    Args:
        sock: a connected socket (blocking, possibly with a timeout).
        num_bytes: number of bytes to read.

    Returns:
        The received bytes (length num_bytes).

    Raises:
        IperfError: the server closed the connection before sending
            num_bytes (premature termination).
        TimeoutError: the socket timeout expired (handled by run_experiment).
    """
    data = b""
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if chunk == b"":
            # Premature termination: recv() returns empty bytes on EOF.
            raise IperfError(
                f"server closed the connection (got {len(data)} of {num_bytes} bytes)"
            )
        data += chunk
    return data


def read_state(sock):
    """Read one state code (a single signed byte) from the control socket.

    Args:
        sock: the control socket.

    Returns:
        The state code as an int (may be negative, e.g. ACCESS_DENIED).
    """
    state_byte = recv_exact(sock, 1)
    (state,) = struct.unpack("b", state_byte)  # "b" = signed char
    return state


def send_state(sock, state):
    """Send one state code (a single signed byte) on the control socket.

    Args:
        sock: the control socket.
        state: one of the state constants above.
    """
    sock.sendall(struct.pack("b", state))


def send_json(sock, obj):
    """Send obj as JSON, prefixed by its length.

    iperf3 frames every JSON message as a 4-byte unsigned length in network
    (big-endian) byte order, followed by that many bytes of JSON text
    (JSON_write in iperf_api.c).

    Args:
        sock: the control socket.
        obj: a JSON-serializable dict.
    """
    payload = json.dumps(obj).encode("utf-8")
    length_prefix = struct.pack("!I", len(payload))  # "!I" = big-endian uint32
    sock.sendall(length_prefix + payload)


def recv_json(sock):
    """Receive one length-prefixed JSON message (see send_json).

    Args:
        sock: the control socket.

    Returns:
        The decoded JSON object (a dict).

    Raises:
        IperfError: the length is implausibly large, the connection closed,
            or the JSON is not an object.
        json.JSONDecodeError: the payload was not valid JSON (handled by
            run_experiment).
        UnicodeDecodeError: the payload was not valid UTF-8 (handled by
            run_experiment).
    """
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_JSON_SIZE:
        # Broken or non-iperf3 server; do not try to allocate this much.
        raise IperfError(f"server sent a {length}-byte JSON message, refusing")
    payload = recv_exact(sock, length)
    message = json.loads(payload.decode("utf-8"))

    # Every iperf3 JSON message is an object. Anything else (a list, a bare
    # number) means a broken server, and callers that look up keys in the
    # message would crash on it.
    if not isinstance(message, dict):
        raise IperfError("server sent JSON that is not an object")
    return message


def raise_for_unexpected_state(sock, state, context):
    """Raise an IperfError describing a state we did not expect.

    Args:
        sock: the control socket (used to read SERVER_ERROR details).
        state: the state code the server sent.
        context: short description of what we were waiting for, used in
            the error message.

    Raises:
        IperfError: always.
    """
    if state == ACCESS_DENIED:
        # Busy server: iperf3 servers run one test at a time and send
        # ACCESS_DENIED to any other client. Caller should try another port
        # or another server.
        raise ServerBusyError(f"server busy (ACCESS_DENIED) while {context}")

    if state == SERVER_ERROR:
        # Rejected negotiation or server-side failure. The server follows
        # SERVER_ERROR with two big-endian 32-bit ints: its internal iperf3
        # error code (i_errno, see iperf_error.c) and the C errno.
        try:
            i_errno, errno_value = struct.unpack("!ii", recv_exact(sock, 8))
        except (IperfError, OSError):
            raise IperfError(f"server error while {context} (no details sent)")
        raise IperfError(
            f"server error while {context}: iperf3 error {i_errno}, errno {errno_value}"
        )

    if state == SERVER_TERMINATE:
        # The server aborted the test (e.g. it was shut down or hit a limit).
        raise IperfError(f"server terminated the test while {context}")

    # Anything else means the server does not follow the protocol we expect.
    state_name = STATE_NAMES.get(state, "unknown")
    raise IperfError(f"unexpected state {state} ({state_name}) while {context}")


def expect_state(sock, expected_state):
    """Read one state code and raise unless it equals expected_state.

    Args:
        sock: the control socket.
        expected_state: the state code the protocol requires next.

    Raises:
        IperfError: the server sent something else (see
            raise_for_unexpected_state) or closed the connection.
    """
    state = read_state(sock)
    if state != expected_state:
        raise_for_unexpected_state(sock, state, f"waiting for {STATE_NAMES[expected_state]}")


# ---------------------------------------------------------------------------
# Protocol phases (one function per step of the sequence in the docstring)
# ---------------------------------------------------------------------------

def connect_control(host, port, timeout):
    """Step 1: open the control connection and send the cookie.

    Args:
        host: server hostname or IP address.
        port: server TCP port.
        timeout: seconds to wait for the connection and for every later
            read on this socket.

    Returns:
        (control_sock, cookie): the connected socket and the cookie bytes,
        which must be sent again on the data connection.
    """
    control_sock = socket.create_connection((host, port), timeout=timeout)

    # 36 random characters plus a NUL terminator, as iperf3's make_cookie().
    random_part = "".join(random.choices(COOKIE_CHARACTERS, k=COOKIE_SIZE - 1))
    cookie = random_part.encode("ascii") + b"\0"
    control_sock.sendall(cookie)
    return control_sock, cookie


def exchange_params(control_sock, duration):
    """Steps 2-4: send test parameters and wait for the server to accept them.

    Args:
        control_sock: the control socket.
        duration: test length, whole seconds.

    Raises:
        IperfError: the server was busy, rejected the parameters, or
            sent something unexpected.
    """
    expect_state(control_sock, PARAM_EXCHANGE)

    # Same keys the real iperf3 client sends for a basic TCP test
    # (send_parameters in iperf_api.c). Keys we omit take server defaults.
    params = {
        "tcp": True,              # TCP test (not UDP/SCTP)
        "omit": 0,                # do not discard any initial seconds
        "time": duration,         # test length, seconds
        "num": 0,                 # 0 = run by time, not by byte count
        "blockcount": 0,          # 0 = run by time, not by block count
        "parallel": 1,            # one data stream
        "len": BLOCK_SIZE,        # block size, bytes
        "pacing_timer": 1000,     # iperf3 default, microseconds
        "client_version": CLIENT_VERSION,
    }
    send_json(control_sock, params)

    # CREATE_STREAMS means the server accepted our parameters.
    expect_state(control_sock, CREATE_STREAMS)


def open_data_stream(control_sock, cookie, congestion, timeout):
    """Step 5: open the data connection with the chosen congestion control.

    Args:
        control_sock: the control socket (we connect the data socket to the
            same server IP address and port).
        cookie: the cookie sent on the control connection.
        congestion: congestion control name (e.g. "cubic", "reno", "bbr"),
            or None to use the kernel default.
        timeout: seconds to wait for the connection.

    Returns:
        (data_sock, congestion_used): the connected data socket and the
        congestion control algorithm the kernel actually applied.

    Raises:
        ValueError: the requested algorithm is not available on this kernel.
            This is a host problem, so it is not an IperfError: trying other
            servers would not help.
    """
    # Reuse the exact address the control socket connected to, so both
    # connections reach the same server even if the hostname has several IPs.
    server_address = control_sock.getpeername()
    data_sock = socket.socket(control_sock.family, socket.SOCK_STREAM)
    data_sock.settimeout(timeout)

    if congestion is not None:
        # Must be set before connect(): the algorithm governs the connection
        # from its very first packets, including slow start.
        try:
            data_sock.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_CONGESTION, congestion.encode("ascii")
            )
        except OSError as error:
            data_sock.close()
            raise ValueError(
                f"congestion control {congestion!r} is not available on this kernel "
                "(check /proc/sys/net/ipv4/tcp_available_congestion_control)"
            ) from error

    data_sock.connect(server_address)

    # The cookie tells the server this connection belongs to our test.
    data_sock.sendall(cookie)

    # Read back what the kernel is actually using; the name comes back
    # NUL-padded to TCP_CA_NAME_MAX bytes.
    raw_name = data_sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, TCP_CA_NAME_MAX)
    congestion_used = raw_name.split(b"\0")[0].decode("ascii")
    return data_sock, congestion_used


def wait_for_test_running(control_sock):
    """Step 6: wait for TEST_START followed by TEST_RUNNING.

    Args:
        control_sock: the control socket.

    Raises:
        IperfError: the server sent anything else or closed the connection.
    """
    expect_state(control_sock, TEST_START)
    expect_state(control_sock, TEST_RUNNING)


def take_sample(data_sock, start_time, previous_sample):
    """Read TCP_INFO from the data socket and build one measurement sample.

    Args:
        data_sock: the data socket.
        start_time: time.monotonic() value when sending started, seconds.
        previous_sample: the previous sample dict, or None for the first one.

    Returns:
        Dict with every tcp_info field plus:
            "t": seconds since sending started,
            "unix_time": wall-clock timestamp, seconds since the epoch,
            "goodput_bps": goodput since the previous sample, bits/second,
            "retrans_segs_interval": segments retransmitted since the
                previous sample (the loss proxy, see below).
        Both interval values are None for the first sample, which has no
        previous one.

    Loss proxy: TCP never learns for sure that a packet was lost, only
    that it retransmitted one, so retransmissions stand in for loss. We
    use the change in the cumulative tcpi_total_retrans counter, the same
    way goodput uses the change in tcpi_bytes_acked, so every
    retransmission in the interval is counted once. The other loss-related
    fields are snapshots that would miss events between samples:
    tcpi_retransmits resets to 0 on every new ACK, and tcpi_lost counts
    only segments presumed lost at the moment of the sample.
    """
    info = read_tcp_info(data_sock)
    # Timestamp taken right after getsockopt so it matches the counters.
    now = time.monotonic()

    sample = {
        "t": now - start_time,
        "unix_time": time.time(),
    }
    sample.update(info)

    if previous_sample is None:
        sample["goodput_bps"] = None
        sample["retrans_segs_interval"] = None
    else:
        sample["goodput_bps"] = compute_goodput_bps(
            previous_sample["bytes_acked"],
            previous_sample["t"],
            sample["bytes_acked"],
            sample["t"],
        )
        sample["retrans_segs_interval"] = (
            sample["total_retrans"] - previous_sample["total_retrans"]
        )
    return sample


def handle_control_message_during_test(control_sock):
    """React to the server speaking on the control socket mid-test.

    During TEST_RUNNING a well-behaved server sends nothing. If the control
    socket becomes readable, the server either closed the connection or is
    aborting the test; both are premature termination.

    Raises:
        IperfError: always.
    """
    state = read_state(control_sock)  # raises IperfError on EOF
    raise_for_unexpected_state(control_sock, state, "sending data")


def send_and_sample(control_sock, data_sock, duration, interval):
    """Step 7: send data for `duration` seconds, sampling every `interval`.

    The data socket is switched to non-blocking mode and we use select() to
    wait until either it can accept more data, the control socket has a
    message, or the next sample is due. A blocking send() could stall for a
    long time when the send buffer is full, which would make samples late.

    Args:
        control_sock: the control socket (watched for early termination).
        data_sock: the data socket.
        duration: how long to send, seconds.
        interval: time between samples, seconds.

    Returns:
        (samples, bytes_sent): list of sample dicts (see take_sample), the
        first taken at t=0 and the last at t=duration; and the total bytes
        handed to send(), bytes.

    Raises:
        IperfError: the server ended the test early.
        OSError: the data connection failed (handled by run_experiment).
    """
    # Payload content does not matter to the server; zeros are fine.
    payload = bytes(BLOCK_SIZE)
    data_sock.setblocking(False)

    bytes_sent = 0
    start_time = time.monotonic()
    end_time = start_time + duration

    # Baseline sample at t=0 so the first interval has a starting point.
    samples = [take_sample(data_sock, start_time, None)]

    # Sample k is due at start_time + k * interval. Computing it from k
    # (instead of adding interval repeatedly) avoids accumulating drift.
    # The final sample is clamped to end_time, so the last interval may be
    # shorter if duration is not a multiple of interval.
    sample_index = 1
    next_sample_time = min(start_time + sample_index * interval, end_time)

    while True:
        wait_seconds = max(0.0, next_sample_time - time.monotonic())
        readable, writable, _ = select.select([control_sock], [data_sock], [], wait_seconds)

        if readable:
            handle_control_message_during_test(control_sock)

        if writable:
            try:
                # send() may accept only part of the payload; that is fine
                # because the data is arbitrary and TCP is a byte stream.
                bytes_sent += data_sock.send(payload)
            except BlockingIOError:
                # Buffer filled between select() and send(); try again.
                pass

        if time.monotonic() >= next_sample_time:
            samples.append(take_sample(data_sock, start_time, samples[-1]))
            if next_sample_time >= end_time:
                break  # that was the final sample at end_time
            sample_index += 1
            next_sample_time = min(start_time + sample_index * interval, end_time)

    return samples, bytes_sent


def exchange_results(control_sock, bytes_sent, samples):
    """Steps 8-9: end the test and swap results JSON with the server.

    Args:
        control_sock: the control socket.
        bytes_sent: total bytes we sent on the data socket.
        samples: the samples from send_and_sample (the last one supplies
            the retransmit count and elapsed time).

    Returns:
        The server's results dict (includes the bytes it received).

    Raises:
        IperfError: the server did not move to EXCHANGE_RESULTS.
    """
    send_state(control_sock, TEST_END)
    expect_state(control_sock, EXCHANGE_RESULTS)

    final_sample = samples[-1]

    # The server's get_results() (iperf_api.c) rejects the message unless
    # all of the cpu_util_* keys, sender_has_retransmits, and per-stream
    # id/bytes/retransmits/jitter/errors/packets keys are present.
    client_results = {
        "cpu_util_total": 0,           # we do not measure CPU usage
        "cpu_util_user": 0,
        "cpu_util_system": 0,
        "sender_has_retransmits": 1,   # we report retransmits below
        "streams": [
            {
                "id": 1,               # iperf3 numbers the first stream 1
                "bytes": bytes_sent,
                "retransmits": final_sample["total_retrans"],
                "jitter": 0,           # UDP-only fields, zero for TCP
                "errors": 0,
                "packets": 0,
                "start_time": 0,
                "end_time": final_sample["t"],
            }
        ],
    }
    send_json(control_sock, client_results)
    return recv_json(control_sock)


def finish_test(control_sock):
    """Step 10: wait for DISPLAY_RESULTS and acknowledge with IPERF_DONE.

    Args:
        control_sock: the control socket.

    Raises:
        IperfError: the server sent something other than DISPLAY_RESULTS.
    """
    expect_state(control_sock, DISPLAY_RESULTS)
    send_state(control_sock, IPERF_DONE)


# ---------------------------------------------------------------------------
# Public entry point for one experiment
# ---------------------------------------------------------------------------

def run_experiment(host, port, duration=60, interval=1.0, congestion=None,
                   timeout=DEFAULT_TIMEOUT):
    """Run one iperf3 TCP upload test against host:port and sample TCP stats.

    Args:
        host: iperf3 server hostname or IP address.
        port: iperf3 server TCP port.
        duration: how long to send data, whole seconds.
        interval: time between TCP_INFO samples, seconds.
        congestion: congestion control algorithm for the data socket
            ("cubic", "reno", "bbr", ...), or None for the kernel default.
        timeout: seconds to wait for a connection or any control message
            before treating the server as unresponsive.

    Returns:
        Dict with:
            "host", "port": the server tested,
            "server_ip": IP address the host resolved to,
            "congestion": algorithm the kernel actually used,
            "bytes_sent": total bytes handed to send(), bytes,
            "samples": list of samples (see take_sample),
            "server_results": the server's results JSON.

    Raises:
        IperfError: the test failed because of the server or the network
            (unresponsive, busy, rejected parameters, connection cut off).
            The caller should log it and try another server. A busy server
            raises the subclass ServerBusyError.
        ValueError: the requested congestion control is not available.
        RuntimeError: the kernel's tcp_info is too old to decode.
    """
    duration = int(duration)  # iperf3's "time" parameter is an integer
    control_sock = None
    data_sock = None
    finished = False

    try:
        control_sock, cookie = connect_control(host, port, timeout)
        # Record the IP address the hostname resolved to, for the report.
        server_ip = control_sock.getpeername()[0]
        exchange_params(control_sock, duration)
        data_sock, congestion_used = open_data_stream(control_sock, cookie, congestion, timeout)
        wait_for_test_running(control_sock)
        samples, bytes_sent = send_and_sample(control_sock, data_sock, duration, interval)
        server_results = exchange_results(control_sock, bytes_sent, samples)
        finish_test(control_sock)
        finished = True

    # Unresponsive or overloaded server: a connect or control read timed out.
    # (socket.timeout is an alias of TimeoutError since Python 3.10.)
    except TimeoutError as error:
        raise IperfError(f"timed out after {timeout} s (server unresponsive)") from error

    # Server sent bytes that are not valid UTF-8 JSON: not a compatible
    # iperf3 server. We list these two ValueError subclasses explicitly
    # instead of catching ValueError, because open_data_stream raises a plain
    # ValueError for an unavailable algorithm, which must reach the caller.
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise IperfError(f"server sent invalid JSON: {error}") from error

    # Connection refused, reset, DNS failure, broken pipe, ...: covers
    # unreachable servers and premature termination of either connection.
    except OSError as error:
        raise IperfError(f"socket error: {error}") from error

    finally:
        if control_sock is not None and not finished:
            # Best effort: tell the server we are aborting so it frees itself
            # for the next client sooner. Ignore failures; the connection
            # may already be gone.
            try:
                send_state(control_sock, CLIENT_TERMINATE)
            except OSError:
                pass
        if data_sock is not None:
            data_sock.close()
        if control_sock is not None:
            control_sock.close()

    return {
        "host": host,
        "port": port,
        "server_ip": server_ip,
        "congestion": congestion_used,
        "bytes_sent": bytes_sent,
        "samples": samples,
        "server_results": server_results,
    }


# ---------------------------------------------------------------------------
# Self-check (runs on any OS; does not open sockets)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Build a fake tcp_info buffer where each field's value is its index,
    # then overwrite a few fields with recognizable values.
    fake_values = []
    for index in range(len(TCP_INFO_FIELDS)):
        fake_values.append(index)
    field_names = []
    for name, _code, _unit in TCP_INFO_FIELDS:
        field_names.append(name)
    fake_values[field_names.index("snd_cwnd")] = 10
    fake_values[field_names.index("rtt")] = 25_000
    fake_values[field_names.index("bytes_acked")] = 2**40  # needs all 64 bits

    # Kernel returns a longer struct than we decode; append padding to check
    # that extra trailing bytes are ignored.
    fake_raw = struct.pack(TCP_INFO_FORMAT, *fake_values) + bytes(24)
    decoded = decode_tcp_info(fake_raw)
    assert TCP_INFO_SIZE == 232, TCP_INFO_SIZE
    assert decoded["snd_cwnd"] == 10
    assert decoded["rtt"] == 25_000
    assert decoded["bytes_acked"] == 2**40
    assert decoded["delivery_rate"] == field_names.index("delivery_rate")
    assert decoded["snd_wnd"] == field_names.index("snd_wnd")

    # Too-short buffer (old kernel) must be rejected.
    try:
        decode_tcp_info(bytes(100))
        raise AssertionError("short tcp_info was accepted")
    except RuntimeError:
        pass

    # 1,250,000 bytes acked in 0.5 s = 2,500,000 bytes/s = 20,000,000 bits/s.
    assert compute_goodput_bps(1_000_000, 1.0, 2_250_000, 1.5) == 20_000_000

    # JSON framing over a local socket pair (no network): a dict round-trips,
    # and JSON that is not an object is rejected.
    sender, receiver = socket.socketpair()
    send_json(sender, {"time": 10})
    assert recv_json(receiver) == {"time": 10}
    send_json(sender, [1])
    try:
        recv_json(receiver)
        raise AssertionError("non-object JSON was accepted")
    except IperfError:
        pass
    sender.close()
    receiver.close()

    print("self-check passed")
