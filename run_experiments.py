"""Single entry point: run the full iperf3 measurement campaign and report.

Pipeline:

    1. Check that every requested congestion control algorithm can be set
       on this kernel (fail fast, before minutes of probing).
    2. Load the server list and pick n working destinations
       (destinations.py, Part 1b).
    3. For each repetition, each destination, and each algorithm, run one
       iperf3 upload test (iperf3_client.py, Part 1a) that samples TCP_INFO
       from the data socket every --interval seconds (Part 1c / 2a).
    4. Save every sample to samples.csv and the run details to
       metadata.json in the results directory.
    5. Build the goodput summary table and plots (report.py, Parts 1c
       and 2b).

Usage:

    python3 run_experiments.py listed_iperf3_servers.csv -n 10 --duration 60 \\
        --interval 1 --repetitions 3 --algorithms cubic reno bbr
    python3 run_experiments.py --report-only results/<timestamp>

Linux only (TCP_INFO and TCP_CONGESTION). Run with --help for all options.
"""

import argparse
import csv
import json
import logging
import os
import platform
import socket
import sys
import time

import destinations
import iperf3_client
import report


logger = logging.getLogger("run_experiments")

# How many times to try one (destination, algorithm) test before recording
# it as failed. Public servers are often busy for a while with another
# client, so one retry is not always enough.
MAX_TRIES_PER_RUN = 3

# Seconds to wait between tries of the same test. Other clients' tests
# usually last 10 s (iperf3's default), so this gives them time to finish.
RETRY_WAIT_SECONDS = 10

# Seconds to wait before every test. Many public iperf3 servers restart
# their iperf3 process after each test and refuse connections for a few
# seconds while doing so; a test started right after the previous one (or
# right after the selection probe) on the same server then fails its first
# try. Observed in testing: an immediate follow-up test got "Connection
# refused", while one started about 3 s later succeeded.
PAUSE_BETWEEN_RUNS_SECONDS = 3

# Defaults for the command-line options (see parse_args for meanings).
DEFAULT_DESTINATIONS = 10
DEFAULT_DURATION_SECONDS = 60
DEFAULT_INTERVAL_SECONDS = 1.0
DEFAULT_REPETITIONS = 1
DEFAULT_ALGORITHMS = ["cubic", "reno", "bbr"]
DEFAULT_RESULTS_ROOT = "results"

METADATA_FILE = "metadata.json"

# Buffer size for measuring the kernel's struct tcp_info length; larger than
# any kernel's struct (under 300 bytes in current kernels).
KERNEL_TCP_INFO_PROBE_BYTES = 1024

# Columns of samples.csv that describe which run a sample belongs to. Each
# sample row also has every key of a take_sample() dict (see
# sample_csv_columns).
RUN_COLUMNS = [
    "run_id",               # execution order of the run, starting at 1
    "repetition",           # repetition number, starting at 1
    "host",                 # server hostname from the server list
    "port",                 # server port that was tested
    "server_ip",            # IP address the hostname resolved to
    "algorithm_requested",  # congestion control we asked for
    "algorithm_used",       # congestion control the kernel reported back
]


def sample_csv_columns():
    """List the columns of samples.csv, in order.

    Returns:
        RUN_COLUMNS, then the timing and interval columns added by
        iperf3_client.take_sample, then every TCP_INFO field.
    """
    columns = list(RUN_COLUMNS)
    columns.extend(["t", "unix_time", "goodput_bps", "retrans_segs_interval"])
    for name, _code, _unit in iperf3_client.TCP_INFO_FIELDS:
        columns.append(name)
    return columns


def measurement_units():
    """Map each measured column of samples.csv to its unit.

    Saved in metadata.json so the raw data documents its own units.

    Returns:
        Dict of column name to unit string.
    """
    units = {
        "t": "seconds since the start of sending",
        "unix_time": "seconds since the Unix epoch",
        "goodput_bps": "bits/second, over the interval ending at t",
        "retrans_segs_interval": "segments retransmitted during the interval ending at t",
    }
    for name, _code, unit in iperf3_client.TCP_INFO_FIELDS:
        units[name] = unit
    return units


def parse_args():
    """Parse and validate the command line.

    Returns:
        argparse.Namespace with the options below.

    Exits (via parser.error) on invalid values.
    """
    parser = argparse.ArgumentParser(
        description="Run iperf3 upload tests against public servers with several "
                    "TCP congestion control algorithms, sample TCP_INFO, and build "
                    "goodput summaries and plots.",
    )
    parser.add_argument(
        "server_list", nargs="?",
        help="CSV server list (IP/HOST,PORT,... as on iperf3serverlist.net)",
    )
    parser.add_argument(
        "-n", "--destinations", type=int, default=DEFAULT_DESTINATIONS,
        help=f"number of destination servers (default {DEFAULT_DESTINATIONS})",
    )
    parser.add_argument(
        "--duration", type=int, default=DEFAULT_DURATION_SECONDS,
        help=f"seconds of sending per test (default {DEFAULT_DURATION_SECONDS})",
    )
    parser.add_argument(
        "--interval", type=float, default=DEFAULT_INTERVAL_SECONDS,
        help=f"seconds between TCP_INFO samples (default {DEFAULT_INTERVAL_SECONDS})",
    )
    parser.add_argument(
        "--repetitions", type=int, default=DEFAULT_REPETITIONS,
        help=f"tests per destination per algorithm (default {DEFAULT_REPETITIONS})",
    )
    parser.add_argument(
        "--algorithms", nargs="+", default=DEFAULT_ALGORITHMS,
        help=f"congestion control algorithms to test (default {' '.join(DEFAULT_ALGORITHMS)})",
    )
    parser.add_argument(
        "--output",
        help=f"results directory (default {DEFAULT_RESULTS_ROOT}/<YYYYmmdd-HHMMSS>)",
    )
    parser.add_argument(
        "--seed", type=int,
        help="random seed for destination selection order (default: random)",
    )
    parser.add_argument(
        "--representative", metavar="HOST:PORT",
        help="destination for the TCP stats plots (default: picked automatically, "
             "see report.choose_representative_destination)",
    )
    parser.add_argument(
        "--report-only", metavar="RESULTS_DIR",
        help="skip the experiments; rebuild the summary and plots from an existing results directory",
    )
    args = parser.parse_args()

    # Bad values would otherwise surface much later as confusing errors.
    if args.report_only is None and args.server_list is None:
        parser.error("server_list is required unless --report-only is given")
    if args.destinations < 1:
        parser.error("--destinations must be at least 1")
    if args.duration < 1:
        parser.error("--duration must be at least 1 second")
    if args.interval <= 0:
        parser.error("--interval must be positive")
    if args.repetitions < 1:
        parser.error("--repetitions must be at least 1")
    if args.representative is not None:
        args.representative = parse_destination(parser, args.representative)
    return args


def parse_destination(parser, text):
    """Split a "HOST:PORT" command-line value into (host, port).

    rpartition splits at the last colon, so the host part may itself
    contain colons (an IPv6 address).

    Args:
        parser: the ArgumentParser, used to report a bad value.
        text: the value as typed, e.g. "iperf.example.net:5201".

    Returns:
        (host, port) with port as an int.

    Exits (via parser.error) if text is not HOST:PORT with a numeric port.
    """
    host, _colon, port = text.rpartition(":")
    if host == "" or not port.isdigit():
        parser.error(f"--representative must be HOST:PORT, got {text!r}")
    return host, int(port)


def find_unavailable_algorithms(algorithms):
    """Return the congestion control algorithms this host cannot use.

    Setting TCP_CONGESTION on a throwaway (unconnected) socket fails with
    an OSError if the algorithm's kernel module is not loaded (common for
    bbr), or if the process is unprivileged and the algorithm is not in
    /proc/sys/net/ipv4/tcp_allowed_congestion_control.

    Args:
        algorithms: list of algorithm names, e.g. ["cubic", "reno", "bbr"].

    Returns:
        List of the names that could not be set (empty if all are fine).
    """
    unavailable = []
    for algorithm in algorithms:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION,
                                 algorithm.encode("ascii"))
        except OSError:
            unavailable.append(algorithm)
        finally:
            test_sock.close()
    return unavailable


def read_kernel_tcp_settings():
    """Read the host kernel's TCP settings that matter for the measurements.

    Together with the kernel version, these document what the decoding in
    iperf3_client.TCP_INFO_FIELDS ran against: the kernel's struct
    tcp_info may be longer than the TCP_INFO_SIZE-byte prefix we decode
    (newer kernels append fields), but never shorter.

    Returns:
        Dict with:
            "default_congestion_control": algorithm sockets get when they
                do not ask for one (Part 2 uses this, normally cubic),
            "available_congestion_control": algorithms the kernel has loaded,
            "tcp_info_kernel_size_bytes": length of struct tcp_info this
                kernel returns. getsockopt(TCP_INFO) works on an unconnected
                socket, so a throwaway one is enough.
    """
    with open("/proc/sys/net/ipv4/tcp_congestion_control", encoding="ascii") as file:
        default_algorithm = file.read().strip()
    with open("/proc/sys/net/ipv4/tcp_available_congestion_control", encoding="ascii") as file:
        available_algorithms = file.read().split()

    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Ask for more than any kernel returns; the reply's length is the
        # kernel's struct size.
        raw = test_sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO,
                                   KERNEL_TCP_INFO_PROBE_BYTES)
    finally:
        test_sock.close()

    return {
        "default_congestion_control": default_algorithm,
        "available_congestion_control": available_algorithms,
        "tcp_info_kernel_size_bytes": len(raw),
    }


def run_with_retries(destination, algorithm, duration, interval):
    """Run one test, retrying the same destination if it fails.

    We retry the same server instead of replacing it because every
    algorithm must be measured over the same destinations (Part 3);
    replacements already happened during destination selection.

    Args:
        destination: dict from destinations.select_destinations
            (needs "host" and "port").
        algorithm: congestion control name for the data socket.
        duration: seconds of sending.
        interval: seconds between samples.

    Returns:
        (result, errors): result is run_experiment's dict, or None if every
        try failed; errors lists the failure message of each failed try.
    """
    errors = []
    for attempt in range(1, MAX_TRIES_PER_RUN + 1):
        try:
            result = iperf3_client.run_experiment(
                destination["host"], destination["port"],
                duration=duration, interval=interval, congestion=algorithm,
            )
            return result, errors
        except iperf3_client.IperfError as error:
            # Busy, unresponsive, rejected, or cut off (see run_experiment).
            logger.warning("try %d/%d of %s:%d (%s) failed: %s",
                           attempt, MAX_TRIES_PER_RUN, destination["host"],
                           destination["port"], algorithm, error)
            errors.append(str(error))
            if attempt < MAX_TRIES_PER_RUN:
                time.sleep(RETRY_WAIT_SECONDS)
    return None, errors


def server_bytes_received(server_results):
    """Extract the bytes the server says it received from its results JSON.

    Args:
        server_results: the server's results dict from run_experiment. Its
            "streams" list has one entry per data stream with a "bytes" key.

    Returns:
        Bytes received on our one stream, or None if the server omitted it.
    """
    streams = server_results.get("streams", [])
    if not streams:
        return None
    return streams[0].get("bytes")


def write_samples(writer, csv_file, run_columns, result):
    """Append one CSV row per sample of a finished run, then flush.

    Flushing after each run means a crash or Ctrl-C mid-campaign keeps
    every run that already finished.

    Args:
        writer: csv.DictWriter for samples.csv.
        csv_file: the open samples.csv file (flushed here).
        run_columns: dict with the RUN_COLUMNS values for this run.
        result: run_experiment's result dict.
    """
    for sample in result["samples"]:
        row = dict(run_columns)
        row.update(sample)
        writer.writerow(row)
    csv_file.flush()


def run_all(destination_list, args, writer, csv_file, runs):
    """Run every (repetition, destination, algorithm) test and save samples.

    Test order: for each repetition, for each destination, run every
    algorithm back to back. Running the algorithms close together on the
    same path limits how much changing network conditions (time of day,
    cross traffic) bias the comparison between them.

    Args:
        destination_list: dicts from destinations.select_destinations.
        args: parsed command line (duration, interval, repetitions,
            algorithms).
        writer, csv_file: samples.csv writer and file (see write_samples).
        runs: list that one record per run is appended to. The caller
            passes it in (instead of receiving a return value) so records
            of finished runs survive an exception or Ctrl-C.
    """
    total_runs = args.repetitions * len(destination_list) * len(args.algorithms)
    run_id = 0

    for repetition in range(1, args.repetitions + 1):
        for destination in destination_list:
            for algorithm in args.algorithms:
                run_id += 1
                logger.info("run %d/%d: repetition %d, %s:%d, %s",
                            run_id, total_runs, repetition,
                            destination["host"], destination["port"], algorithm)

                # Give the server time to restart after the previous test
                # (see PAUSE_BETWEEN_RUNS_SECONDS). Also applies to the first
                # run, which follows the selection probe on the same server.
                time.sleep(PAUSE_BETWEEN_RUNS_SECONDS)

                result, errors = run_with_retries(destination, algorithm,
                                                  args.duration, args.interval)
                record = {
                    "run_id": run_id,
                    "repetition": repetition,
                    "host": destination["host"],
                    "port": destination["port"],
                    "algorithm_requested": algorithm,
                    "errors": errors,
                }

                if result is None:
                    # Every try failed: keep the record (shows up in the
                    # report as a missing run) but there are no samples.
                    record["status"] = "failed"
                    runs.append(record)
                    continue

                if result["congestion"] != algorithm:
                    logger.warning("asked for %s but kernel used %s",
                                   algorithm, result["congestion"])

                first_sample = result["samples"][0]
                final_sample = result["samples"][-1]
                record.update({
                    "status": "ok",
                    "server_ip": result["server_ip"],
                    "algorithm_used": result["congestion"],
                    "start_unix_time": first_sample["unix_time"],
                    # Bytes our client handed to send(). Not the same as the
                    # tcp_info column bytes_sent, which is what the kernel put
                    # on the wire and so also counts retransmissions.
                    "app_bytes_sent": result["bytes_sent"],
                    "bytes_acked": final_sample["bytes_acked"],
                    "server_bytes_received": server_bytes_received(result["server_results"]),
                    "total_retrans": final_sample["total_retrans"],
                })
                runs.append(record)

                run_columns = {
                    "run_id": run_id,
                    "repetition": repetition,
                    "host": destination["host"],
                    "port": destination["port"],
                    "server_ip": result["server_ip"],
                    "algorithm_requested": algorithm,
                    "algorithm_used": result["congestion"],
                }
                write_samples(writer, csv_file, run_columns, result)


def destinations_without_data(selected, runs):
    """List the selected destinations where every run failed.

    This is the shortfall that happens after selection: a server can pass
    the short selection probe and then fail every real test (for example,
    it went offline or limits longer tests). It is not replaced, because
    every algorithm must be measured over the same destinations (see
    run_with_retries), so it is reported instead.

    Args:
        selected: dicts from destinations.select_destinations.
        runs: per-run records from run_all.

    Returns:
        List of {"host", "port"} dicts, one per selected destination with
        no run whose status is "ok". Empty if every destination has data.
    """
    destinations_with_data = set()
    for run in runs:
        if run["status"] == "ok":
            destinations_with_data.add((run["host"], run["port"]))

    missing = []
    for destination in selected:
        if (destination["host"], destination["port"]) not in destinations_with_data:
            missing.append({"host": destination["host"], "port": destination["port"]})
    return missing


def write_metadata(path, args, kernel_settings, selected, selection_failures, runs):
    """Write metadata.json describing the campaign.

    Args:
        path: file to write.
        args: parsed command line.
        kernel_settings: dict from read_kernel_tcp_settings.
        selected, selection_failures: from destinations.select_destinations.
        runs: per-run records from run_all.
    """
    failed_runs = 0
    for run in runs:
        if run["status"] != "ok":
            failed_runs += 1

    missing_destinations = destinations_without_data(selected, runs)
    effective_destinations = len(selected) - len(missing_destinations)

    metadata = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "arguments": vars(args),
        # TCP behavior and the tcp_info layout depend on the host kernel.
        "host_kernel": platform.release(),
        "host_platform": platform.platform(),
        "kernel_tcp_settings": kernel_settings,
        "tcp_info_format": iperf3_client.TCP_INFO_FORMAT,
        "tcp_info_size_bytes": iperf3_client.TCP_INFO_SIZE,
        "units": measurement_units(),
        "requested_destinations": args.destinations,
        # Shortfall at selection time: too few servers passed the probe.
        "destination_shortfall": args.destinations - len(selected),
        # Shortfall in the final data: also counts selected destinations
        # whose every run failed.
        "effective_destinations": effective_destinations,
        "effective_destination_shortfall": args.destinations - effective_destinations,
        "destinations_without_data": missing_destinations,
        "destinations": selected,
        "selection_failures": selection_failures,
        "test_order": "for each repetition: for each destination: for each algorithm",
        "failed_runs": failed_runs,
        "runs": runs,
    }
    with open(path, "w", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)


def main():
    """Run the whole pipeline (see the module docstring)."""
    args = parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if args.report_only is not None:
        report.generate_report(args.report_only, args.representative)
        return

    # TCP_CONGESTION only exists in Python's socket module on Linux.
    if not hasattr(socket, "TCP_CONGESTION"):
        sys.exit("error: this script needs Linux (TCP_INFO and TCP_CONGESTION)")

    unavailable = find_unavailable_algorithms(args.algorithms)
    if unavailable:
        sys.exit(
            f"error: congestion control not available: {', '.join(unavailable)}. "
            "Check /proc/sys/net/ipv4/tcp_available_congestion_control "
            "(load bbr with 'modprobe tcp_bbr') and tcp_allowed_congestion_control."
        )

    kernel_settings = read_kernel_tcp_settings()

    output_dir = args.output
    if output_dir is None:
        output_dir = os.path.join(DEFAULT_RESULTS_ROOT, time.strftime("%Y%m%d-%H%M%S"))
    samples_path = os.path.join(output_dir, report.SAMPLES_FILE)
    # Never overwrite the measurements of an earlier campaign.
    if os.path.exists(samples_path):
        sys.exit(f"error: {samples_path} already exists; choose another --output")
    os.makedirs(output_dir, exist_ok=True)
    logger.info("results directory: %s", output_dir)

    servers = destinations.load_servers(args.server_list)
    selected, selection_failures = destinations.select_destinations(
        servers, args.destinations, seed=args.seed,
    )

    runs = []
    with open(samples_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=sample_csv_columns())
        writer.writeheader()
        try:
            run_all(selected, args, writer, csv_file, runs)
        finally:
            # Written even if the campaign is interrupted, so the samples
            # that were saved still have their context and units.
            write_metadata(os.path.join(output_dir, METADATA_FILE),
                           args, kernel_settings, selected, selection_failures, runs)

    # Report the final shortfall in the terminal too, not only in
    # metadata.json (selection already warned about its own shortfall).
    effective_destinations = len(selected) - len(destinations_without_data(selected, runs))
    if effective_destinations < args.destinations:
        logger.warning("shortfall: only %d of %d requested destinations produced data",
                       effective_destinations, args.destinations)

    report.generate_report(output_dir, args.representative)


if __name__ == "__main__":
    main()
