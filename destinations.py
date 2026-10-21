"""Load the iperf3 server list and pick n working destinations (Part 1b).

Public iperf3 servers are often busy (each runs one test at a time) or
offline, so a randomly chosen server cannot be assumed to work. This module
shuffles the server list, probes candidates with a short real iperf3 test,
and keeps the first n that complete it. Every failure is logged and counted,
the total number of probes is bounded, and any shortfall versus the
requested n is reported.

Server list format (listed_iperf3_servers.csv, from iperf3serverlist.net):

    IP/HOST,PORT,GB/S,CONTINENT,COUNTRY,SITE,PROVIDER

PORT is either one port ("5201") or an inclusive range ("5201-5210"). Hosts
with a range run a separate iperf3 server on each port.
"""

import csv
import logging
import random

import iperf3_client


logger = logging.getLogger(__name__)

# Length of each probe test, seconds. Long enough to exercise the whole
# protocol (params, data, results exchange) and to outlast iperf3's
# --server-bitrate-limit averaging window (5 s by default): a rate-limited
# server aborts the test only after that window, so a shorter probe would
# pass it and every real test would then fail. Still short next to a 60 s
# test, so probing many candidates stays reasonably quick.
DEFAULT_PROBE_SECONDS = 10

# Default probe budget per requested destination. With n = 10 this allows
# 30 probes in total before giving up and reporting a shortfall.
DEFAULT_ATTEMPTS_PER_DESTINATION = 3

# How many different ports to try on one host when it answers "busy".
# Other ports on the same host may be free, but a host that is busy on
# several ports is probably heavily loaded, so we move on.
MAX_PORTS_PER_HOST = 3


def parse_ports(port_text):
    """Turn a PORT cell into a list of port numbers.

    Args:
        port_text: "5201" (single port) or "5201-5210" (inclusive range).

    Returns:
        List of ints, e.g. [5201] or [5201, 5202, ..., 5210].

    Raises:
        ValueError: the text is not a number or a valid range.
    """
    port_text = port_text.strip()

    if "-" in port_text:
        first_text, last_text = port_text.split("-")
        first_port = int(first_text)
        last_port = int(last_text)
        if first_port > last_port:
            raise ValueError(f"port range {port_text!r} is backwards")
        # range() excludes its end, so add 1 to include the last port.
        return list(range(first_port, last_port + 1))

    return [int(port_text)]


def load_servers(path):
    """Read the server-list CSV into a list of server dicts.

    Rows with an unreadable PORT cell are logged and skipped rather than
    aborting the whole run.

    Args:
        path: path to the CSV file.

    Returns:
        List of dicts with keys "host", "ports" (list of ints), "continent",
        "country", "site", "provider". The GB/S column is ignored because it
        is often blank or not a plain number (e.g. "2x10").
    """
    servers = []
    with open(path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            host = row["IP/HOST"].strip()
            try:
                ports = parse_ports(row["PORT"])
            except ValueError:
                logger.warning("skipping %s: bad PORT value %r", host, row["PORT"])
                continue

            servers.append({
                "host": host,
                "ports": ports,
                "continent": row["CONTINENT"].strip(),
                "country": row["COUNTRY"].strip(),
                "site": row["SITE"].strip(),
                "provider": row["PROVIDER"].strip(),
            })
    return servers


def select_destinations(servers, n, max_attempts=None,
                        probe_seconds=DEFAULT_PROBE_SECONDS,
                        timeout=iperf3_client.DEFAULT_TIMEOUT, seed=None):
    """Pick n random servers that successfully complete a short iperf3 test.

    Candidates are visited in random order. For each host we try up to
    MAX_PORTS_PER_HOST random ports from its range:
      - probe succeeds: keep this host and port, move to the next host;
      - server busy (ServerBusyError): try another port on the same host;
      - any other failure (timeout, refused, rejected, cut off): skip the
        rest of this host, because other ports will almost certainly fail
        the same way.
    Each probe counts as one attempt; we stop after max_attempts probes even
    if fewer than n destinations were found.

    Args:
        servers: list of server dicts from load_servers.
        n: number of destinations wanted.
        max_attempts: total probe budget. None means
            n * DEFAULT_ATTEMPTS_PER_DESTINATION.
        probe_seconds: length of each probe test, whole seconds.
        timeout: connect/control timeout per probe, seconds.
        seed: random seed, so the same selection order can be reproduced.
            None gives a different order each run.

    Returns:
        (selected, failures):
            selected: list of up to n dicts with the server's metadata plus
                "port" (the port that worked) and "server_ip" (resolved IP).
            failures: list of dicts with "host", "port", and "reason" for
                every failed probe, for the report.
    """
    if max_attempts is None:
        max_attempts = n * DEFAULT_ATTEMPTS_PER_DESTINATION

    rng = random.Random(seed)
    candidates = list(servers)  # copy so the caller's list is not reordered
    rng.shuffle(candidates)

    selected = []
    failures = []
    attempts = 0

    for server in candidates:
        if len(selected) >= n or attempts >= max_attempts:
            break

        # Pick up to MAX_PORTS_PER_HOST distinct ports in random order.
        port_count = min(MAX_PORTS_PER_HOST, len(server["ports"]))
        ports_to_try = rng.sample(server["ports"], port_count)

        for port in ports_to_try:
            if attempts >= max_attempts:
                break
            attempts += 1
            logger.info("probe %d/%d: %s:%d", attempts, max_attempts, server["host"], port)

            try:
                result = iperf3_client.run_experiment(
                    server["host"], port,
                    duration=probe_seconds, interval=probe_seconds, timeout=timeout,
                )
            except iperf3_client.ServerBusyError as error:
                # Busy: another port on this host may be free.
                logger.warning("%s:%d failed: %s", server["host"], port, error)
                failures.append({"host": server["host"], "port": port, "reason": str(error)})
                continue
            except iperf3_client.IperfError as error:
                # Unreachable, rejected, or broken: give up on this host.
                logger.warning("%s:%d failed: %s", server["host"], port, error)
                failures.append({"host": server["host"], "port": port, "reason": str(error)})
                break

            # Probe succeeded: record this destination and go to the next host.
            selected.append({
                "host": server["host"],
                "port": port,
                "server_ip": result["server_ip"],
                "continent": server["continent"],
                "country": server["country"],
                "site": server["site"],
                "provider": server["provider"],
            })
            logger.info("selected %s:%d (%d/%d)", server["host"], port, len(selected), n)
            break

    if len(selected) < n:
        logger.warning(
            "shortfall: found %d of %d requested destinations after %d probes",
            len(selected), n, attempts,
        )
    return selected, failures


# ---------------------------------------------------------------------------
# Self-check (runs on any OS; uses a fake run_experiment, no network)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    assert parse_ports("5201") == [5201]
    assert parse_ports(" 5201-5203 ") == [5201, 5202, 5203]

    loaded = load_servers("listed_iperf3_servers.csv")
    assert len(loaded) == 185, len(loaded)

    # Fake servers: "busy" is busy on every port, "dead" times out, the
    # rest succeed. Replace run_experiment so no network is used.
    def fake_run_experiment(host, port, **_kwargs):
        if host == "busy":
            raise iperf3_client.ServerBusyError("busy")
        if host == "dead":
            raise iperf3_client.IperfError("timed out")
        return {"server_ip": "192.0.2.1"}

    iperf3_client.run_experiment = fake_run_experiment

    def fake_server(host):
        return {"host": host, "ports": [1, 2, 3, 4, 5], "continent": "",
                "country": "", "site": "", "provider": ""}

    # Busy host uses 3 probes (3 ports), dead host 1 probe, good hosts 1 each.
    fake_servers = [fake_server("busy"), fake_server("dead"),
                    fake_server("good1"), fake_server("good2")]
    picked, failed = select_destinations(fake_servers, n=2, max_attempts=10, seed=1)
    assert sorted(d["host"] for d in picked) == ["good1", "good2"]
    assert len(failed) <= MAX_PORTS_PER_HOST + 1

    # Budget too small to reach both good hosts: shortfall, no crash.
    picked, failed = select_destinations(fake_servers, n=4, max_attempts=2, seed=1)
    assert len(picked) + len(failed) == 2

    print("self-check passed")
