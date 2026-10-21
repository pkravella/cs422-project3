"""Summary table and plots for one results directory.

This is the analysis half of Parts 1(c) and 2(b). run_experiments.py saves
every TCP_INFO sample to <results dir>/samples.csv and then calls
generate_report(), which:

    1. Loads the samples from samples.csv.
    2. Computes min / median / mean / 95th-percentile goodput for each
       (destination, congestion control algorithm) pair, pooling all
       repetitions, and writes them to goodput_summary.csv and stdout.
    3. Plots goodput over time, one panel per destination, to
       goodput_over_time.pdf.
    4. Picks one representative destination and, for each algorithm,
       plots its TCP stats (cwnd, RTT, retransmissions, goodput) over time
       to tcp_timeseries_<algorithm>.pdf and against goodput to
       tcp_scatter_<algorithm>.pdf. Every algorithm's figures use the same
       axis limits so they can be compared side by side (Part 3a).

Everything is read back from the CSV rather than passed in memory, so the
table and plot can be regenerated after a long campaign without rerunning
it (run_experiments.py --report-only <results dir>).
"""

import csv
import logging
import math
import os
import statistics

import matplotlib

# "Agg" renders to files only, with no window. It must be selected before
# pyplot is imported, and it works on headless machines and in Docker.
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402 (must come after matplotlib.use)
from matplotlib.lines import Line2D  # noqa: E402


logger = logging.getLogger(__name__)

# File names inside a results directory.
SAMPLES_FILE = "samples.csv"
SUMMARY_FILE = "goodput_summary.csv"
GOODPUT_PLOT_FILE = "goodput_over_time.pdf"
# One pair per algorithm; "{algorithm}" is replaced by its name.
TIMESERIES_PLOT_FILE = "tcp_timeseries_{algorithm}.pdf"
SCATTER_PLOT_FILE = "tcp_scatter_{algorithm}.pdf"

# Goodput is stored in bits/second; tables and plots use megabits/second
# (decimal mega, as networking rates are: 1 Mbit/s = 1,000,000 bits/s).
BITS_PER_MEGABIT = 1_000_000

# tcp_info reports RTTs in microseconds; plots use milliseconds.
MICROSECONDS_PER_MILLISECOND = 1000

# TCP stats plotted for the representative destination: (sample key, axis
# label). Each is drawn over time and against goodput.
TCP_METRICS = [
    ("snd_cwnd", "cwnd (segments)"),
    ("rtt_ms", "smoothed RTT (ms)"),
    ("retrans_segs", "retransmitted segments\nper interval"),
]
GOODPUT_METRIC = ("goodput_mbps", "goodput (Mbit/s)")

# Axis tops are the largest value plotted times this, so the highest point
# does not sit on the plot border.
AXIS_HEADROOM = 1.05

# Columns of goodput_summary.csv, in order.
SUMMARY_COLUMNS = [
    "host", "port", "algorithm", "samples",
    "min_mbps", "median_mbps", "mean_mbps", "p95_mbps",
]

# Digits after the decimal point when writing Mbit/s values.
SUMMARY_DECIMALS = 3

# Plot layout: panels per row and the size of each panel, inches.
PLOT_COLUMNS = 2
PANEL_WIDTH_INCHES = 6
PANEL_HEIGHT_INCHES = 3


def load_samples(path):
    """Read the goodput samples from a samples.csv file.

    The first sample of every run is a baseline taken at t = 0. It has no
    previous sample to measure an interval from, so its goodput_bps cell
    is empty and the row is skipped here.

    Args:
        path: path to samples.csv written by run_experiments.py.

    Returns:
        List of dicts, in file order (which is time order within a run),
        with keys:
            "run_id", "repetition": ints,
            "host": str, "port": int,
            "algorithm": congestion control the kernel actually used,
            "t": seconds since the run started sending,
            "goodput_mbps": goodput over the interval ending at t, Mbit/s,
            "snd_cwnd": congestion window at t, segments,
            "rtt_ms": smoothed RTT (tcpi_rtt) at t, milliseconds,
            "min_rtt_ms": smallest RTT seen so far, milliseconds,
            "retrans_segs": segments retransmitted during the interval
                ending at t (the loss proxy).
    """
    samples = []
    with open(path, newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            if row["goodput_bps"] == "":
                continue  # baseline sample at t = 0, no interval before it

            samples.append({
                "run_id": int(row["run_id"]),
                "repetition": int(row["repetition"]),
                "host": row["host"],
                "port": int(row["port"]),
                "algorithm": row["algorithm_used"],
                "t": float(row["t"]),
                "goodput_mbps": float(row["goodput_bps"]) / BITS_PER_MEGABIT,
                "snd_cwnd": int(row["snd_cwnd"]),
                "rtt_ms": int(row["rtt"]) / MICROSECONDS_PER_MILLISECOND,
                "min_rtt_ms": int(row["min_rtt"]) / MICROSECONDS_PER_MILLISECOND,
                "retrans_segs": int(row["retrans_segs_interval"]),
            })
    return samples


def percentile_95(values):
    """Return the 95th percentile of a list of numbers.

    statistics.quantiles(values, n=100) returns the 99 cut points that split
    the data into 100 equal groups; cut point k (1-based) is the k-th
    percentile, so the 95th is at index 94. Values between data points are
    linearly interpolated.

    method="inclusive" treats the samples as the whole population, so the
    result always lies between min and max. The default "exclusive" method
    assumes the samples come from a larger population and can extrapolate
    beyond the largest sample, which would be confusing in a summary table.

    Args:
        values: list of numbers (at least one).

    Returns:
        The 95th percentile, same unit as the values.
    """
    if len(values) == 1:
        # quantiles() needs at least two points; one value is every percentile.
        return values[0]
    return statistics.quantiles(values, n=100, method="inclusive")[94]


def summarize_goodput(samples):
    """Compute goodput statistics per (destination, algorithm).

    All repetitions of the same destination and algorithm are pooled into
    one group, as the spec asks for one row per destination and algorithm.

    Args:
        samples: list of sample dicts from load_samples.

    Returns:
        List of dicts with the keys in SUMMARY_COLUMNS, sorted by host,
        port, then algorithm. Goodput values are in Mbit/s.
    """
    # Group goodput values by (host, port, algorithm).
    groups = {}
    for sample in samples:
        key = (sample["host"], sample["port"], sample["algorithm"])
        if key not in groups:
            groups[key] = []
        groups[key].append(sample["goodput_mbps"])

    rows = []
    for key in sorted(groups):
        host, port, algorithm = key
        values = groups[key]
        rows.append({
            "host": host,
            "port": port,
            "algorithm": algorithm,
            "samples": len(values),
            "min_mbps": min(values),
            "median_mbps": statistics.median(values),
            "mean_mbps": statistics.mean(values),
            "p95_mbps": percentile_95(values),
        })
    return rows


def write_summary(rows, path):
    """Write summary rows to a CSV file, rounding Mbit/s values.

    Args:
        rows: list of dicts from summarize_goodput.
        path: CSV file to create (overwritten if it exists).
    """
    with open(path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        for row in rows:
            rounded_row = dict(row)
            for column in ["min_mbps", "median_mbps", "mean_mbps", "p95_mbps"]:
                rounded_row[column] = round(row[column], SUMMARY_DECIMALS)
            writer.writerow(rounded_row)


def format_summary_table(rows):
    """Format summary rows as an aligned text table for the terminal.

    Args:
        rows: list of dicts from summarize_goodput.

    Returns:
        The table as one multi-line string.
    """
    # Width of the destination column: the longest "host:port", at least
    # as wide as its header.
    destination_width = len("destination")
    for row in rows:
        destination = f"{row['host']}:{row['port']}"
        destination_width = max(destination_width, len(destination))

    header = (
        f"{'destination':<{destination_width}}  {'algorithm':<9}  {'samples':>7}  "
        f"{'min':>8}  {'median':>8}  {'mean':>8}  {'p95':>8}   (Mbit/s)"
    )
    lines = [header, "-" * len(header)]
    for row in rows:
        destination = f"{row['host']}:{row['port']}"
        lines.append(
            f"{destination:<{destination_width}}  {row['algorithm']:<9}  {row['samples']:>7}  "
            f"{row['min_mbps']:>8.2f}  {row['median_mbps']:>8.2f}  "
            f"{row['mean_mbps']:>8.2f}  {row['p95_mbps']:>8.2f}"
        )
    return "\n".join(lines)


def first_seen_order(samples, key):
    """List the distinct values of samples[...][key] in order of appearance.

    samples.csv is in test order, so this is the order the tests ran in.

    Args:
        samples: list of sample dicts from load_samples.
        key: dict key to collect, e.g. "algorithm".

    Returns:
        List of distinct values.
    """
    values = []
    for sample in samples:
        if sample[key] not in values:
            values.append(sample[key])
    return values


def group_by_run(samples):
    """Split samples into runs.

    Args:
        samples: list of sample dicts from load_samples, in file order.

    Returns:
        Dict of run_id to that run's samples (in time order). Dicts keep
        insertion order, so runs come out in the order they ran.
    """
    runs = {}
    for sample in samples:
        if sample["run_id"] not in runs:
            runs[sample["run_id"]] = []
        runs[sample["run_id"]].append(sample)
    return runs


def column(samples, key):
    """Collect one value from every sample, ready to pass to matplotlib.

    Args:
        samples: list of sample dicts.
        key: dict key to collect, e.g. "t" or "snd_cwnd".

    Returns:
        List of sample[key], in the same order as samples.
    """
    return [sample[key] for sample in samples]


def plot_goodput_over_time(samples, path):
    """Plot goodput over time, one panel per destination, to a PDF.

    Each run (one destination, algorithm, and repetition) is one line.
    Lines are colored by algorithm, so repetitions of the same algorithm
    share a color. All panels share the same x and y axes so destinations
    can be compared at a glance. Each point is the average goodput over
    the sampling interval that ends at its x value.

    Args:
        samples: list of sample dicts from load_samples (must not be empty).
        path: PDF file to create (overwritten if it exists).
    """
    # Split samples into runs, and list destinations and algorithms in the
    # order they first appear (which is the order the tests were run).
    runs = group_by_run(samples)
    destination_order = []
    for sample in samples:
        destination = (sample["host"], sample["port"])
        if destination not in destination_order:
            destination_order.append(destination)
    algorithm_order = first_seen_order(samples, "algorithm")

    # One color per algorithm from matplotlib's default cycle ("C0", "C1", ...).
    algorithm_colors = {}
    for index, algorithm in enumerate(algorithm_order):
        algorithm_colors[algorithm] = f"C{index}"

    # Grid of panels. squeeze=False keeps `axes` a 2-D array even for a
    # single row or column, so indexing below works for any count.
    row_count = math.ceil(len(destination_order) / PLOT_COLUMNS)
    figure, axes = plt.subplots(
        row_count, PLOT_COLUMNS,
        sharex=True, sharey=True, squeeze=False,
        figsize=(PANEL_WIDTH_INCHES * PLOT_COLUMNS, PANEL_HEIGHT_INCHES * row_count),
    )

    # Panel position for destination number i: row i // columns, column i % columns.
    panels = {}
    for index, destination in enumerate(destination_order):
        panel = axes[index // PLOT_COLUMNS][index % PLOT_COLUMNS]
        host, port = destination
        panel.set_title(f"{host}:{port}", fontsize=9)
        panel.grid(True, alpha=0.3)
        panels[destination] = panel

    # Hide leftover panels when the destination count is odd.
    for index in range(len(destination_order), row_count * PLOT_COLUMNS):
        axes[index // PLOT_COLUMNS][index % PLOT_COLUMNS].set_visible(False)

    for run_samples in runs.values():
        first = run_samples[0]
        panel = panels[(first["host"], first["port"])]
        times = []
        goodputs = []
        for sample in run_samples:
            times.append(sample["t"])
            goodputs.append(sample["goodput_mbps"])
        panel.plot(times, goodputs, color=algorithm_colors[first["algorithm"]],
                   linewidth=1, alpha=0.8)

    # Goodput cannot be negative; anchoring at 0 avoids exaggerating small
    # differences when every panel shares the y axis.
    axes[0][0].set_ylim(bottom=0)

    # One legend for the whole figure, one entry per algorithm.
    legend_handles = []
    for algorithm in algorithm_order:
        legend_handles.append(Line2D([], [], color=algorithm_colors[algorithm], label=algorithm))
    figure.legend(handles=legend_handles, loc="upper right")

    figure.suptitle("Goodput over time (acknowledged bytes per interval)")
    figure.supxlabel("time since start of sending (s)")
    figure.supylabel("goodput (Mbit/s)")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)  # free memory; pyplot keeps figures open otherwise


# ---------------------------------------------------------------------------
# TCP stats plots for one representative destination (Part 2b, Part 3a)
# ---------------------------------------------------------------------------

def samples_for_destination(samples, destination):
    """Return the samples of one destination, all algorithms, in file order.

    Args:
        samples: list of sample dicts from load_samples.
        destination: (host, port).

    Returns:
        List of the sample dicts whose host and port match destination.
    """
    selected = []
    for sample in samples:
        if (sample["host"], sample["port"]) == destination:
            selected.append(sample)
    return selected


def choose_representative_destination(samples):
    """Pick the destination whose TCP stats are plotted.

    Rules, in order:
        1. Prefer destinations with data for every algorithm, so the
           algorithms can be compared on the same path (Part 3a). If none
           has, consider all destinations.
        2. Among those, keep the ones with the most successful runs (no
           failed repetitions).
        3. Pick the one whose mean goodput is the median of the remaining
           destinations, so the plots show a typical path rather than the
           fastest or the slowest.

    Args:
        samples: list of sample dicts from load_samples (must not be empty).

    Returns:
        (host, port) of the chosen destination.
    """
    all_algorithms = set(first_seen_order(samples, "algorithm"))

    # For each destination: the algorithms it has data for, its run ids,
    # and all its goodput values.
    algorithms_by_destination = {}
    run_ids_by_destination = {}
    goodputs_by_destination = {}
    for sample in samples:
        destination = (sample["host"], sample["port"])
        if destination not in algorithms_by_destination:
            algorithms_by_destination[destination] = set()
            run_ids_by_destination[destination] = set()
            goodputs_by_destination[destination] = []
        algorithms_by_destination[destination].add(sample["algorithm"])
        run_ids_by_destination[destination].add(sample["run_id"])
        goodputs_by_destination[destination].append(sample["goodput_mbps"])

    # Rule 1.
    candidates = []
    for destination, algorithms in algorithms_by_destination.items():
        if algorithms == all_algorithms:
            candidates.append(destination)
    if not candidates:
        candidates = list(algorithms_by_destination)

    # Rule 2.
    most_runs = 0
    for destination in candidates:
        most_runs = max(most_runs, len(run_ids_by_destination[destination]))
    complete_candidates = []
    for destination in candidates:
        if len(run_ids_by_destination[destination]) == most_runs:
            complete_candidates.append(destination)

    # Rule 3: sort by mean goodput and take the middle one (for an even
    # count, the upper of the two middle destinations).
    def mean_goodput(destination):
        return statistics.mean(goodputs_by_destination[destination])

    complete_candidates.sort(key=mean_goodput)
    return complete_candidates[len(complete_candidates) // 2]


def compute_axis_limits(samples):
    """Compute one axis top per plotted quantity, shared by every algorithm.

    Using the same limits in every algorithm's figure is what makes them
    comparable (Part 3a asks for consistent axis scales). Every quantity is
    non-negative, so each axis runs from 0 to the value returned here.

    Args:
        samples: the representative destination's samples, all algorithms.

    Returns:
        Dict of sample key ("t", "goodput_mbps", and each TCP_METRICS key)
        to the axis top: largest value times AXIS_HEADROOM.
    """
    limits = {}
    keys = ["t", GOODPUT_METRIC[0]]
    for key, _label in TCP_METRICS:
        keys.append(key)
    for key in keys:
        top = max(column(samples, key)) * AXIS_HEADROOM
        # An all-zero quantity (e.g. no retransmissions at all) would give
        # an empty 0..0 axis; show 0..1 instead.
        if top == 0:
            top = 1
        limits[key] = top
    return limits


def repetition_color(repetition):
    """Pick the color for a repetition, the same in every figure.

    Args:
        repetition: repetition number, starting at 1.

    Returns:
        Matplotlib color from the default cycle: 1 -> "C0", 2 -> "C1", ...
    """
    return f"C{repetition - 1}"


def repetition_legend_handles(runs):
    """Build one legend entry per repetition, in run order.

    Args:
        runs: dict from group_by_run.

    Returns:
        List of Line2D handles for figure.legend().
    """
    handles = []
    for run_samples in runs.values():
        repetition = run_samples[0]["repetition"]
        handles.append(Line2D([], [], color=repetition_color(repetition),
                              label=f"repetition {repetition}"))
    return handles


def plot_time_series(samples, destination, algorithm, limits, path):
    """Plot cwnd, RTT, retransmissions, and goodput over time to a PDF.

    Four panels stacked on a shared time axis, one line per repetition.
    The RTT panel also shows min_rtt dashed: the gap between the two lines
    is roughly the queueing delay our own traffic adds.

    cwnd and RTT are snapshots taken at time t, so they are drawn as plain
    lines. Retransmissions and goodput describe the whole interval ending
    at t, so they are drawn as steps that hold each value across its
    interval (drawstyle "steps-pre": the segment from the previous point to
    point i is drawn at point i's value).

    Args:
        samples: the destination's samples for this algorithm only.
        destination: (host, port), for the title.
        algorithm: congestion control actually used, for the title.
        limits: dict from compute_axis_limits.
        path: PDF file to create (overwritten if it exists).
    """
    panel_metrics = TCP_METRICS + [GOODPUT_METRIC]
    figure, axes = plt.subplots(len(panel_metrics), 1, sharex=True, figsize=(8, 9))

    runs = group_by_run(samples)
    for run_samples in runs.values():
        color = repetition_color(run_samples[0]["repetition"])
        times = column(run_samples, "t")
        for panel, (key, _label) in zip(axes, panel_metrics):
            values = column(run_samples, key)
            if key in ("retrans_segs", "goodput_mbps"):
                # The first interval starts when sending starts (t = 0, the
                # baseline sample that load_samples skips). steps-pre needs
                # a point there, or the first interval would not be drawn.
                panel.plot([0.0] + times, [values[0]] + values, color=color,
                           linewidth=1, drawstyle="steps-pre")
            else:
                panel.plot(times, values, color=color, linewidth=1)

        # min_rtt on the RTT panel (index 1 in TCP_METRICS).
        axes[1].plot(times, column(run_samples, "min_rtt_ms"), color=color,
                     linewidth=1, linestyle="--")

    for panel, (key, label) in zip(axes, panel_metrics):
        panel.set_ylim(0, limits[key])
        panel.set_ylabel(label, fontsize=9)
        panel.grid(True, alpha=0.3)
    axes[-1].set_xlim(0, limits["t"])
    axes[-1].set_xlabel("time since start of sending (s)")

    legend_handles = repetition_legend_handles(runs)
    legend_handles.append(Line2D([], [], color="gray", linestyle="--", label="min RTT"))
    # loc="best" places the legend where it covers the fewest points.
    axes[0].legend(handles=legend_handles, loc="best", fontsize=8)

    host, port = destination
    figure.suptitle(f"TCP stats over time: {host}:{port}, {algorithm}")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)


def plot_scatter(samples, destination, algorithm, limits, path):
    """Plot cwnd, RTT, and retransmissions against goodput to a PDF.

    Three panels side by side sharing the goodput (y) axis; each point is
    one sample, colored by repetition.

    Timing caveat: goodput is the average over the interval ending at t,
    while cwnd and RTT are snapshots at t. With short intervals the two
    are close; within a sudden change (e.g. a cwnd cut right before the
    sample) a point pairs the new cwnd with the old interval's goodput.

    Args:
        samples: the destination's samples for this algorithm only.
        destination: (host, port), for the title.
        algorithm: congestion control actually used, for the title.
        limits: dict from compute_axis_limits.
        path: PDF file to create (overwritten if it exists).
    """
    goodput_key, goodput_label = GOODPUT_METRIC
    figure, axes = plt.subplots(1, len(TCP_METRICS), sharey=True, figsize=(10, 4))

    runs = group_by_run(samples)
    for run_samples in runs.values():
        color = repetition_color(run_samples[0]["repetition"])
        goodputs = column(run_samples, goodput_key)
        for panel, (key, _label) in zip(axes, TCP_METRICS):
            panel.scatter(column(run_samples, key), goodputs, color=color, s=12, alpha=0.7)

    for panel, (key, label) in zip(axes, TCP_METRICS):
        panel.set_xlim(0, limits[key])
        panel.set_xlabel(label.replace("\n", " "))
        panel.grid(True, alpha=0.3)
    axes[0].set_ylim(0, limits[goodput_key])
    axes[0].set_ylabel(goodput_label)

    axes[0].legend(handles=repetition_legend_handles(runs), loc="best", fontsize=8)

    host, port = destination
    figure.suptitle(f"TCP stats vs goodput: {host}:{port}, {algorithm}")
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)


def plot_tcp_stats(samples, representative, results_dir):
    """Draw the time-series and scatter figures for every algorithm.

    Args:
        samples: all samples from load_samples (must not be empty).
        representative: (host, port) to plot, or None to pick one with
            choose_representative_destination. A destination with no
            samples is reported and replaced by the automatic pick.
        results_dir: directory the PDFs are written to.

    Returns:
        The (host, port) that was plotted.
    """
    if representative is None:
        representative = choose_representative_destination(samples)
    destination_samples = samples_for_destination(samples, representative)

    if not destination_samples:
        # A typo in --representative should not throw away the report of a
        # long campaign, so fall back to the automatic pick.
        logger.warning("no samples for representative %s:%d, picking one automatically",
                       representative[0], representative[1])
        representative = choose_representative_destination(samples)
        destination_samples = samples_for_destination(samples, representative)

    logger.info("representative destination: %s:%d", representative[0], representative[1])
    limits = compute_axis_limits(destination_samples)

    for algorithm in first_seen_order(destination_samples, "algorithm"):
        algorithm_samples = []
        for sample in destination_samples:
            if sample["algorithm"] == algorithm:
                algorithm_samples.append(sample)

        timeseries_path = os.path.join(results_dir, TIMESERIES_PLOT_FILE.format(algorithm=algorithm))
        plot_time_series(algorithm_samples, representative, algorithm, limits, timeseries_path)
        logger.info("wrote %s", timeseries_path)

        scatter_path = os.path.join(results_dir, SCATTER_PLOT_FILE.format(algorithm=algorithm))
        plot_scatter(algorithm_samples, representative, algorithm, limits, scatter_path)
        logger.info("wrote %s", scatter_path)
    return representative


def generate_report(results_dir, representative=None):
    """Build the goodput summary table and plot for one results directory.

    Args:
        results_dir: directory containing samples.csv. Outputs are written
            next to it (goodput_summary.csv, goodput_over_time.pdf, and the
            tcp_timeseries_* / tcp_scatter_* PDFs).
        representative: (host, port) for the TCP stats plots, or None to
            pick one automatically (see plot_tcp_stats).

    Returns:
        The summary rows (see summarize_goodput); empty if there were no
        goodput samples, e.g. because every run failed.
    """
    samples = load_samples(os.path.join(results_dir, SAMPLES_FILE))
    if not samples:
        # Every run failed (or the campaign was interrupted before the
        # first run finished): nothing to summarize or plot.
        logger.warning("no goodput samples in %s, skipping report", results_dir)
        return []

    rows = summarize_goodput(samples)

    summary_path = os.path.join(results_dir, SUMMARY_FILE)
    write_summary(rows, summary_path)
    print(format_summary_table(rows))
    logger.info("wrote %s", summary_path)

    plot_path = os.path.join(results_dir, GOODPUT_PLOT_FILE)
    plot_goodput_over_time(samples, plot_path)
    logger.info("wrote %s", plot_path)

    plot_tcp_stats(samples, representative, results_dir)
    return rows


# ---------------------------------------------------------------------------
# Self-check (runs on any OS; no network)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    # Inclusive percentile of 1..5: position 0.95 * (5 - 1) = 3.8 between
    # the sorted values, i.e. 4 + 0.8 * (5 - 4) = 4.8.
    assert abs(percentile_95([1, 2, 3, 4, 5]) - 4.8) < 1e-9
    assert percentile_95([7]) == 7

    # Representative destination: x, y, z have data for both algorithms,
    # w only for cubic (excluded by rule 1 despite its high goodput). Mean
    # goodputs 1, 5, 9: the median is y.
    def fake_sample(run_id, host, algorithm, goodput):
        return {"run_id": run_id, "host": host, "port": 5201,
                "algorithm": algorithm, "goodput_mbps": goodput}
    fake_samples = [
        fake_sample(1, "x", "cubic", 1), fake_sample(2, "x", "reno", 1),
        fake_sample(3, "y", "cubic", 5), fake_sample(4, "y", "reno", 5),
        fake_sample(5, "z", "cubic", 9), fake_sample(6, "z", "reno", 9),
        fake_sample(7, "w", "cubic", 100),
    ]
    assert choose_representative_destination(fake_samples) == ("y", 5201)
    # Rule 2: x gets an extra run (no failed repetition), so it wins.
    fake_samples.append(fake_sample(8, "x", "cubic", 1))
    assert choose_representative_destination(fake_samples) == ("x", 5201)

    # Fake samples.csv: two destinations, two algorithms, one baseline row
    # (empty interval values) at the start of each run. cwnd is 10 x the
    # goodput in Mbit/s, RTT 20 ms, min RTT 15 ms, and the goodput-5 sample
    # has 2 retransmissions.
    header = ["run_id", "repetition", "host", "port", "algorithm_used", "t", "goodput_bps",
              "snd_cwnd", "rtt", "min_rtt", "retrans_segs_interval"]
    fake_runs = [
        # (run_id, repetition, host, algorithm, goodput values in Mbit/s)
        (1, 1, "a.example", "cubic", [1, 2, 3, 4, 5]),
        (2, 1, "a.example", "reno", [10, 10, 10]),
        (3, 1, "b.example", "cubic", [20, 30]),
        (4, 2, "a.example", "reno", [10, 10]),
    ]
    with tempfile.TemporaryDirectory() as temp_dir:
        with open(os.path.join(temp_dir, SAMPLES_FILE), "w", newline="") as fake_file:
            fake_writer = csv.writer(fake_file)
            fake_writer.writerow(header)
            for run_id, repetition, host, algorithm, values in fake_runs:
                fake_writer.writerow([run_id, repetition, host, 5201, algorithm, 0.0, "",
                                      10, 20_000, 15_000, ""])
                for index, value in enumerate(values):
                    retransmissions = 0
                    if value == 5:
                        retransmissions = 2
                    fake_writer.writerow([run_id, repetition, host, 5201, algorithm,
                                          float(index + 1), value * BITS_PER_MEGABIT,
                                          value * 10, 20_000, 15_000, retransmissions])

        summary = generate_report(temp_dir)

        # Baselines skipped, groups sorted by host then algorithm, both
        # reno repetitions pooled.
        assert len(summary) == 3
        first_row = summary[0]
        assert (first_row["host"], first_row["algorithm"]) == ("a.example", "cubic")
        assert first_row["samples"] == 5
        assert first_row["min_mbps"] == 1
        assert first_row["median_mbps"] == 3
        assert first_row["mean_mbps"] == 3
        assert abs(first_row["p95_mbps"] - 4.8) < 1e-9
        assert summary[1]["algorithm"] == "reno"
        assert summary[1]["samples"] == 5
        assert summary[2]["mean_mbps"] == 25

        assert os.path.getsize(os.path.join(temp_dir, SUMMARY_FILE)) > 0
        assert os.path.getsize(os.path.join(temp_dir, GOODPUT_PLOT_FILE)) > 0

        # a.example is the only destination with both algorithms. Its axis
        # limits cover both algorithms: goodput and cwnd peak in reno, the
        # retransmissions and the longest run in cubic.
        a_samples = samples_for_destination(load_samples(os.path.join(temp_dir, SAMPLES_FILE)),
                                            ("a.example", 5201))
        limits = compute_axis_limits(a_samples)
        assert abs(limits["goodput_mbps"] - 10 * AXIS_HEADROOM) < 1e-9
        assert abs(limits["snd_cwnd"] - 100 * AXIS_HEADROOM) < 1e-9
        assert abs(limits["rtt_ms"] - 20 * AXIS_HEADROOM) < 1e-9
        assert abs(limits["retrans_segs"] - 2 * AXIS_HEADROOM) < 1e-9
        assert abs(limits["t"] - 5 * AXIS_HEADROOM) < 1e-9
        for algorithm in ["cubic", "reno"]:
            for file_pattern in [TIMESERIES_PLOT_FILE, SCATTER_PLOT_FILE]:
                plot_path = os.path.join(temp_dir, file_pattern.format(algorithm=algorithm))
                assert os.path.getsize(plot_path) > 0

        # A --representative with no data falls back to the automatic pick.
        assert plot_tcp_stats(a_samples, ("nowhere", 1), temp_dir) == ("a.example", 5201)

    print("self-check passed")
