#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


TIMESTAMP_DIR_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
PACKET_PATTERN = re.compile(
    r"^(?P<timestamp>\d+\.\d+)\s+IP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):.*length\s+(?P<length>\d+)\s*$"
)
DEFAULT_PORT_START = 50000
DEFAULT_PORT_END = 50050
DEFAULT_FOREGROUND_PORT = 50001
DEFAULT_BIN_WIDTH_SECONDS = 0.5
DEFAULT_MAX_TIME_SECONDS = 30.0
BASE_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot per-flow throughput from nested run directories that contain "
            "client.pcap and server.pcap files."
        )
    )
    parser.add_argument(
        "experiment_dir",
        nargs="?",
        type=Path,
        help=(
            "Outer timestamp directory to analyze. Defaults to the newest timestamp "
            "directory in experiments/congested_path."
        ),
    )
    parser.add_argument(
        "--bin-width",
        type=float,
        default=DEFAULT_BIN_WIDTH_SECONDS,
        help=f"Time bin width in seconds (default: {DEFAULT_BIN_WIDTH_SECONDS}).",
    )
    parser.add_argument(
        "--port-start",
        type=int,
        default=DEFAULT_PORT_START,
        help=f"First flow port to include (default: {DEFAULT_PORT_START}).",
    )
    parser.add_argument(
        "--port-end",
        type=int,
        default=DEFAULT_PORT_END,
        help=f"Last flow port to include (default: {DEFAULT_PORT_END}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Directory for generated outputs. Defaults to the root measurement folder.",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="Display plots interactively in addition to saving them.",
    )
    parser.add_argument(
        "--max-time",
        type=float,
        default=DEFAULT_MAX_TIME_SECONDS,
        help=f"Maximum time in seconds to include in the plot and averaged CSV (default: {DEFAULT_MAX_TIME_SECONDS}).",
    )
    return parser.parse_args()


def iter_timestamp_dirs(base_dir: Path) -> list[Path]:
    if not base_dir.exists():
        return []
    return sorted(
        path
        for path in base_dir.iterdir()
        if path.is_dir() and TIMESTAMP_DIR_PATTERN.match(path.name)
    )


def iter_measurement_dirs(base_dir: Path) -> list[Path]:
    if not base_dir.exists():
        return []
    return sorted(
        path
        for path in base_dir.iterdir()
        if path.is_dir()
        and path.name != "__pycache__"
        and any(child.is_dir() and TIMESTAMP_DIR_PATTERN.match(child.name) for child in path.iterdir())
    )


def resolve_experiment_dir(requested_dir: Path | None) -> Path:
    if requested_dir is not None:
        return requested_dir.resolve()

    measurement_dirs = iter_measurement_dirs(BASE_DIR)
    if not measurement_dirs:
        raise FileNotFoundError(f"No timestamp directories found in {BASE_DIR}")
    return measurement_dirs[-1]


def resolve_output_dir(experiment_dir: Path, requested_output_dir: Path | None) -> Path:
    if requested_output_dir is not None:
        return requested_output_dir.resolve()
    return experiment_dir


def split_endpoint(endpoint: str) -> tuple[str, int] | None:
    host, separator, port = endpoint.rpartition(".")
    if not separator or not port.isdigit():
        return None
    return host, int(port)


def identify_flow_port(src: str, dst: str, port_start: int, port_end: int) -> int | None:
    src_endpoint = split_endpoint(src)
    dst_endpoint = split_endpoint(dst)
    if src_endpoint is None or dst_endpoint is None:
        return None

    _, src_port = src_endpoint
    _, dst_port = dst_endpoint
    src_in_range = port_start <= src_port <= port_end
    dst_in_range = port_start <= dst_port <= port_end

    if src_in_range and not dst_in_range:
        return src_port
    if dst_in_range and not src_in_range:
        return dst_port
    return None


def classify_transport(line: str) -> str | None:
    if ": UDP," in line:
        return "QUIC"
    if "Flags [" in line:
        return "TCP"
    return None


def parse_pcap(
    pcap_path: Path,
    capture_name: str,
    run_name: str,
    port_start: int,
    port_end: int,
) -> list[dict[str, object]]:
    command = [
        "tcpdump",
        "-tt",
        "-n",
        "-r",
        str(pcap_path),
        "(",
        "tcp",
        "or",
        "udp",
        ")",
        "and",
        "portrange",
        f"{port_start}-{port_end}",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    stderr = result.stderr.strip()
    truncated_dump = "tcpdump: pcap_loop: truncated dump file;" in stderr
    if result.returncode != 0 and not truncated_dump:
        raise RuntimeError(f"tcpdump failed for {pcap_path}: {stderr or 'unknown error'}")

    records: list[dict[str, object]] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        match = PACKET_PATTERN.match(line)
        if not match:
            continue

        flow_port = identify_flow_port(
            match.group("src"),
            match.group("dst"),
            port_start,
            port_end,
        )
        if flow_port is None:
            continue
        transport = classify_transport(line)
        if transport is None:
            continue

        records.append(
            {
                "run": run_name,
                "capture": capture_name,
                "timestamp": float(match.group("timestamp")),
                "flow_port": flow_port,
                "payload_bytes": int(match.group("length")),
                "transport": transport,
            }
        )

    return records


def load_run_records(run_dir: Path, port_start: int, port_end: int) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for capture_name in ("client", "server"):
        pcap_path = run_dir / f"{capture_name}.pcap"
        if not pcap_path.exists():
            continue
        try:
            records.extend(parse_pcap(pcap_path, capture_name, run_dir.name, port_start, port_end))
        except RuntimeError as error:
            print(f"Skipping {pcap_path}: {error}", file=sys.stderr)
    return records


def prepare_matplotlib(show: bool) -> None:
    cache_root = Path(tempfile.mkdtemp(prefix="plot-cache-"))
    (cache_root / "matplotlib").mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("XDG_CACHE_HOME", str(cache_root))
    os.environ.setdefault("MPLCONFIGDIR", str(cache_root / "matplotlib"))
    if not show:
        import matplotlib

        matplotlib.use("Agg")


def build_run_dataframe(
    run_records: list[dict[str, object]],
    bin_width: float,
    run_name: str,
):
    import pandas as pd

    frame = pd.DataFrame(run_records)
    if frame.empty:
        return frame, frame

    start_time = frame["timestamp"].min()
    end_time = frame["timestamp"].max()
    bin_count = max(1, math.ceil((end_time - start_time) / bin_width) + 1)

    frame["time_seconds"] = frame["timestamp"] - start_time
    frame["bin_index"] = (frame["time_seconds"] / bin_width).astype(int).clip(upper=bin_count - 1)

    summary = (
        frame.groupby(["capture", "flow_port", "bin_index"], as_index=False)["payload_bytes"]
        .sum()
        .rename(columns={"payload_bytes": "bytes_per_bin"})
    )
    summary["throughput_mbps"] = summary["bytes_per_bin"] * 8 / (bin_width * 1_000_000)

    captures = sorted(frame["capture"].unique())
    flows = sorted(frame["flow_port"].unique())
    full_index = pd.MultiIndex.from_product(
        [captures, flows, range(bin_count)],
        names=["capture", "flow_port", "bin_index"],
    )
    summary = (
        summary.set_index(["capture", "flow_port", "bin_index"])
        .reindex(full_index, fill_value=0)
        .reset_index()
    )
    transport_by_flow = frame.groupby("flow_port")["transport"].agg(lambda values: sorted(set(values))[0]).to_dict()
    summary["transport"] = summary["flow_port"].map(transport_by_flow)
    summary["time_seconds"] = summary["bin_index"] * bin_width
    summary["run"] = run_name
    summary["flow_label"] = summary["flow_port"].map(lambda value: f"port {value}")

    return frame, summary


def plot_run(summary_frame, output_path: Path, run_name: str, show: bool, capture_name: str) -> None:
    import matplotlib.pyplot as plt
    import seaborn as sns

    sns.set_theme(style="whitegrid", context="talk")
    figure, axis = plt.subplots(figsize=(11, 5.5), constrained_layout=True)
    flow_ports = sorted(summary_frame["flow_port"].unique())
    foreground_port = DEFAULT_FOREGROUND_PORT if DEFAULT_FOREGROUND_PORT in flow_ports else None
    background_ports = [port for port in flow_ports if port != foreground_port]
    transport_by_flow = (
        summary_frame.groupby("flow_port")["transport"]
        .agg(lambda values: sorted(set(values))[0])
        .to_dict()
    )

    if foreground_port is None:
        foreground_frame = summary_frame.iloc[0:0]
        background_frame = summary_frame
    else:
        foreground_frame = summary_frame[summary_frame["flow_port"] == foreground_port]
        background_frame = summary_frame[summary_frame["flow_port"] != foreground_port]

    grey_palette = sns.color_palette("Greys", n_colors=max(len(background_ports) + 2, 3))[1:-1]
    for color, flow_port in zip(grey_palette, background_ports):
        flow_frame = background_frame[background_frame["flow_port"] == flow_port]
        if flow_frame.empty:
            continue
        axis.plot(
            flow_frame["time_seconds"],
            flow_frame["throughput_mbps"],
            color=color,
            linewidth=1.5,
            alpha=0.9,
            label="_nolegend_",
        )

    if not foreground_frame.empty:
        axis.plot(
            foreground_frame["time_seconds"],
            foreground_frame["throughput_mbps"],
            color=sns.color_palette("deep")[0],
            linewidth=2.2,
            label=transport_by_flow.get(foreground_port, "Foreground"),
        )

    if background_ports:
        background_protocols = sorted({transport_by_flow.get(port, "Background") for port in background_ports})
        axis.plot([], [], color="0.45", linewidth=1.8, label=" / ".join(background_protocols))

    figure.suptitle(f"Per-flow {capture_name}-side throughput for run {run_name}")
    axis.set_xlabel("Time since first packet in run (s)")
    axis.set_ylabel("Throughput (Mbit/s)")
    axis.set_title(f"{capture_name}.pcap")
    axis.grid(True, alpha=0.3)
    axis.legend(title="Flow")

    figure.savefig(output_path, dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    plt.close(figure)


def plot_average(summary_frame, output_path: Path, show: bool, run_count: int, capture_name: str) -> None:
    import matplotlib.pyplot as plt
    import seaborn as sns

    sns.set_theme(style="whitegrid", context="talk")
    figure, axis = plt.subplots(figsize=(11, 5.5), constrained_layout=True)
    flow_ports = sorted(summary_frame["flow_port"].unique())
    foreground_port = DEFAULT_FOREGROUND_PORT if DEFAULT_FOREGROUND_PORT in flow_ports else None
    background_ports = [port for port in flow_ports if port != foreground_port]
    transport_by_flow = (
        summary_frame.groupby("flow_port")["transport"]
        .agg(lambda values: sorted(set(values))[0])
        .to_dict()
    )

    if foreground_port is None:
        foreground_frame = summary_frame.iloc[0:0]
        background_frame = summary_frame
    else:
        foreground_frame = summary_frame[summary_frame["flow_port"] == foreground_port]
        background_frame = summary_frame[summary_frame["flow_port"] != foreground_port]

    grey_palette = sns.color_palette("Greys", n_colors=max(len(background_ports) + 2, 3))[1:-1]
    for color, flow_port in zip(grey_palette, background_ports):
        flow_frame = background_frame[background_frame["flow_port"] == flow_port]
        if flow_frame.empty:
            continue
        axis.fill_between(
            flow_frame["time_seconds"],
            flow_frame["ci_lower"],
            flow_frame["ci_upper"],
            color=color,
            alpha=0.18,
            linewidth=0,
        )
        axis.plot(
            flow_frame["time_seconds"],
            flow_frame["throughput_mbps_mean"],
            color=color,
            linewidth=1.5,
            alpha=0.9,
            label="_nolegend_",
        )

    if not foreground_frame.empty:
        axis.fill_between(
            foreground_frame["time_seconds"],
            foreground_frame["ci_lower"],
            foreground_frame["ci_upper"],
            color=sns.color_palette("deep")[0],
            alpha=0.18,
            linewidth=0,
        )
        axis.plot(
            foreground_frame["time_seconds"],
            foreground_frame["throughput_mbps_mean"],
            color=sns.color_palette("deep")[0],
            linewidth=2.2,
            label=transport_by_flow.get(foreground_port, "Foreground"),
        )

    if background_ports:
        background_protocols = sorted({transport_by_flow.get(port, "Background") for port in background_ports})
        axis.plot([], [], color="0.45", linewidth=1.8, label=" / ".join(background_protocols))

    figure.suptitle(f"Average {capture_name}-side per-flow throughput across {run_count} runs")
    axis.set_xlabel("Time since first packet in run (s)")
    axis.set_ylabel("Average throughput (Mbit/s)")
    axis.set_title(f"{capture_name}.pcap")
    axis.grid(True, alpha=0.3)

    axis.legend(title="Flow")
    figure.savefig(output_path, dpi=200, bbox_inches="tight")
    if show:
        plt.show()
    plt.close(figure)


def process_experiment_dir(args: argparse.Namespace, experiment_dir: Path) -> int:
    if not experiment_dir.exists():
        print(f"Experiment directory does not exist: {experiment_dir}", file=sys.stderr)
        return 1

    run_dirs = iter_timestamp_dirs(experiment_dir)
    if not run_dirs:
        print(f"No run directories found in {experiment_dir}", file=sys.stderr)
        return 1

    output_dir = resolve_output_dir(experiment_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    prepare_matplotlib(args.show)
    import pandas as pd

    all_summaries = []
    for run_dir in run_dirs:
        run_records = load_run_records(run_dir, args.port_start, args.port_end)
        if not run_records:
            print(f"Skipping {run_dir.name}: no matching packets in {args.port_start}-{args.port_end}")
            continue

        _, summary = build_run_dataframe(run_records, args.bin_width, run_dir.name)
        if summary.empty:
            print(f"Skipping {run_dir.name}: no plot data after binning")
            continue
        summary = summary[summary["time_seconds"] <= args.max_time].copy()
        if summary.empty:
            print(f"Skipping {run_dir.name}: no packets within first {args.max_time} seconds")
            continue

        all_summaries.append(summary)
        run_output_stem = f"{experiment_dir.name}_{run_dir.name}"
        for capture_name in ("client", "server"):
            capture_frame = summary[summary["capture"] == capture_name].copy()
            if capture_frame.empty:
                continue
            run_pdf_path = output_dir / f"{run_output_stem}_{capture_name}_throughput.pdf"
            run_png_path = output_dir / f"{run_output_stem}_{capture_name}_throughput.png"
            plot_run(capture_frame, run_pdf_path, run_dir.name, args.show, capture_name)
            plot_run(capture_frame, run_png_path, run_dir.name, args.show, capture_name)
            print(f"Wrote {run_pdf_path}")
            print(f"Wrote {run_png_path}")

    if not all_summaries:
        print("No plots were generated.", file=sys.stderr)
        return 1

    combined_frame = pd.concat(all_summaries, ignore_index=True)
    stats_frame = (
        combined_frame.groupby(
            ["capture", "flow_port", "time_seconds", "flow_label", "transport"],
            as_index=False,
        )["throughput_mbps"]
        .agg(["mean", "std", "count"])
        .reset_index()
        .rename(
            columns={
                "mean": "throughput_mbps_mean",
                "std": "throughput_mbps_std",
                "count": "sample_count",
            }
        )
        .sort_values(["capture", "flow_port", "time_seconds"])
    )
    stats_frame["throughput_mbps_std"] = stats_frame["throughput_mbps_std"].fillna(0.0)
    stats_frame["ci_half_width"] = 1.96 * (
        stats_frame["throughput_mbps_std"] / stats_frame["sample_count"].clip(lower=1).pow(0.5)
    )
    stats_frame["ci_lower"] = (stats_frame["throughput_mbps_mean"] - stats_frame["ci_half_width"]).clip(lower=0.0)
    stats_frame["ci_upper"] = stats_frame["throughput_mbps_mean"] + stats_frame["ci_half_width"]

    output_stem = experiment_dir.name
    combined_csv_path = output_dir / f"{output_stem}_all_runs_throughput.csv"
    average_csv_path = output_dir / f"{output_stem}_average_throughput.csv"
    combined_frame.to_csv(combined_csv_path, index=False)
    stats_frame.to_csv(average_csv_path, index=False)
    run_count = combined_frame["run"].nunique()
    for capture_name in ("client", "server"):
        capture_frame = stats_frame[stats_frame["capture"] == capture_name].copy()
        if capture_frame.empty:
            continue
        average_pdf_path = output_dir / f"{output_stem}_average_{capture_name}_throughput.pdf"
        average_png_path = output_dir / f"{output_stem}_average_{capture_name}_throughput.png"
        plot_average(capture_frame, average_pdf_path, args.show, run_count, capture_name)
        plot_average(capture_frame, average_png_path, args.show, run_count, capture_name)
        print(f"Wrote {average_pdf_path}")
        print(f"Wrote {average_png_path}")
    print(f"Wrote {combined_csv_path}")
    print(f"Wrote {average_csv_path}")
    return 0


def main() -> int:
    args = parse_args()
    if args.bin_width <= 0:
        print("--bin-width must be greater than 0", file=sys.stderr)
        return 2
    if args.port_start > args.port_end:
        print("--port-start must be less than or equal to --port-end", file=sys.stderr)
        return 2
    if args.max_time <= 0:
        print("--max-time must be greater than 0", file=sys.stderr)
        return 2

    if args.experiment_dir is not None:
        experiment_dirs = [resolve_experiment_dir(args.experiment_dir)]
    else:
        experiment_dirs = iter_measurement_dirs(BASE_DIR)
        if not experiment_dirs:
            print(f"No measurement directories found in {BASE_DIR}", file=sys.stderr)
            return 1

    exit_code = 0
    for experiment_dir in experiment_dirs:
        print(f"Processing {experiment_dir}")
        exit_code = max(exit_code, process_experiment_dir(args, experiment_dir))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
