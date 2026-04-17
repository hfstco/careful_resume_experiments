import argparse
import json
from pathlib import Path

import matplotlib
from matplotlib.ticker import FuncFormatter
import numpy as np
import pandas as pd
import seaborn as sns

matplotlib.use("Agg")

import matplotlib.pyplot as plt

MAX_TIME_SECONDS = 15.0
AXIS_LABEL_SIZE = 20
TICK_LABEL_SIZE = 20
LEGEND_SIZE = 20


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot average server cwnd over time from safe_retreat qlog files."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=None,
        type=Path,
        help="Measurement root to plot, or the safe_retreat directory to plot all roots.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Output image path for single-root mode. Defaults to <root>/safe-retreat.pdf.",
    )
    return parser.parse_args()


def find_measurement_roots(base_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in base_dir.iterdir()
        if path.is_dir()
        and not path.name.startswith("__")
        and any(path.rglob("*.server.qlog"))
    )


def default_root() -> Path:
    safe_retreat_dir = Path(__file__).resolve().parent
    roots = find_measurement_roots(safe_retreat_dir)
    if not roots:
        raise SystemExit(f"No measurement directories found under {safe_retreat_dir}")
    return safe_retreat_dir


def find_server_qlogs(root: Path) -> list[Path]:
    qlogs: list[Path] = []
    for directory in sorted(path for path in root.iterdir() if path.is_dir()):
        directory_qlogs = sorted(directory.rglob("*.server.qlog"))
        if not directory_qlogs:
            continue
        qlogs.extend(directory_qlogs)

    if qlogs:
        return qlogs

    return sorted(root.rglob("*.server.qlog"))


def find_run_dirs(root: Path) -> list[Path]:
    return sorted(
        directory for directory in root.iterdir() if directory.is_dir() and any(directory.glob("*.server.qlog"))
    )


def extract_recovery_rows(qlog_path: Path) -> tuple[list[dict], list[dict]]:
    with qlog_path.open() as handle:
        qlog = json.load(handle)

    trace = qlog["traces"][0]
    cwnd_rows: list[dict] = []
    loss_rows: list[dict] = []

    for event in trace.get("events", []):
        if len(event) < 4:
            continue

        time_us, category, event_name, data = event[:4]
        if category != "recovery" or not isinstance(data, dict):
            continue

        run_dir = qlog_path.parent
        if event_name == "metrics_updated" and "cwnd" in data:
            cwnd_rows.append(
                {
                    "run": run_dir.name,
                    "time_s": time_us / 1_000_000,
                    "cwnd_bytes": data["cwnd"],
                }
            )
        elif event_name == "packet_lost":
            loss_rows.append(
                {
                    "run": run_dir.name,
                    "time_s": time_us / 1_000_000,
                }
            )

    return cwnd_rows, loss_rows


def load_recovery_dataframes(root: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    cwnd_rows: list[dict] = []
    loss_rows: list[dict] = []
    for qlog_path in find_server_qlogs(root):
        qlog_cwnd_rows, qlog_loss_rows = extract_recovery_rows(qlog_path)
        cwnd_rows.extend(qlog_cwnd_rows)
        loss_rows.extend(qlog_loss_rows)

    if not cwnd_rows:
        raise SystemExit(f"No server qlog files with cwnd samples found under {root}")

    return pd.DataFrame(cwnd_rows), pd.DataFrame(loss_rows)


def average_cwnd(data: pd.DataFrame, num_points: int = 1000) -> pd.DataFrame:
    run_groups = [group.sort_values("time_s") for _, group in data.groupby("run", sort=True)]
    max_time = min(MAX_TIME_SECONDS, max(group["time_s"].max() for group in run_groups))
    time_grid = np.linspace(0.0, max_time, num=num_points)

    interpolated = []
    for group in run_groups:
        times = group["time_s"].to_numpy()
        cwnd = group["cwnd_bytes"].to_numpy()
        run_grid = np.full_like(time_grid, np.nan, dtype=float)
        valid = time_grid <= times[-1]
        run_grid[valid] = np.interp(time_grid[valid], times, cwnd)
        interpolated.append(run_grid)

    stacked = np.vstack(interpolated)
    return pd.DataFrame(
        {
            "time_s": time_grid,
            "cwnd_mb": np.nanmean(stacked, axis=0) / 1_000_000,
            "cwnd_mb_lower": np.nanquantile(stacked, 0.025, axis=0) / 1_000_000,
            "cwnd_mb_upper": np.nanquantile(stacked, 0.975, axis=0) / 1_000_000,
        }
    )


def average_packet_loss(
    loss_data: pd.DataFrame, run_names: list[str], max_time: float, num_points: int = 1000
) -> pd.DataFrame:
    bin_edges = np.linspace(0.0, max_time, num=num_points + 1)
    bin_centers = (bin_edges[:-1] + bin_edges[1:]) / 2

    histograms = []
    for run_name in run_names:
        run_losses = loss_data.loc[loss_data["run"] == run_name, "time_s"].to_numpy()
        counts, _ = np.histogram(run_losses, bins=bin_edges)
        histograms.append(counts.astype(float))

    if histograms:
        stacked = np.vstack(histograms)
        average_counts = np.mean(stacked, axis=0)
        lower_counts = np.quantile(stacked, 0.025, axis=0)
        upper_counts = np.quantile(stacked, 0.975, axis=0)
    else:
        average_counts = np.zeros(num_points)
        lower_counts = np.zeros(num_points)
        upper_counts = np.zeros(num_points)

    return pd.DataFrame(
        {
            "time_s": bin_centers,
            "lost_packets": average_counts,
            "lost_packets_lower": lower_counts,
            "lost_packets_upper": upper_counts,
        }
    )


def summarize_recovery(cwnd_data: pd.DataFrame, loss_data: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    average_cwnd_data = average_cwnd(cwnd_data)
    average_loss_data = average_packet_loss(
        loss_data=loss_data,
        run_names=sorted(cwnd_data["run"].unique()),
        max_time=average_cwnd_data["time_s"].max(),
        num_points=len(average_cwnd_data),
    )
    return average_cwnd_data, average_loss_data


def summarize_single_run(cwnd_data: pd.DataFrame, loss_data: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    run_cwnd = cwnd_data.sort_values("time_s").copy()
    run_cwnd = run_cwnd.loc[run_cwnd["time_s"] <= MAX_TIME_SECONDS].copy()
    run_cwnd["cwnd_mb"] = run_cwnd["cwnd_bytes"] / 1_000_000
    run_cwnd["cwnd_mb_lower"] = run_cwnd["cwnd_mb"]
    run_cwnd["cwnd_mb_upper"] = run_cwnd["cwnd_mb"]

    loss_bins = np.linspace(0.0, MAX_TIME_SECONDS, num=1001)
    bin_centers = (loss_bins[:-1] + loss_bins[1:]) / 2
    loss_times = loss_data["time_s"].to_numpy()
    counts, _ = np.histogram(loss_times, bins=loss_bins)
    run_loss = pd.DataFrame(
        {
            "time_s": bin_centers,
            "lost_packets": counts.astype(float),
            "lost_packets_lower": counts.astype(float),
            "lost_packets_upper": counts.astype(float),
        }
    )
    return run_cwnd, run_loss


def plot_recovery(cwnd_data: pd.DataFrame, loss_data: pd.DataFrame, output_path: Path) -> None:
    average_cwnd_data, average_loss_data = summarize_recovery(cwnd_data, loss_data)
    sns.set_theme(style="whitegrid", context="talk")
    figure, axes = plt.subplots(
        2, 1, figsize=(14, 10), sharex=True, height_ratios=[3, 1.6]
    )
    axes[0].plot(
        average_cwnd_data["time_s"],
        average_cwnd_data["cwnd_mb"],
        linewidth=2.4,
        color="#4c72b0",
        label="cwnd",
    )
    axes[0].fill_between(
        average_cwnd_data["time_s"],
        average_cwnd_data["cwnd_mb_lower"],
        average_cwnd_data["cwnd_mb_upper"],
        color="#4c72b0",
        alpha=0.18,
        linewidth=0,
    )
    axes[1].plot(
        average_loss_data["time_s"],
        average_loss_data["lost_packets"],
        linewidth=2.0,
        color="#c44e52",
        label="lost packets",
    )
    axes[1].fill_between(
        average_loss_data["time_s"],
        average_loss_data["lost_packets_lower"],
        average_loss_data["lost_packets_upper"],
        color="#c44e52",
        alpha=0.18,
        linewidth=0,
    )

    axes[0].set_xlabel("")
    axes[0].set_ylabel("cwnd [MB]", fontsize=AXIS_LABEL_SIZE)
    axes[0].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[0].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.2f}"))
    axes[1].set_xlabel("")
    axes[1].set_ylabel("# packets lost", fontsize=AXIS_LABEL_SIZE)
    axes[1].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[1].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.0f}"))
    axes[0].set_xlim(0, MAX_TIME_SECONDS)
    axes[1].set_xlim(0, MAX_TIME_SECONDS)
    axes[0].legend(fontsize=LEGEND_SIZE)
    axes[1].legend(fontsize=LEGEND_SIZE)
    for axis in axes:
        axis.tick_params(axis="both", labelsize=TICK_LABEL_SIZE)
    figure.tight_layout()
    figure.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(figure)


def plot_single_run(cwnd_data: pd.DataFrame, loss_data: pd.DataFrame, output_path: Path) -> None:
    single_cwnd_data, single_loss_data = summarize_single_run(cwnd_data, loss_data)
    sns.set_theme(style="whitegrid", context="talk")
    figure, axes = plt.subplots(
        2, 1, figsize=(14, 10), sharex=True, height_ratios=[3, 1.6]
    )
    axes[0].plot(
        single_cwnd_data["time_s"],
        single_cwnd_data["cwnd_mb"],
        linewidth=2.4,
        color="#4c72b0",
        label="cwnd",
    )
    axes[1].plot(
        single_loss_data["time_s"],
        single_loss_data["lost_packets"],
        linewidth=2.0,
        color="#c44e52",
        label="lost packets",
    )

    axes[0].set_xlabel("")
    axes[0].set_ylabel("cwnd [MB]", fontsize=AXIS_LABEL_SIZE)
    axes[0].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[0].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.2f}"))
    axes[1].set_xlabel("")
    axes[1].set_ylabel("# packets lost", fontsize=AXIS_LABEL_SIZE)
    axes[1].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[1].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.0f}"))
    axes[0].set_xlim(0, MAX_TIME_SECONDS)
    axes[1].set_xlim(0, MAX_TIME_SECONDS)
    axes[0].legend(fontsize=LEGEND_SIZE)
    axes[1].legend(fontsize=LEGEND_SIZE)
    for axis in axes:
        axis.tick_params(axis="both", labelsize=TICK_LABEL_SIZE)
    figure.tight_layout()
    figure.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(figure)


def plot_combined_recovery(
    measurement_summaries: list[tuple[str, pd.DataFrame, pd.DataFrame]], output_path: Path
) -> None:
    sns.set_theme(style="whitegrid", context="talk")
    figure, axes = plt.subplots(
        2, 1, figsize=(14, 10), sharex=True, height_ratios=[3, 1.6]
    )

    palette = sns.color_palette(n_colors=len(measurement_summaries))
    for color, (measurement_name, average_cwnd_data, average_loss_data) in zip(
        palette, measurement_summaries
    ):
        axes[0].plot(
            average_cwnd_data["time_s"],
            average_cwnd_data["cwnd_mb"],
            linewidth=2.4,
            color=color,
            label=measurement_name,
        )
        axes[0].fill_between(
            average_cwnd_data["time_s"],
            average_cwnd_data["cwnd_mb_lower"],
            average_cwnd_data["cwnd_mb_upper"],
            color=color,
            alpha=0.14,
            linewidth=0,
        )
        axes[1].plot(
            average_loss_data["time_s"],
            average_loss_data["lost_packets"],
            linewidth=2.0,
            color=color,
            label=measurement_name,
        )
        axes[1].fill_between(
            average_loss_data["time_s"],
            average_loss_data["lost_packets_lower"],
            average_loss_data["lost_packets_upper"],
            color=color,
            alpha=0.14,
            linewidth=0,
        )

    axes[0].set_xlabel("")
    axes[0].set_ylabel("cwnd [MB]", fontsize=AXIS_LABEL_SIZE)
    axes[0].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[0].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.2f}"))
    axes[1].set_xlabel("")
    axes[1].set_ylabel("# packets lost", fontsize=AXIS_LABEL_SIZE)
    axes[1].ticklabel_format(axis="y", style="plain", useOffset=False)
    axes[1].yaxis.set_major_formatter(FuncFormatter(lambda value, _: f"{value:.0f}"))
    axes[0].set_xlim(0, MAX_TIME_SECONDS)
    axes[1].set_xlim(0, MAX_TIME_SECONDS)
    axes[0].legend(fontsize=LEGEND_SIZE)
    axes[1].legend(fontsize=LEGEND_SIZE)
    for axis in axes:
        axis.tick_params(axis="both", labelsize=TICK_LABEL_SIZE)
    figure.tight_layout()
    figure.savefig(output_path, dpi=200, bbox_inches="tight")
    plt.close(figure)


def main() -> None:
    args = parse_args()
    root = args.root.resolve() if args.root else default_root()

    safe_retreat_dir = Path(__file__).resolve().parent
    if root == safe_retreat_dir:
        measurement_roots = find_measurement_roots(root)
        if not measurement_roots:
            raise SystemExit(f"No measurement directories found under {root}")
        measurement_summaries: list[tuple[str, pd.DataFrame, pd.DataFrame]] = []
        for measurement_root in measurement_roots:
            for run_dir in find_run_dirs(measurement_root):
                run_cwnd_data, run_loss_data = load_recovery_dataframes(run_dir)
                run_output_path = run_dir / "safe-retreat.pdf"
                plot_single_run(run_cwnd_data, run_loss_data, run_output_path)
                print(f"Wrote plot to {run_output_path}")
            cwnd_data, loss_data = load_recovery_dataframes(measurement_root)
            output_path = measurement_root / "safe-retreat.pdf"
            plot_recovery(cwnd_data, loss_data, output_path)
            average_cwnd_data, average_loss_data = summarize_recovery(cwnd_data, loss_data)
            measurement_summaries.append(
                (measurement_root.name, average_cwnd_data, average_loss_data)
            )
            print(f"Wrote plot to {output_path}")
        combined_output_path = root / "safe-retreat.pdf"
        plot_combined_recovery(measurement_summaries, combined_output_path)
        print(f"Wrote plot to {combined_output_path}")
        return

    output_path = args.output.resolve() if args.output else root / "safe-retreat.pdf"
    for run_dir in find_run_dirs(root):
        run_cwnd_data, run_loss_data = load_recovery_dataframes(run_dir)
        run_output_path = run_dir / "safe-retreat.pdf"
        plot_single_run(run_cwnd_data, run_loss_data, run_output_path)
        print(f"Wrote plot to {run_output_path}")
    cwnd_data, loss_data = load_recovery_dataframes(root)
    plot_recovery(cwnd_data, loss_data, output_path)
    print(f"Wrote plot to {output_path}")


if __name__ == "__main__":
    main()
