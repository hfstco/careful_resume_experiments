#!/usr/bin/env python3
import math
import re
import subprocess
import sys
from collections import Counter
from collections import defaultdict
from pathlib import Path


TIMESTAMP_DIR_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2}$")
PACKET_PATTERN = re.compile(
    r"^(?P<timestamp>\d+\.\d+)\s+IP6?\s+(?P<src>\S+)\s+>\s+(?P<dst>\S+):.*length\s+(?P<length>\d+)\s*$"
)

BASE_DIR = Path(__file__).resolve().parent
BIN_WIDTH_SECONDS = 1.0
PORT_START = 50000
PORT_END = 50050
SHOW_PLOTS = False


def split_endpoint(endpoint: str) -> tuple[str, int] | None:
    head, separator, tail = endpoint.rpartition(".")
    if not separator or not tail.isdigit():
        return None
    return head, int(tail)


def infer_client_ip(packet_lines: list[tuple[str, str]]) -> str | None:
    client_candidates: Counter[str] = Counter()
    for src, dst in packet_lines:
        src_endpoint = split_endpoint(src)
        dst_endpoint = split_endpoint(dst)
        if src_endpoint is None or dst_endpoint is None:
            continue

        src_host, src_port = src_endpoint
        dst_host, dst_port = dst_endpoint
        if PORT_START <= src_port <= PORT_END and not (PORT_START <= dst_port <= PORT_END):
            client_candidates[dst_host] += 1
        if PORT_START <= dst_port <= PORT_END and not (PORT_START <= src_port <= PORT_END):
            client_candidates[src_host] += 1

    if not client_candidates:
        return None
    return client_candidates.most_common(1)[0][0]


def detect_incoming_flow_port(
    src: str,
    dst: str,
    client_ip: str,
    port_start: int,
    port_end: int,
) -> int | None:
    src_endpoint = split_endpoint(src)
    dst_endpoint = split_endpoint(dst)
    if src_endpoint is None or dst_endpoint is None:
        return None

    src_host, src_port = src_endpoint
    dst_host, dst_port = dst_endpoint
    if dst_host != client_ip:
        return None
    if not (port_start <= src_port <= port_end):
        return None
    if port_start <= dst_port <= port_end:
        return None
    return src_port


def load_received_packets(pcap_path: Path, port_start: int, port_end: int) -> list[tuple[float, int, int]]:
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
    if result.returncode != 0:
        raise RuntimeError(
            f"tcpdump failed for {pcap_path} with exit code {result.returncode}:\n{result.stderr.strip()}"
        )

    parsed_lines: list[tuple[float, str, str, int]] = []
    endpoint_pairs: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        match = PACKET_PATTERN.match(line.strip())
        if not match:
            continue
        parsed_lines.append(
            (
                float(match.group("timestamp")),
                match.group("src"),
                match.group("dst"),
                int(match.group("length")),
            )
        )
        endpoint_pairs.append((match.group("src"), match.group("dst")))

    client_ip = infer_client_ip(endpoint_pairs)
    if client_ip is None:
        return []

    packets: list[tuple[float, int, int]] = []
    for timestamp, src, dst, length in parsed_lines:
        flow_port = detect_incoming_flow_port(
            src,
            dst,
            client_ip,
            port_start,
            port_end,
        )
        if flow_port is None:
            continue

        packets.append(
            (
                timestamp,
                flow_port,
                length,
            )
        )

    return packets


def build_series(
    packets: list[tuple[float, int, int]],
    start_time: float,
    end_time: float,
    bin_width: float,
) -> tuple[list[float], dict[int, list[float]]]:
    bin_count = max(1, math.ceil((end_time - start_time) / bin_width))
    times = [index * bin_width for index in range(bin_count)]
    bytes_per_flow: dict[int, list[int]] = defaultdict(lambda: [0] * bin_count)

    for timestamp, flow_port, payload_bytes in packets:
        offset = max(0.0, timestamp - start_time)
        bin_index = min(bin_count - 1, int(offset / bin_width))
        bytes_per_flow[flow_port][bin_index] += payload_bytes

    throughput_per_flow = {
        flow_port: [payload * 8 / (bin_width * 1_000_000) for payload in payloads]
        for flow_port, payloads in sorted(bytes_per_flow.items())
    }
    return times, throughput_per_flow


def plot_run(
    run_dir: Path,
    capture: tuple[list[float], dict[int, list[float]]],
    output_path: Path,
    show: bool,
) -> None:
    try:
        import seaborn as sns

        if show:
            import matplotlib.pyplot as plt
        else:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError(
            "seaborn and matplotlib are required to render throughput plots. "
            "Install them with `python3 -m pip install seaborn matplotlib` and rerun the script."
        ) from error

    sns.set_theme(style="whitegrid", context="talk")
    figure, axis = plt.subplots(1, 1, figsize=(14, 6), constrained_layout=True)
    figure.suptitle(f"Client-side received TCP/UDP throughput by flow port\n{run_dir.name}")

    times, throughput_per_flow = capture
    if throughput_per_flow:
        for flow_port, values in throughput_per_flow.items():
            sns.lineplot(
                x=times,
                y=values,
                ax=axis,
                linewidth=1.5,
                label=str(flow_port),
            )
        axis.legend(
            title="Flow port",
            ncols=4,
            fontsize="small",
            title_fontsize="small",
            loc="upper right",
        )
    else:
        axis.text(0.5, 0.5, "No matching TCP packets found", ha="center", va="center", transform=axis.transAxes)
    axis.set_ylabel("Throughput (Mbit/s)")
    axis.set_xlabel("Time since first received packet (s)")
    axis.set_title("client.pcap")
    axis.grid(True, alpha=0.3)
    axis.ticklabel_format(style="plain", axis="both", useOffset=False)
    figure.savefig(output_path, dpi=200)
    if show:
        plt.show()
    plt.close(figure)


def iter_run_directories(base_dir: Path) -> list[Path]:
    return sorted(
        path
        for path in base_dir.iterdir()
        if path.is_dir() and TIMESTAMP_DIR_PATTERN.match(path.name)
    )


def main() -> int:
    if BIN_WIDTH_SECONDS <= 0:
        print("BIN_WIDTH_SECONDS must be greater than 0", file=sys.stderr)
        return 2
    if PORT_START > PORT_END:
        print("PORT_START must be less than or equal to PORT_END", file=sys.stderr)
        return 2

    run_directories = iter_run_directories(BASE_DIR)
    if not run_directories:
        print(f"No timestamp directories found in {BASE_DIR}", file=sys.stderr)
        return 1

    for run_dir in run_directories:
        client_pcap = run_dir / "client.pcap"
        if not client_pcap.exists():
            print(f"Skipping {run_dir.name}: missing client.pcap", file=sys.stderr)
            continue

        client_packets = load_received_packets(client_pcap, PORT_START, PORT_END)
        if not client_packets:
            print(
                f"Skipping {run_dir.name}: no matching received TCP/UDP packets in configured port range",
                file=sys.stderr,
            )
            continue

        start_time = min(packet[0] for packet in client_packets)
        end_time = max(packet[0] for packet in client_packets) + BIN_WIDTH_SECONDS
        capture = build_series(client_packets, start_time, end_time, BIN_WIDTH_SECONDS)

        output_path = run_dir / "tcp_throughput.png"
        plot_run(run_dir, capture, output_path, SHOW_PLOTS)
        print(f"Wrote {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
