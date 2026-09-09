"""Command-line interface for OpenRF Debugger."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from openrf.capture.pcap import load_pcap
from openrf.correlation.events import HardwareEvent, correlate_events
from openrf.packets.ieee802154 import summarize_packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openrf",
        description="Analyze and correlate RF protocol and embedded-device events.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect packets in a PCAP file.")
    inspect_cmd.add_argument("pcap", type=Path)

    packets_cmd = sub.add_parser("packets", help="Print packet summaries.")
    packets_cmd.add_argument("pcap", type=Path)

    correlate_cmd = sub.add_parser(
        "correlate",
        help="Correlate RF packets with hardware events.",
    )
    correlate_cmd.add_argument("pcap", type=Path)
    correlate_cmd.add_argument("events", type=Path)

    return parser


def _print_packets(path: Path) -> None:
    packets = load_pcap(path)
    for index, packet in enumerate(packets):
        summary = summarize_packet(packet)
        print(
            f"{index:04d} "
            f"ts={summary.timestamp:.6f} "
            f"len={summary.length} "
            f"frame_type={summary.frame_type}"
        )


def _load_events(path: Path) -> list[HardwareEvent]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [HardwareEvent.from_dict(item) for item in raw]


def main() -> int:
    args = build_parser().parse_args()

    if args.command in {"inspect", "packets"}:
        _print_packets(args.pcap)
        return 0

    if args.command == "correlate":
        packets = load_pcap(args.pcap)
        events = _load_events(args.events)
        correlations = correlate_events(packets, events)

        for correlation in correlations:
            print(
                f"packet_ts={correlation.packet_timestamp:.6f} "
                f"event_ts={correlation.event_timestamp:.6f} "
                f"delta_ms={correlation.delta_ms:.3f} "
                f"event={correlation.event_description}"
            )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
