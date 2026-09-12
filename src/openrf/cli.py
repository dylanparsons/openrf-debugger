"""Command-line interface for OpenRF Debugger."""

from __future__ import annotations

import argparse
import json
import threading
from pathlib import Path

from openrf.capture.pcap import load_pcap
from openrf.capture.psd import load_psd
from openrf.correlation.events import HardwareEvent, StreamCorrelator, correlate_events
from openrf.packets.ieee802154 import summarize_packet


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openrf",
        description="Analyze and correlate RF protocol and embedded-device events.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect packets in a capture file.")
    inspect_cmd.add_argument("pcap", type=Path)

    packets_cmd = sub.add_parser("packets", help="Print packet summaries.")
    packets_cmd.add_argument("pcap", type=Path)

    correlate_cmd = sub.add_parser(
        "correlate",
        help="Correlate RF packets with hardware events.",
    )
    correlate_cmd.add_argument("pcap", type=Path)
    correlate_cmd.add_argument("events", type=Path)
    correlate_cmd.add_argument(
        "--direction",
        choices=["nearest", "after", "before"],
        default="nearest",
        help="Match events after/before the packet, or nearest either way (default: nearest).",
    )
    correlate_cmd.add_argument(
        "--max-delta-ms",
        type=float,
        default=100.0,
        help="Maximum packet/event time gap to count as a match (default: 100ms).",
    )
    correlate_cmd.add_argument(
        "--clock-offset-ms",
        type=float,
        default=0.0,
        help="Shift event timestamps by this amount before matching.",
    )

    live_cmd = sub.add_parser(
        "live",
        help="Live-capture from a sensniff-firmware sniffer dongle, "
        "optionally correlating with hardware events as they arrive.",
    )
    live_cmd.add_argument("--port", required=True, help="Serial port, e.g. /dev/ttyACM0")
    live_cmd.add_argument("--baudrate", type=int, default=115200)
    live_cmd.add_argument(
        "--channel", type=int, default=None, help="IEEE 802.15.4 channel (11-26)"
    )
    live_cmd.add_argument(
        "--events",
        type=Path,
        default=None,
        help="Events JSON file to correlate against. Mutually exclusive with --logic-analyzer.",
    )
    live_cmd.add_argument(
        "--logic-analyzer",
        action="store_true",
        help="Correlate against live edges from a sigrok-supported logic analyzer. "
        "Requires sigrok-cli on PATH.",
    )
    live_cmd.add_argument("--la-driver", default="fx2lafw")
    live_cmd.add_argument("--la-samplerate", default="1m")
    live_cmd.add_argument(
        "--la-channels", default=None, help="Comma-separated channel list, e.g. 0,1,2,3"
    )
    live_cmd.add_argument(
        "--direction", choices=["nearest", "after", "before"], default="nearest"
    )
    live_cmd.add_argument("--max-delta-ms", type=float, default=100.0)
    live_cmd.add_argument("--clock-offset-ms", type=float, default=0.0)

    return parser


def _load_capture(path: Path):
    suffix = path.suffix.lower()

    if suffix == ".psd":
        return load_psd(path)

    if suffix in {".pcap", ".pcapng"}:
        return load_pcap(path)

    raise ValueError(
        f"Unsupported capture format: {suffix or '<none>'}. "
        "Expected .psd, .pcap, or .pcapng."
    )


def _print_packets(path: Path) -> None:
    packets = _load_capture(path)
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


def _print_correlation(correlation) -> None:  # type: ignore[no-untyped-def]
    print(
        f"packet_ts={correlation.packet_timestamp:.6f} "
        f"event_ts={correlation.event_timestamp:.6f} "
        f"delta_ms={correlation.delta_ms:.3f} "
        f"event={correlation.event_description}"
    )


def main() -> int:
    args = build_parser().parse_args()

    if args.command in {"inspect", "packets"}:
        _print_packets(args.pcap)
        return 0

    if args.command == "correlate":
        packets = _load_capture(args.pcap)
        events = _load_events(args.events)
        correlations = correlate_events(
            packets,
            events,
            max_delta_ms=args.max_delta_ms,
            direction=args.direction,
            clock_offset_ms=args.clock_offset_ms,
        )
        for correlation in correlations:
            _print_correlation(correlation)
        return 0

    if args.command == "live":
        return _run_live(args)

    return 1


def _run_live(args: argparse.Namespace) -> int:
    from openrf.capture.live import SensniffSource

    if args.events is not None and args.logic_analyzer:
        print("error: --events and --logic-analyzer are mutually exclusive")
        return 1

    try:
        source = SensniffSource(args.port, baudrate=args.baudrate)
    except RuntimeError as exc:
        print(f"error: {exc}")
        return 1

    with source:
        if args.channel is not None:
            source.set_channel(args.channel)

        if args.events is None and not args.logic_analyzer:
            for packet in source.read_packets():
                print(f"ts={packet.timestamp:.6f} len={packet.length}")
            return 0

        correlator = StreamCorrelator(
            max_delta_ms=args.max_delta_ms,
            direction=args.direction,
            clock_offset_ms=args.clock_offset_ms,
        )
        lock = threading.Lock()

        if args.events is not None:
            for event in _load_events(args.events):
                correlator.add_event(event)
            for packet in source.read_packets():
                for correlation in correlator.add_packet(packet.timestamp):
                    _print_correlation(correlation)
            return 0

        # events stream in on a background thread while the main thread
        # reads packets, since both sides block
        from openrf.capture.logic_analyzer import LogicAnalyzerConfig, LogicAnalyzerSource

        la_config = LogicAnalyzerConfig(
            driver=args.la_driver,
            samplerate=args.la_samplerate,
            channels=args.la_channels,
        )
        la_source = LogicAnalyzerSource(la_config)

        def feed_events() -> None:
            try:
                with la_source:
                    for event in la_source.read_events():
                        with lock:
                            resolved = correlator.add_event(event)
                        for correlation in resolved:
                            _print_correlation(correlation)
            except RuntimeError as exc:
                print(f"error: {exc}")

        thread = threading.Thread(target=feed_events, daemon=True)
        thread.start()

        for packet in source.read_packets():
            with lock:
                resolved = correlator.add_packet(packet.timestamp)
            for correlation in resolved:
                _print_correlation(correlation)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
