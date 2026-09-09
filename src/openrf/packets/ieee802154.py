"""IEEE 802.15.4 packet inspection helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:
    from scapy.layers.dot15d4 import Dot15d4
except ImportError:  # pragma: no cover
    Dot15d4 = None


@dataclass(frozen=True)
class PacketSummary:
    timestamp: float
    length: int
    frame_type: str


def frame_type_name(packet: Any) -> str:
    """Return a readable IEEE 802.15.4 frame type when available."""
    if Dot15d4 is None or not packet.haslayer(Dot15d4):
        return "unknown"

    layer = packet.getlayer(Dot15d4)
    fcf_frametype = getattr(layer, "fcf_frametype", None)

    names = {
        0: "beacon",
        1: "data",
        2: "acknowledgement",
        3: "command",
    }
    return names.get(fcf_frametype, f"reserved({fcf_frametype})")


def summarize_packet(packet: Any) -> PacketSummary:
    timestamp = float(getattr(packet, "time", 0.0))
    length = len(packet)
    return PacketSummary(
        timestamp=timestamp,
        length=length,
        frame_type=frame_type_name(packet),
    )
