"""Timestamped hardware events and packet correlation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HardwareEvent:
    timestamp: float
    source: str
    kind: str
    description: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "HardwareEvent":
        return cls(
            timestamp=float(value["timestamp"]),
            source=str(value["source"]),
            kind=str(value["kind"]),
            description=str(value["description"]),
        )


@dataclass(frozen=True)
class Correlation:
    packet_timestamp: float
    event_timestamp: float
    delta_ms: float
    event_description: str


def correlate_events(
    packets: list[Any],
    events: list[HardwareEvent],
    max_delta_ms: float = 100.0,
) -> list[Correlation]:
    """Match each packet with the closest hardware event within a time window."""
    correlations: list[Correlation] = []

    for packet in packets:
        packet_ts = float(getattr(packet, "time", 0.0))
        if not events:
            continue

        event = min(events, key=lambda item: abs(item.timestamp - packet_ts))
        delta_ms = (event.timestamp - packet_ts) * 1000.0

        if abs(delta_ms) <= max_delta_ms:
            correlations.append(
                Correlation(
                    packet_timestamp=packet_ts,
                    event_timestamp=event.timestamp,
                    delta_ms=delta_ms,
                    event_description=event.description,
                )
            )

    return correlations
