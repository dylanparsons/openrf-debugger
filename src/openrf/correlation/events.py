"""Timestamped hardware events and packet correlation."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Literal

Direction = Literal["nearest", "after", "before"]


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


def _is_candidate(event_ts: float, packet_ts: float, direction: Direction) -> bool:
    if direction == "after":
        return event_ts >= packet_ts
    if direction == "before":
        return event_ts <= packet_ts
    return True


def correlate_events(
    packets: list[Any],
    events: list[HardwareEvent],
    max_delta_ms: float = 100.0,
    direction: Direction = "nearest",
    clock_offset_ms: float = 0.0,
    consume_events: bool = True,
) -> list[Correlation]:
    """Match each packet with a hardware event within a time window.

    direction: "nearest" matches either direction, "after"/"before"
    restrict to events that happened at or after/before the packet.
    clock_offset_ms is added to event timestamps before matching, to
    correct for packets and events coming from unsynchronized clocks.
    consume_events (default True) stops one event from matching more
    than one packet.
    """
    remaining = [
        HardwareEvent(
            timestamp=event.timestamp + clock_offset_ms / 1000.0,
            source=event.source,
            kind=event.kind,
            description=event.description,
        )
        for event in events
    ]
    used_indices: set[int] = set()
    correlations: list[Correlation] = []

    for packet in packets:
        packet_ts = float(getattr(packet, "time", 0.0))

        best_index = None
        best_delta_ms = None
        for index, event in enumerate(remaining):
            if consume_events and index in used_indices:
                continue
            if not _is_candidate(event.timestamp, packet_ts, direction):
                continue
            delta_ms = (event.timestamp - packet_ts) * 1000.0
            if best_delta_ms is None or abs(delta_ms) < abs(best_delta_ms):
                best_index = index
                best_delta_ms = delta_ms

        if best_index is None or best_delta_ms is None:
            continue
        if abs(best_delta_ms) > max_delta_ms:
            continue

        event = remaining[best_index]
        correlations.append(
            Correlation(
                packet_timestamp=packet_ts,
                event_timestamp=event.timestamp,
                delta_ms=best_delta_ms,
                event_description=event.description,
            )
        )
        if consume_events:
            used_indices.add(best_index)

    return correlations


@dataclass
class _PendingPacket:
    timestamp: float
    arrived_at: float


class StreamCorrelator:
    """Correlates packets and events live, without requiring both lists
    up front (see correlate_events for the batch case).

    Buffers unmatched packets and events and resolves matches as new data
    arrives. Call flush() periodically so packets waiting on an event
    that never shows up don't wait forever.
    """

    def __init__(
        self,
        max_delta_ms: float = 100.0,
        direction: Direction = "nearest",
        clock_offset_ms: float = 0.0,
    ) -> None:
        self._max_delta_ms = max_delta_ms
        self._direction = direction
        self._clock_offset_s = clock_offset_ms / 1000.0
        self._pending_packets: Deque[_PendingPacket] = deque()
        self._pending_events: Deque[HardwareEvent] = deque()

    def add_packet(self, timestamp: float, now: float | None = None) -> list[Correlation]:
        self._pending_packets.append(
            _PendingPacket(timestamp=timestamp, arrived_at=now if now is not None else timestamp)
        )
        return self._resolve()

    def add_event(self, event: HardwareEvent) -> list[Correlation]:
        shifted = HardwareEvent(
            timestamp=event.timestamp + self._clock_offset_s,
            source=event.source,
            kind=event.kind,
            description=event.description,
        )
        self._pending_events.append(shifted)
        return self._resolve()

    def flush(self, now: float) -> list[Correlation]:
        while self._pending_packets:
            oldest = self._pending_packets[0]
            if (now - oldest.arrived_at) * 1000.0 <= self._max_delta_ms:
                break
            self._pending_packets.popleft()
        return []

    def _resolve(self) -> list[Correlation]:
        resolved: list[Correlation] = []
        remaining_packets: Deque[_PendingPacket] = deque()

        while self._pending_packets:
            packet = self._pending_packets.popleft()
            match_index = None
            match_delta_ms = None

            for index, event in enumerate(self._pending_events):
                if not _is_candidate(event.timestamp, packet.timestamp, self._direction):
                    continue
                delta_ms = (event.timestamp - packet.timestamp) * 1000.0
                if match_delta_ms is None or abs(delta_ms) < abs(match_delta_ms):
                    match_index = index
                    match_delta_ms = delta_ms

            if (
                match_index is not None
                and match_delta_ms is not None
                and abs(match_delta_ms) <= self._max_delta_ms
            ):
                event = self._pending_events[match_index]
                del self._pending_events[match_index]
                resolved.append(
                    Correlation(
                        packet_timestamp=packet.timestamp,
                        event_timestamp=event.timestamp,
                        delta_ms=match_delta_ms,
                        event_description=event.description,
                    )
                )
            else:
                remaining_packets.append(packet)

        self._pending_packets = remaining_packets
        return resolved
