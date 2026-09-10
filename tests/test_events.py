from types import SimpleNamespace

from openrf.correlation.events import HardwareEvent, StreamCorrelator, correlate_events


def test_event_from_dict():
    event = HardwareEvent.from_dict(
        {
            "timestamp": 10.5,
            "source": "uart",
            "kind": "tx",
            "description": "command transmitted",
        }
    )

    assert event.timestamp == 10.5
    assert event.source == "uart"


def test_correlates_nearest_event():
    packet = SimpleNamespace(time=10.500)
    event = HardwareEvent(
        timestamp=10.510,
        source="gpio",
        kind="edge",
        description="status asserted",
    )

    result = correlate_events([packet], [event], max_delta_ms=20)

    assert len(result) == 1
    assert round(result[0].delta_ms, 3) == 10.0


def test_events_are_not_reused_across_packets():
    packets = [SimpleNamespace(time=10.000), SimpleNamespace(time=10.005)]
    event = HardwareEvent(
        timestamp=10.002, source="gpio", kind="edge", description="edge"
    )

    result = correlate_events(packets, [event], max_delta_ms=50)

    assert len(result) == 1


def test_direction_after_ignores_earlier_events():
    packet = SimpleNamespace(time=10.000)
    earlier = HardwareEvent(
        timestamp=9.995, source="gpio", kind="edge", description="before"
    )
    later = HardwareEvent(
        timestamp=10.010, source="gpio", kind="edge", description="after"
    )

    result = correlate_events(
        [packet], [earlier, later], max_delta_ms=50, direction="after"
    )

    assert len(result) == 1
    assert result[0].event_description == "after"


def test_clock_offset_shifts_event_timestamps():
    packet = SimpleNamespace(time=10.000)
    event = HardwareEvent(
        timestamp=9.900, source="gpio", kind="edge", description="edge"
    )

    assert correlate_events([packet], [event], max_delta_ms=20) == []

    result = correlate_events(
        [packet], [event], max_delta_ms=20, clock_offset_ms=100.0
    )
    assert len(result) == 1
    assert round(result[0].delta_ms, 3) == 0.0


def test_stream_correlator_matches_as_data_arrives():
    correlator = StreamCorrelator(max_delta_ms=50)

    assert correlator.add_packet(timestamp=10.000) == []

    event = HardwareEvent(
        timestamp=10.010, source="gpio", kind="edge", description="edge"
    )
    resolved = correlator.add_event(event)

    assert len(resolved) == 1
    assert round(resolved[0].delta_ms, 3) == 10.0


def test_stream_correlator_flush_drops_stale_packets():
    correlator = StreamCorrelator(max_delta_ms=50)
    correlator.add_packet(timestamp=10.000, now=10.000)

    correlator.flush(now=10.200)

    event = HardwareEvent(
        timestamp=10.010, source="gpio", kind="edge", description="edge"
    )
    assert correlator.add_event(event) == []
