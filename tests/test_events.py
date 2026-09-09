from types import SimpleNamespace

from openrf.correlation.events import HardwareEvent, correlate_events


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
