import pytest

from openrf.capture.logic_analyzer import parse_vcd

SAMPLE_VCD = """\
$date today $end
$version sigrok-cli $end
$timescale 1 ns $end
$scope module logic $end
$var wire 1 ! CH0 $end
$var wire 1 " CH1 $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
0!
0"
$end
#1000
1!
#2500
1"
#5000
0!
"""


def test_parses_transitions_with_correct_names_and_edges():
    events = list(parse_vcd(SAMPLE_VCD.splitlines(), start_time=100.0))

    # $dumpvars sets initial state (0!, 0") -- these are also transitions
    # from "unknown" and are reported like any other edge.
    descriptions = [event.description for event in events]
    assert "CH0 falling" in descriptions[:2]
    assert "CH1 falling" in descriptions[:2]

    rising_ch0 = next(e for e in events if e.description == "CH0 rising")
    assert rising_ch0.timestamp - 100.0 == pytest.approx(1000 * 1e-9)

    rising_ch1 = next(e for e in events if e.description == "CH1 rising")
    assert rising_ch1.timestamp - 100.0 == pytest.approx(2500 * 1e-9)

    falling_ch0 = [e for e in events if e.description == "CH0 falling"]
    assert len(falling_ch0) == 2  # initial dumpvars state + the real transition
    assert falling_ch0[-1].timestamp - 100.0 == pytest.approx(5000 * 1e-9)


def test_events_carry_the_configured_source_name():
    events = list(
        parse_vcd(SAMPLE_VCD.splitlines(), start_time=0.0, source_name="my_la")
    )
    assert all(event.source == "my_la" for event in events)
    assert all(event.kind == "edge" for event in events)


def test_respects_microsecond_timescale():
    vcd = """\
$timescale 1 us $end
$var wire 1 ! CH0 $end
$enddefinitions $end
#0
0!
#10
1!
"""
    events = list(parse_vcd(vcd.splitlines(), start_time=0.0))
    rising = next(e for e in events if e.description == "CH0 rising")
    assert rising.timestamp == pytest.approx(10 * 1e-6)
