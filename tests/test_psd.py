from pathlib import Path

import pytest

from openrf.capture.psd import load_psd


SAMPLE_PSD = Path(__file__).parents[1] / "tools" / "sample.psd"


def test_load_sample_psd():
    packets = load_psd(SAMPLE_PSD)

    assert len(packets) == 7

    first = packets[0]

    assert first.psd_packet_number == 1
    assert first.psd_rssi == -116
    assert first.psd_crc_ok is True
    assert first.psd_raw_timestamp > 0

    assert first.haslayer("Dot15d4")
    assert first.seqnum == 78


def test_psd_packet_numbers_are_sequential():
    packets = load_psd(SAMPLE_PSD)

    assert [packet.psd_packet_number for packet in packets] == list(range(1, 8))


def test_invalid_psd_size(tmp_path):
    path = tmp_path / "invalid.psd"
    path.write_bytes(b"\x00")

    with pytest.raises(ValueError, match="multiple"):
        load_psd(path)
