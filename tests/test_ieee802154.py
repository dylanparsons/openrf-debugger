from scapy.layers.dot15d4 import Dot15d4

from openrf.packets.ieee802154 import frame_type_name, summarize_packet


def test_ieee802154_data_frame():
    packet = Dot15d4(fcf_frametype=1)

    assert frame_type_name(packet) == "data"

    summary = summarize_packet(packet)
    assert summary.length == len(packet)
    assert summary.frame_type == "data"
