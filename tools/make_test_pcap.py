from scapy.all import wrpcap, Raw
from scapy.layers.dot15d4 import Dot15d4, Dot15d4Data

packet = (
    Dot15d4(
        fcf_frametype=1,
        fcf_panidcompress=0,
        fcf_srcaddrmode=2,
        fcf_destaddrmode=2,
        seqnum=1,
    )
    / Dot15d4Data(
        dest_panid=0x1234,
        dest_addr=0x5678,
        src_panid=0x1234,
        src_addr=0x1234,
    )
    / Raw(b"OpenRF test packet")
)

wrpcap("test.pcap", [packet])
print("Wrote test.pcap")
