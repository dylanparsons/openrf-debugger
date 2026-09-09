"""Generate a tiny synthetic IEEE 802.15.4 PCAP for local testing."""

from scapy.all import wrpcap
from scapy.layers.dot15d4 import Dot15d4

packet = Dot15d4(fcf_frametype=1)
packet.time = 1710000000.150

wrpcap("sample.pcap", [packet])

print("Wrote sample.pcap")
