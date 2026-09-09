"""PCAP loading helpers."""

from pathlib import Path
from typing import Any

from scapy.all import rdpcap


def load_pcap(path: str | Path) -> list[Any]:
    """Load packets from a PCAP/PCAPNG file."""
    return list(rdpcap(str(path)))
