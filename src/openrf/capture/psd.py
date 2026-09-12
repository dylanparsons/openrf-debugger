"""TI SmartRF Packet Sniffer PSD loading helpers."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Any, Iterator

from scapy.layers.dot15d4 import Dot15d4
from scapy.all import conf

conf.dot15d4_protocol = "zigbee"

RECORD_SIZE = 151
HEADER_SIZE = 14
TIME_DIVISOR = 32

FLAG_FCS_INCLUDED_IN_LENGTH = 1 << 0
FLAG_CORRELATION_USED = 1 << 1
FLAG_INCOMPLETE_PACKET = 1 << 2
FLAG_BUFFER_OVERFLOW = 1 << 3
FLAG_GENERIC_PROTOCOL = 1 << 4

STATUS_CRC_OK = 1 << 7


def _parse_records(data: bytes) -> Iterator[Any]:
    if len(data) % RECORD_SIZE:
        raise ValueError(
            f"invalid PSD size: {len(data)} bytes "
            f"is not a multiple of {RECORD_SIZE}"
        )

    first_timestamp: int | None = None

    for offset in range(0, len(data), RECORD_SIZE):
        record = data[offset : offset + RECORD_SIZE]

        packet_info = record[0]
        packet_number = int.from_bytes(record[1:5], "little")
        raw_timestamp = int.from_bytes(record[5:13], "little")
        length = record[13]

        if length < 2:
            raise ValueError(
                f"packet {packet_number}: invalid length {length}"
            )

        if length > RECORD_SIZE - HEADER_SIZE:
            raise ValueError(
                f"packet {packet_number}: length {length} "
                "exceeds record capacity"
            )

        packet_data = record[
            HEADER_SIZE : HEADER_SIZE + length
        ]

        # TI's 802.15.4 capture format replaces the on-air FCS
        # with RSSI and status bytes.
        frame = packet_data[:-2]
        rssi = struct.unpack("b", packet_data[-2:-1])[0]
        status = packet_data[-1]

        if first_timestamp is None:
            first_timestamp = raw_timestamp

        timestamp = (
            (raw_timestamp - first_timestamp)
            / TIME_DIVISOR
            / 1_000_000
        )

        packet = Dot15d4(frame)
        packet.time = timestamp

        # Preserve TI sniffer metadata.
        packet.psd_packet_number = packet_number
        packet.psd_packet_info = packet_info
        packet.psd_raw_timestamp = raw_timestamp
        packet.psd_rssi = rssi
        packet.psd_status = status
        packet.psd_crc_ok = bool(status & STATUS_CRC_OK)
        packet.psd_lqi = status & 0x7F
        packet.psd_correlation_used = bool(
            packet_info & FLAG_CORRELATION_USED
        )
        packet.psd_incomplete = bool(
            packet_info & FLAG_INCOMPLETE_PACKET
        )
        packet.psd_buffer_overflow = bool(
            packet_info & FLAG_BUFFER_OVERFLOW
        )
        packet.psd_generic_protocol = bool(
            packet_info & FLAG_GENERIC_PROTOCOL
        )
        packet.psd_fcs_in_length = bool(
            packet_info & FLAG_FCS_INCLUDED_IN_LENGTH
        )

        yield packet


def load_psd(path: str | Path) -> list[Any]:
    """Load packets from a TI SmartRF Packet Sniffer PSD file."""
    return list(_parse_records(Path(path).read_bytes()))
