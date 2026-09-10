"""Live capture from CC2531-class sniffer dongles.

Frames are yielded as they arrive over serial, instead of requiring a
complete PCAP file up front (see capture.pcap.load_pcap for that case).

Implements the sensniff firmware framing (4-byte magic b"Snif", version
byte, length byte, payload). Stock TI sniffer firmware and the
cc2531_usb_wpan_adapter firmware use different protocols -- swap
read_sensniff_frame for those.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Iterator, Protocol

SENSNIFF_MAGIC = b"Snif"


def read_sensniff_frame(
    read: Callable[[int], bytes], readline: Callable[[], bytes]
) -> bytes | None:
    """Read one sensniff frame from a transport, returning its payload.

    Takes read/readline callables rather than a serial object so this can
    be tested against an in-memory buffer. Returns None on timeout, short
    read, or non-frame debug text sharing the UART.
    """
    magic = read(4)
    if len(magic) < 4:
        return None

    if magic != SENSNIFF_MAGIC:
        # sensniff shares the UART with debug logging; drain the line
        # instead of resyncing byte-by-byte.
        readline()
        return None

    header = read(2)
    if len(header) < 2:
        return None

    _version, size = header[0], header[1]
    payload = read(size)
    if len(payload) < size:
        return None

    return payload


@dataclass(frozen=True)
class LivePacket:
    """A captured frame and the host-clock time it arrived.

    Not a device-side capture timestamp -- sensniff doesn't send one, and
    this is subject to USB/serial buffering latency. Use clock_offset_ms
    on the correlator to calibrate against another timestamp source.
    """

    timestamp: float
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)


class CaptureSource(Protocol):
    def read_packets(self) -> Iterator[LivePacket]:
        ...


class SensniffSource:
    """Reads frames from a CC2531 dongle running sensniff firmware.

    Requires the pyserial extra (pip install -e ".[live]").

        with SensniffSource("/dev/ttyACM0") as source:
            source.set_channel(15)
            for packet in source.read_packets():
                ...
    """

    def __init__(self, port: str, baudrate: int = 115200, timeout: float = 1.0) -> None:
        try:
            import serial
        except ImportError as exc:  # pragma: no cover - exercised via extras
            raise RuntimeError(
                'SensniffSource requires pyserial. Install with: pip install -e ".[live]"'
            ) from exc

        self._serial = serial.Serial(port, baudrate=baudrate, timeout=timeout)

    def set_channel(self, channel: int) -> None:
        if not 11 <= channel <= 26:
            raise ValueError("IEEE 802.15.4 channels range from 11 to 26")
        self._serial.write(bytes([channel]))

    def close(self) -> None:
        self._serial.close()

    def __enter__(self) -> "SensniffSource":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def read_packets(self) -> Iterator[LivePacket]:
        while True:
            frame = read_sensniff_frame(self._serial.read, self._serial.readline)
            if frame is not None:
                yield LivePacket(timestamp=time.time(), payload=frame)
