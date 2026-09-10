from openrf.capture.live import read_sensniff_frame


class FakeTransport:
    """Minimal stand-in for a pyserial.Serial object's read/readline."""

    def __init__(self, data: bytes):
        self._buf = data

    def read(self, n: int) -> bytes:
        chunk, self._buf = self._buf[:n], self._buf[n:]
        return chunk

    def readline(self) -> bytes:
        if b"\n" not in self._buf:
            line, self._buf = self._buf, b""
            return line
        line, self._buf = self._buf.split(b"\n", 1)
        return line + b"\n"


def test_reads_a_well_formed_frame():
    payload = bytes([0x61, 0x88, 0x00, 0xFF, 0xFF])
    frame = b"Snif" + bytes([1, len(payload)]) + payload
    transport = FakeTransport(frame)

    result = read_sensniff_frame(transport.read, transport.readline)

    assert result == payload


def test_skips_non_frame_debug_text():
    data = b"sniffer: booted\nSnif" + bytes([1, 2]) + b"\xaa\xbb"
    transport = FakeTransport(data)

    # First read consumes the debug line and returns None.
    first = read_sensniff_frame(transport.read, transport.readline)
    assert first is None

    second = read_sensniff_frame(transport.read, transport.readline)
    assert second == b"\xaa\xbb"


def test_returns_none_on_timeout():
    transport = FakeTransport(b"Sni")  # short read, no full magic

    assert read_sensniff_frame(transport.read, transport.readline) is None


def test_returns_none_on_short_payload():
    # Header claims 10 bytes of payload but only 2 are available.
    data = b"Snif" + bytes([1, 10]) + b"\xaa\xbb"
    transport = FakeTransport(data)

    assert read_sensniff_frame(transport.read, transport.readline) is None
