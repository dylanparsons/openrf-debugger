"""Hardware events from a sigrok-supported logic analyzer.

Shells out to sigrok-cli rather than driving the analyzer's USB interface
directly -- sigrok already has drivers for a wide range of hardware,
including fx2lafw-based clones. Requires sigrok-cli on PATH.

Parses VCD output rather than sigrok's own CSV module: VCD is a stable,
standardized format and only records transitions, which is what we want
for turning edges into discrete events. libsigrok's CSV column layout has
changed across versions.
"""

from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from typing import IO, Iterable, Iterator, Optional

from openrf.correlation.events import HardwareEvent

_VAR_RE = re.compile(r"\$var\s+\w+\s+\d+\s+(\S+)\s+(\S+)")
_TIMESCALE_RE = re.compile(r"\$timescale\s+(\d+)\s*(fs|ps|ns|us|ms|s)\s*\$end")

_SECONDS_PER_UNIT = {
    "fs": 1e-15,
    "ps": 1e-12,
    "ns": 1e-9,
    "us": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
}


def parse_vcd(
    lines: Iterable[str],
    start_time: float,
    source_name: str = "logic_analyzer",
) -> Iterator[HardwareEvent]:
    """Parse a VCD stream into one HardwareEvent per signal transition.

    start_time is the host-clock time corresponding to VCD timestamp 0.
    Each event's timestamp is start_time + vcd_time * seconds_per_unit --
    an approximation of capture time, not a synchronized clock. Use
    clock_offset_ms on the correlator for tighter alignment.
    """
    identifier_to_name: dict[str, str] = {}
    seconds_per_unit = 1e-9
    current_vcd_time = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        timescale_match = _TIMESCALE_RE.search(line)
        if timescale_match:
            magnitude, unit = timescale_match.groups()
            seconds_per_unit = int(magnitude) * _SECONDS_PER_UNIT[unit]
            continue

        var_match = _VAR_RE.search(line)
        if var_match:
            identifier, name = var_match.groups()
            identifier_to_name[identifier] = name
            continue

        if line.startswith("#"):
            try:
                current_vcd_time = int(line[1:])
            except ValueError:
                pass
            continue

        if line in ("$dumpvars", "$end", "$enddefinitions"):
            continue

        if len(line) >= 2 and line[0] in "01xXzZ":
            value, identifier = line[0], line[1:]
            name = identifier_to_name.get(identifier, identifier)
            if value == "1":
                edge = "rising"
            elif value == "0":
                edge = "falling"
            else:
                edge = "unknown"

            timestamp = start_time + current_vcd_time * seconds_per_unit
            yield HardwareEvent(
                timestamp=timestamp,
                source=source_name,
                kind="edge",
                description=f"{name} {edge}",
            )


@dataclass
class LogicAnalyzerConfig:
    driver: str = "fx2lafw"
    samplerate: str = "1m"
    channels: Optional[str] = None


class LogicAnalyzerSource:
    """Streams hardware events from a sigrok-supported logic analyzer."""

    def __init__(
        self,
        config: Optional[LogicAnalyzerConfig] = None,
        source_name: str = "logic_analyzer",
    ) -> None:
        self._config = config or LogicAnalyzerConfig()
        self._source_name = source_name
        self._process: Optional["subprocess.Popen[str]"] = None

    def _build_command(self) -> list[str]:
        cmd = [
            "sigrok-cli",
            "--driver",
            self._config.driver,
            "--config",
            f"samplerate={self._config.samplerate}",
            "--continuous",
            "--output-format",
            "vcd",
        ]
        if self._config.channels:
            cmd += ["--channels", self._config.channels]
        return cmd

    def read_events(self) -> Iterator[HardwareEvent]:
        try:
            self._process = subprocess.Popen(
                self._build_command(),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError as exc:
            raise RuntimeError(
                "sigrok-cli not found. Install it (e.g. `apt install sigrok-cli`) "
                "and make sure it's on PATH."
            ) from exc

        start_time = time.time()
        stdout: IO[str] = self._process.stdout  # type: ignore[assignment]
        yield from parse_vcd(stdout, start_time=start_time, source_name=self._source_name)

    def stop(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()

    def __enter__(self) -> "LogicAnalyzerSource":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()
