# OpenRF Debugger

RF debugging tools for embedded systems.

Currently focused on Zigbee and IEEE 802.15.4.

## Usage

Install:

```bash
python -m pip install -e ".[dev]"
```

Read a PCAP:

```bash
openrf inspect capture.pcap
```

Show decoded packets:

```bash
openrf packets capture.pcap
```

Correlate RF packets with device events:

```bash
openrf correlate capture.pcap events.json
```

Device events use a simple JSON format:

```json
[
  {
    "timestamp": 1710000000.125,
    "source": "uart",
    "kind": "tx",
    "description": "command transmitted"
  },
  {
    "timestamp": 1710000000.180,
    "source": "gpio",
    "kind": "edge",
    "description": "status line asserted"
  }
]
```

## Development

```bash
pytest
```

## Current

* IEEE 802.15.4 packet inspection
* basic Zigbee layer detection
* PCAP input
* timestamped hardware events
* packet/event correlation

## License

MIT
