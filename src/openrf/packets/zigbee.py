"""Basic Zigbee identification helpers."""

from __future__ import annotations

from typing import Any

try:
    from scapy.layers.zigbee import ZigbeeNWK, ZigbeeAppDataPayload
except ImportError:  # pragma: no cover
    ZigbeeNWK = None
    ZigbeeAppDataPayload = None


def has_zigbee_network_layer(packet: Any) -> bool:
    """Return True when Scapy identifies a Zigbee NWK layer."""
    return ZigbeeNWK is not None and packet.haslayer(ZigbeeNWK)


def has_zigbee_application_payload(packet: Any) -> bool:
    """Return True when a Zigbee application payload is present."""
    return (
        ZigbeeAppDataPayload is not None
        and packet.haslayer(ZigbeeAppDataPayload)
    )


def classify_zigbee(packet: Any) -> str:
    """Classify a packet at a coarse Zigbee layer level."""
    if has_zigbee_application_payload(packet):
        return "zigbee-application"
    if has_zigbee_network_layer(packet):
        return "zigbee-network"
    return "not-zigbee"
