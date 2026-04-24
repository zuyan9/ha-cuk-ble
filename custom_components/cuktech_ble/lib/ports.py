"""AD1204U per-port telemetry decode.

The per-port u32 word (siid=2 piid=1..4) packs four bytes:
    b0 = in-use flag (0 idle, 1 active)
    b1 = protocol code (see PROTOCOL_NAMES)
    b2 = current in deciamps (A * 10)
    b3 = voltage in decivolts (V * 10)

Verified across 15+ datapoints spanning 0.5W-100W and 5V-20V on all ports.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PORTS: tuple[str, ...] = ("c1", "c2", "c3", "a")

PORT_PROPERTY_PIID: dict[str, int] = {"c1": 1, "c2": 2, "c3": 3, "a": 4}
PIID_TO_PORT: dict[int, str] = {v: k for k, v in PORT_PROPERTY_PIID.items()}

# b1 protocol-code map for ACTIVE ports. The authoritative idle indicator is
# b0 (in_use); decode_port_info forces protocol_name="idle" whenever in_use is
# false, regardless of b1. Codes 0x01/0x03/0x05/0x06/0x30 were previously
# labelled "idle" but live probes show them on loaded PD contracts too
# (0x01 at 5V loads, 0x03 at 20V loads on C1/C2).
PROTOCOL_NAMES: dict[int, str] = {
    0x01: "pd",          # seen loaded at 5V on C1/C2
    0x03: "pd",          # seen loaded at 20V on C1/C2 (e.g. PD3.0 45W contract)
    0x05: "pd",
    0x06: "pd",
    0x08: "pd_pps",
    0x0a: "pd_fixed",
    0x30: "pd",          # seen loaded on C3 (C3+A rail non-compat) and unloaded on A
    0x60: "usb_a",       # generic USB-A: seen on DCP (5V) and on QC2.0/SCP (9V).
                          # Also reported by C3 when the C3+A rail is in USB-A compat mode.
    0x70: "usb_a_qc",    # seen on QC in an earlier btsnoop capture; not reliably
                          # distinguishable from 0x60 — the charger's b1 does not
                          # cleanly separate DCP vs QC.
    0x80: "pd",          # C3 port-family code; fixed + PPS across 5-15V
}


@dataclass(frozen=True)
class PortInfo:
    """Decoded state of one charger port."""

    port: str
    raw_uint32_le: int
    in_use: bool
    protocol_code: int
    protocol_name: str
    voltage_v: float
    current_a: float
    power_w: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "raw_uint32_le": self.raw_uint32_le,
            "in_use": self.in_use,
            "protocol_code": self.protocol_code,
            "protocol_name": self.protocol_name,
            "voltage_v": self.voltage_v,
            "current_a": self.current_a,
            "power_w": self.power_w,
        }


def decode_port_info(port: str, value: int) -> PortInfo:
    if port not in PORT_PROPERTY_PIID:
        raise ValueError(f"unknown port {port!r}")
    if value < 0 or value > 0xFFFFFFFF:
        raise ValueError("value out of uint32 range")
    # b0 is a bitfield, not a strict flag: idle is always 0, but active ports
    # have been seen reporting 0x01 and 0x11 on the same port at different
    # times. Treat non-zero as active.
    b0 = value & 0xFF
    b1 = (value >> 8) & 0xFF
    b2 = (value >> 16) & 0xFF
    b3 = (value >> 24) & 0xFF
    voltage = b3 / 10.0
    current = b2 / 10.0
    in_use = bool(b0)
    if in_use:
        protocol_name = PROTOCOL_NAMES.get(b1, f"unknown_{b1:#04x}")
    else:
        protocol_name = "idle"
    return PortInfo(
        port=port,
        raw_uint32_le=value,
        in_use=in_use,
        protocol_code=b1,
        protocol_name=protocol_name,
        voltage_v=voltage,
        current_a=current,
        power_w=round(voltage * current, 2),
    )


# ----- c1c2_protocol / c3a_protocol words (2.11 / 2.12) ---------------------
# Each u32 is two LE16 halves: low16 = C2/A, high16 = C1/C3.
# Each half is two bytes: low byte = PDO watt cap (decimal), high byte = kind.
#
# Verified on C1 across PD-fixed 5/9/12/15/20V and PPS 3.3-11V / 3.3-21V with
# a SINK240 trigger board:
#     cap_byte = watts (linear, e.g. 0x0f=15W, 0x1b=27W, 0x24=36W, 0x2d=45W,
#     0x37=55W PPS, 0x50=80W PPS, 0x64=100W max SPR).
# The old hardcoded lookup (0x0a/0f/1e/2d/37/3c/50/64) was just coincidences
# observed in early captures — the encoding is just `cap_byte`.
#
# high byte (verified on C1/C2):
#     0x07 = PD Fixed PDO
#     0x08 = PD PPS PDO (APDO)
# Other high-byte values previously observed on the C3/A shared rail
# (0x01, 0x02, 0x04) track that rail's voltage-band quirks — see
# docs/properties.md.

PDO_KIND_BY_HIGH_BYTE: dict[int, str] = {
    0x07: "pd_fixed",
    0x08: "pd_pps",
}


def decode_pdo_caps(value: int, *, high_port: str, low_port: str) -> dict[str, int | None]:
    """Extract negotiated watt caps for the two ports sharing this u32 word."""
    low_half = value & 0xFFFF
    high_half = (value >> 16) & 0xFFFF
    def _cap(half: int) -> int | None:
        byte = half & 0xFF
        # An idle port reports both halves = 0; treat that as "no contract".
        return byte or None
    return {
        low_port: _cap(low_half),
        high_port: _cap(high_half),
    }


def decode_pdo_kind(value: int, *, high_port: str, low_port: str) -> dict[str, str | None]:
    """Extract PDO kind (`pd_fixed`/`pd_pps`/None) for the two paired ports."""
    low_half = value & 0xFFFF
    high_half = (value >> 16) & 0xFFFF
    def _kind(half: int) -> str | None:
        if (half & 0xFF) == 0:
            return None
        return PDO_KIND_BY_HIGH_BYTE.get((half >> 8) & 0xFF)
    return {
        low_port: _kind(low_half),
        high_port: _kind(high_half),
    }
