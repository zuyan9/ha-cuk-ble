"""High-level MIOT property read/write over an authenticated ``MiSession``.

The wire format is settled (see project memory): siid=2 request/response
with per-entry type+marker+value bytes. This module encodes/decodes that
format and gives the caller a simple dict of {(siid, piid): value}.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .session import MiSession

# The full siid=2 property catalogue Mi Home polls in one shot.
# (siid, piid, python type hint)
DEFAULT_READ_TUPLES: tuple[tuple[int, int], ...] = (
    (2, 1), (2, 2), (2, 3), (2, 4),   # port C1/C2/C3/A info (u32)
    (2, 5), (2, 6), (2, 7),           # scene_mode, screen_save_time, protocol_ctl (u8)
    (2, 0x0d),                        # device_language (u8)
    (2, 0x0f),                        # usb_a_always_on (bool)
    (2, 0x10),                        # port_ctl (u8)
    (2, 0x11), (2, 0x12),             # c1c2_protocol, c3a_protocol (u32)
    (2, 0x13), (2, 0x14),             # screenoff_while_idle, screen_dir_lock (bool)
    (2, 0x15),                        # protocol_ctl_extend (u32)
)


@dataclass(frozen=True)
class PropertyValue:
    siid: int
    piid: int
    status: int
    type_byte: int
    marker: int
    value: Any

    @property
    def key(self) -> tuple[int, int]:
        return (self.siid, self.piid)


class MiotProtocolError(Exception):
    pass


def encode_get_properties(seq: int, tuples: tuple[tuple[int, int], ...]) -> bytes:
    body = b"\x33\x20" + seq.to_bytes(2, "little")
    body += bytes([0x02, len(tuples)])
    for siid, piid in tuples:
        body += bytes([siid]) + piid.to_bytes(2, "little")
    return body


def parse_response(pt: bytes) -> list[PropertyValue]:
    # Charger returns either 0x93 (original btsnoop) or 0x1c (seen live on
    # other get_properties flows) — both carry the same body layout.
    if len(pt) < 6 or pt[1] != 0x20 or pt[0] not in (0x93, 0x1c):
        raise MiotProtocolError(f"bad response header: {pt[:6].hex()}")
    i = 6
    out: list[PropertyValue] = []
    while i < len(pt):
        siid = pt[i]
        piid = int.from_bytes(pt[i + 1 : i + 3], "little")
        status = int.from_bytes(pt[i + 3 : i + 5], "little")
        type_byte = pt[i + 5]
        marker = pt[i + 6]
        if type_byte == 0x04:
            raw = pt[i + 7 : i + 11]
            out.append(PropertyValue(siid, piid, status, type_byte, marker,
                                     int.from_bytes(raw, "little")))
            i += 11
        elif type_byte == 0x01:
            raw = pt[i + 7 : i + 8]
            val: Any = bool(raw[0]) if marker == 0x00 else raw[0]
            out.append(PropertyValue(siid, piid, status, type_byte, marker, val))
            i += 8
        else:
            raise MiotProtocolError(
                f"unknown type 0x{type_byte:02x} at offset {i} in {pt.hex()}"
            )
    return out


async def get_properties(
    session: MiSession,
    tuples: tuple[tuple[int, int], ...] = DEFAULT_READ_TUPLES,
    *,
    seq: int = 0x001b,
) -> dict[tuple[int, int], PropertyValue]:
    request = encode_get_properties(seq, tuples)
    response_pt = await session.send_request(request)
    return {item.key: item for item in parse_response(response_pt)}


# --- set_properties (single prop) -------------------------------------------
#
# Wire format reversed from a tablet Mi Home capture (2026-04-23):
#   request  = 0c 20 <seq_le2> 00 <count> (<siid> <piid_le2> <type> <marker> <value>)*
#   response = 0b 20 <seq_le2> 01 <count> (<siid> <piid_le2> <status_le2>)*
# See memory/project_ad1204u_miot_set.md for the full reasoning.

SET_REQUEST_OPCODE = b"\x0c\x20"
SET_RESPONSE_OPCODE = b"\x0b\x20"


def encode_set_property(
    seq: int, siid: int, piid: int, value: int | bool, *, u32: bool = False
) -> bytes:
    body = SET_REQUEST_OPCODE + seq.to_bytes(2, "little")
    body += bytes([0x00, 0x01])  # flags(0)=0, count=1
    body += bytes([siid]) + piid.to_bytes(2, "little")
    if isinstance(value, bool):
        body += bytes([0x01, 0x00, int(value)])
    elif u32:
        body += bytes([0x04, 0x50]) + int(value).to_bytes(4, "little")
    else:
        body += bytes([0x01, 0x10, int(value) & 0xFF])
    return body


def parse_set_response(pt: bytes) -> list[tuple[int, int, int]]:
    """Decode a 0x0b 0x20 response. Returns [(siid, piid, status), ...]."""
    if len(pt) < 6 or pt[:2] != SET_RESPONSE_OPCODE:
        raise MiotProtocolError(f"bad set-response header: {pt[:6].hex()}")
    count = pt[5]
    i = 6
    out: list[tuple[int, int, int]] = []
    for _ in range(count):
        if i + 5 > len(pt):
            raise MiotProtocolError(f"truncated set-response: {pt.hex()}")
        siid = pt[i]
        piid = int.from_bytes(pt[i + 1 : i + 3], "little")
        status = int.from_bytes(pt[i + 3 : i + 5], "little")
        out.append((siid, piid, status))
        i += 5
    return out


async def set_property(
    session: MiSession,
    siid: int,
    piid: int,
    value: int | bool,
    *,
    seq: int = 0x0100,
    u32: bool = False,
) -> None:
    """Write one property. Raises MiotProtocolError on non-zero status."""
    request = encode_set_property(seq, siid, piid, value, u32=u32)
    response_pt = await session.send_request(request)
    results = parse_set_response(response_pt)
    for r_siid, r_piid, r_status in results:
        if (r_siid, r_piid) == (siid, piid) and r_status != 0:
            raise MiotProtocolError(
                f"set_property(siid={siid}, piid=0x{piid:x}) failed "
                f"with status 0x{r_status:04x}"
            )
