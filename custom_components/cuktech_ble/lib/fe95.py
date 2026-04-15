"""Parser for Xiaomi/Mijia FE95 BLE service data frames."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .util import bytes_to_hex, compact_mapping


@dataclass(frozen=True)
class FE95Frame:
    """Parsed metadata from an FE95 service data frame.

    Xiaomi/Mijia FE95 frames commonly start with:

    - 2 byte frame control, little-endian
    - 2 byte product id, little-endian
    - 1 byte frame counter
    - 6 byte BLE MAC, little-endian, when present

    The AD1204U frame observed so far is exactly that 11 byte header with no
    metric payload. Unknown trailing bytes are preserved for later analysis.
    """

    raw: bytes
    frame_control: int
    product_id: int | None
    frame_counter: int | None
    mac_address: str | None
    payload: bytes

    @property
    def raw_hex(self) -> str:
        return bytes_to_hex(self.raw)

    @property
    def frame_control_hex(self) -> str:
        return f"0x{self.frame_control:04x}"

    @property
    def product_id_hex(self) -> str | None:
        if self.product_id is None:
            return None
        return f"0x{self.product_id:04x}"

    @property
    def payload_hex(self) -> str:
        return bytes_to_hex(self.payload)

    @property
    def is_minimum_header(self) -> bool:
        return len(self.raw) >= 5

    @property
    def has_mac_address(self) -> bool:
        return self.mac_address is not None

    def to_dict(self) -> dict[str, Any]:
        return compact_mapping(
            {
                "raw_hex": self.raw_hex,
                "frame_control": self.frame_control,
                "frame_control_hex": self.frame_control_hex,
                "product_id": self.product_id,
                "product_id_hex": self.product_id_hex,
                "frame_counter": self.frame_counter,
                "mac_address": self.mac_address,
                "payload_hex": self.payload_hex,
                "payload_length": len(self.payload),
                "has_mac_address": self.has_mac_address,
            }
        )


def parse_fe95(service_data: bytes | bytearray | memoryview) -> FE95Frame:
    """Parse FE95 service data into stable metadata and raw unknown payload."""
    data = bytes(service_data)
    if len(data) < 2:
        raise ValueError("FE95 service data must contain at least a frame control")

    frame_control = int.from_bytes(data[0:2], "little")
    product_id = int.from_bytes(data[2:4], "little") if len(data) >= 4 else None
    frame_counter = data[4] if len(data) >= 5 else None

    mac_address = None
    payload_offset = 5
    if len(data) >= 11:
        mac_address = _decode_little_endian_mac(data[5:11])
        payload_offset = 11

    return FE95Frame(
        raw=data,
        frame_control=frame_control,
        product_id=product_id,
        frame_counter=frame_counter,
        mac_address=mac_address,
        payload=data[payload_offset:],
    )


def _decode_little_endian_mac(value: bytes) -> str:
    if len(value) != 6:
        raise ValueError("MAC field must be exactly 6 bytes")
    return ":".join(f"{byte:02X}" for byte in reversed(value))
