"""Dataclasses used by scanner, probe, and future Home Assistant work."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from .fe95 import FE95Frame
from .util import bytes_to_hex, compact_mapping

SnapshotSource = Literal["advertisement", "gatt_read", "gatt_notify"]


@dataclass(frozen=True)
class DiscoveredCharger:
    """A charger candidate discovered from BLE advertisements."""

    address: str
    name: str | None
    rssi: int | None
    service_data: bytes
    beacon: FE95Frame | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def product_id(self) -> int | None:
        if self.beacon is None:
            return None
        return self.beacon.product_id

    @property
    def service_data_hex(self) -> str:
        return bytes_to_hex(self.service_data)

    def to_dict(self) -> dict[str, Any]:
        return compact_mapping(
            {
                "address": self.address,
                "name": self.name,
                "rssi": self.rssi,
                "product_id": self.product_id,
                "product_id_hex": None
                if self.product_id is None
                else f"0x{self.product_id:04x}",
                "service_data_hex": self.service_data_hex,
                "beacon": None if self.beacon is None else self.beacon.to_dict(),
                "metadata": self.metadata or None,
            }
        )


@dataclass(frozen=True)
class ChargerSnapshot:
    """One raw observation that may later become decoded metrics."""

    timestamp: datetime
    source_type: SnapshotSource
    source_frame: bytes
    address: str | None = None
    characteristic_uuid: str | None = None
    total_power_w: float | None = None
    temperature_c: float | None = None
    port_metrics: dict[str, dict[str, float | str | bool | None]] = field(
        default_factory=dict
    )
    decoded_metrics: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def now(
        cls,
        *,
        source_type: SnapshotSource,
        source_frame: bytes | bytearray | memoryview,
        address: str | None = None,
        characteristic_uuid: str | None = None,
        decoded_metrics: dict[str, Any] | None = None,
    ) -> "ChargerSnapshot":
        return cls(
            timestamp=datetime.now(timezone.utc),
            source_type=source_type,
            source_frame=bytes(source_frame),
            address=address,
            characteristic_uuid=characteristic_uuid,
            decoded_metrics=decoded_metrics or {},
        )

    @property
    def source_frame_hex(self) -> str:
        return bytes_to_hex(self.source_frame)

    def to_dict(self) -> dict[str, Any]:
        return compact_mapping(
            {
                "timestamp": self.timestamp.isoformat(),
                "source_type": self.source_type,
                "address": self.address,
                "characteristic_uuid": self.characteristic_uuid,
                "source_frame_hex": self.source_frame_hex,
                "total_power_w": self.total_power_w,
                "temperature_c": self.temperature_c,
                "port_metrics": self.port_metrics or None,
                "decoded_metrics": self.decoded_metrics or None,
            }
        )
