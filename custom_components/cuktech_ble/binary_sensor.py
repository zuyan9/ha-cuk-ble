"""Binary sensor entities for the AD1204U integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .lib.ports import PORTS

from . import AD1204UConfigEntry
from .coordinator import AD1204UData
from .entity import AD1204UEntity


@dataclass(frozen=True, kw_only=True)
class AD1204UBinarySensorDescription(BinarySensorEntityDescription):
    value_fn: Callable[[AD1204UData], bool | None]
    port: str | None = None


def _port_in_use(port: str) -> Callable[[AD1204UData], bool | None]:
    def _get(data: AD1204UData) -> bool | None:
        info = data.ports.get(port)
        return None if info is None else info.in_use
    return _get


BINARY_SENSORS: tuple[AD1204UBinarySensorDescription, ...] = tuple(
    AD1204UBinarySensorDescription(
        key=f"{port}_in_use",
        translation_key="port_in_use",
        name="In use",
        device_class=BinarySensorDeviceClass.POWER,
        value_fn=_port_in_use(port),
        port=port,
    )
    for port in PORTS
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities(AD1204UBinarySensor(coordinator, d) for d in BINARY_SENSORS)


class AD1204UBinarySensor(AD1204UEntity, BinarySensorEntity):
    entity_description: AD1204UBinarySensorDescription

    def __init__(self, coordinator, description: AD1204UBinarySensorDescription) -> None:
        super().__init__(coordinator, port=description.port)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)
