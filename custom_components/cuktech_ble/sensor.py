"""Sensor entities for the AD1204U integration."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    EntityCategory,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfPower,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .lib.ports import PORTS

from . import AD1204UConfigEntry
from .coordinator import AD1204UData
from .entity import AD1204UEntity


@dataclass(frozen=True, kw_only=True)
class AD1204USensorDescription(SensorEntityDescription):
    value_fn: Callable[[AD1204UData], Any]
    port: str | None = None


def _port_power(port: str) -> Callable[[AD1204UData], float | None]:
    def _get(data: AD1204UData) -> float | None:
        info = data.ports.get(port)
        return None if info is None else info.power_w
    return _get


def _port_voltage(port: str) -> Callable[[AD1204UData], float | None]:
    def _get(data: AD1204UData) -> float | None:
        info = data.ports.get(port)
        return None if info is None else info.voltage_v
    return _get


def _port_current(port: str) -> Callable[[AD1204UData], float | None]:
    def _get(data: AD1204UData) -> float | None:
        info = data.ports.get(port)
        return None if info is None else info.current_a
    return _get


PROTOCOL_OPTIONS = ("idle", "pd", "pd_fixed", "pd_pps", "usb_a", "usb_a_qc", "unknown")


def _port_protocol(port: str) -> Callable[[AD1204UData], str | None]:
    def _get(data: AD1204UData) -> str | None:
        info = data.ports.get(port)
        if info is None:
            return None
        return info.protocol_name if info.protocol_name in PROTOCOL_OPTIONS else "unknown"
    return _get


def _port_cap(port: str) -> Callable[[AD1204UData], int | None]:
    def _get(data: AD1204UData) -> int | None:
        return data.pdo_caps_w.get(port)
    return _get


def _build_descriptions() -> tuple[AD1204USensorDescription, ...]:
    out: list[AD1204USensorDescription] = []
    for port in PORTS:
        out.extend(
            [
                AD1204USensorDescription(
                    key=f"{port}_power",
                    translation_key="cuktech_power",
                    native_unit_of_measurement=UnitOfPower.WATT,
                    device_class=SensorDeviceClass.POWER,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_power(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_voltage",
                    translation_key="cuktech_voltage",
                    native_unit_of_measurement=UnitOfElectricPotential.VOLT,
                    device_class=SensorDeviceClass.VOLTAGE,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_voltage(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_current",
                    translation_key="cuktech_current",
                    native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
                    device_class=SensorDeviceClass.CURRENT,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_current(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_voltage",
                    translation_key="cuktech_voltage",
                    native_unit_of_measurement=UnitOfElectricPotential.VOLT,
                    device_class=SensorDeviceClass.VOLTAGE,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_voltage(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_current",
                    translation_key="cuktech_current",
                    native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
                    device_class=SensorDeviceClass.CURRENT,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_current(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_voltage",
                    translation_key="cuktech_voltage",
                    native_unit_of_measurement=UnitOfElectricPotential.VOLT,
                    device_class=SensorDeviceClass.VOLTAGE,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_voltage(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_current",
                    translation_key="cuktech_current",
                    native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
                    device_class=SensorDeviceClass.CURRENT,
                    state_class=SensorStateClass.MEASUREMENT,
                    suggested_display_precision=1,
                    value_fn=_port_current(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_protocol",
                    translation_key="port_protocol",
                    device_class=SensorDeviceClass.ENUM,
                    options=list(PROTOCOL_OPTIONS),
                    entity_category=EntityCategory.DIAGNOSTIC,
                    value_fn=_port_protocol(port),
                    port=port,
                ),
                AD1204USensorDescription(
                    key=f"{port}_pdo_cap",
                    translation_key="pdo_cap",
                    native_unit_of_measurement=UnitOfPower.WATT,
                    device_class=SensorDeviceClass.POWER,
                    entity_category=EntityCategory.DIAGNOSTIC,
                    entity_registry_enabled_default=False,
                    value_fn=_port_cap(port),
                    port=port,
                ),
            ]
        )
    out.append(
        AD1204USensorDescription(
            key="total_power",
            translation_key="total_power",
            native_unit_of_measurement=UnitOfPower.WATT,
            device_class=SensorDeviceClass.POWER,
            state_class=SensorStateClass.MEASUREMENT,
            suggested_display_precision=1,
            value_fn=lambda d: d.total_power_w,
        )
    )
    return tuple(out)


SENSORS: tuple[AD1204USensorDescription, ...] = _build_descriptions()


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities(AD1204USensor(coordinator, desc) for desc in SENSORS)


class AD1204USensor(AD1204UEntity, SensorEntity):
    entity_description: AD1204USensorDescription

    def __init__(self, coordinator, description: AD1204USensorDescription) -> None:
        super().__init__(coordinator, port=description.port)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"

    @property
    def native_value(self) -> Any:
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)
