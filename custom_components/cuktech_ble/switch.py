"""Switch entities for writable charger booleans."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from homeassistant.components.switch import (
    SwitchEntity,
    SwitchEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import AD1204UConfigEntry
from .coordinator import AD1204UCoordinator, AD1204UData
from .entity import AD1204UEntity


@dataclass(frozen=True, kw_only=True)
class AD1204USwitchDescription(SwitchEntityDescription):
    siid: int
    piid: int
    getter: Callable[[AD1204UData], bool | None]
    # Mi Home sends some "bool"-looking toggles as u8 0/1 (type=0x01 marker=0x10)
    # rather than the proper bool encoding (marker=0x00). Match that so writes
    # are byte-identical to the vendor app — confirmed via tablet capture on
    # 2026-04-23.
    kind: str = "bool"  # "bool" or "u8"


SWITCHES: tuple[AD1204USwitchDescription, ...] = (
    AD1204USwitchDescription(
        key="usb_a_always_on",
        translation_key="usb_a_always_on",
        siid=2,
        piid=0x000F,
        kind="bool",
        getter=lambda data: data.usb_a_always_on,
    ),
    AD1204USwitchDescription(
        key="screenoff_while_idle",
        translation_key="screenoff_while_idle",
        siid=2,
        piid=0x0013,
        kind="u8",
        getter=lambda data: data.screenoff_while_idle,
    ),
    AD1204USwitchDescription(
        key="screen_dir_lock",
        translation_key="screen_dir_lock",
        siid=2,
        piid=0x0014,
        kind="u8",
        getter=lambda data: data.screen_dir_lock,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data.coordinator
    async_add_entities(
        AD1204USwitch(coordinator, description=desc) for desc in SWITCHES
    )


class AD1204USwitch(AD1204UEntity, SwitchEntity):
    entity_description: AD1204USwitchDescription

    def __init__(
        self,
        coordinator: AD1204UCoordinator,
        *,
        description: AD1204USwitchDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if data is None:
            return None
        return self.entity_description.getter(data)

    async def async_turn_on(self, **kwargs: object) -> None:
        await self._write(True)

    async def async_turn_off(self, **kwargs: object) -> None:
        await self._write(False)

    async def _write(self, value: bool) -> None:
        if self.entity_description.kind == "u8":
            # Send as u8 (type=0x01 marker=0x10) to match Mi Home's wire format.
            payload: int | bool = int(value)
        else:
            payload = value
        await self.coordinator.async_set_property(
            self.entity_description.siid,
            self.entity_description.piid,
            payload,
        )
