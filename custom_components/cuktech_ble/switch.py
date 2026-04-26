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
        key="usb_a_trickle_charging",
        translation_key="usb_a_trickle_charging",
        siid=2,
        piid=0x000F,
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
    
    entities: list[AD1204UEntity] = []
    for desc in SWITCHES:
        entities.append(AD1204USwitch(coordinator, description=desc))
    
    for desc in PORT_SWITCHES:
        entities.append(AD1204UPortSwitch(coordinator, description=desc))
        
    async_add_entities(entities)


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

@dataclass(frozen=True, kw_only=True)
class AD1204UPortSwitchDescription(SwitchEntityDescription):
    bit_index: int


PORT_SWITCHES: tuple[AD1204UPortSwitchDescription, ...] = (
    AD1204UPortSwitchDescription(
        key="port_c1_power",
        translation_key="port_c1_power",
        bit_index=0,
    ),
    AD1204UPortSwitchDescription(
        key="port_c2_power",
        translation_key="port_c2_power",
        bit_index=1,
    ),
    AD1204UPortSwitchDescription(
        key="port_c3_power",
        translation_key="port_c3_power",
        bit_index=2,
    ),
    AD1204UPortSwitchDescription(
        key="port_a_power",
        translation_key="port_a_power",
        bit_index=3,
    ),
)


class AD1204UPortSwitch(AD1204UEntity, SwitchEntity):
    entity_description: AD1204UPortSwitchDescription

    def __init__(
        self,
        coordinator: AD1204UCoordinator,
        *,
        description: AD1204UPortSwitchDescription,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.address}_{description.key}"

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if data is None or data.port_ctl is None:
            return None
        return (data.port_ctl & (1 << self.entity_description.bit_index)) > 0

    async def async_turn_on(self, **kwargs: object) -> None:
        await self._write(True)

    async def async_turn_off(self, **kwargs: object) -> None:
        await self._write(False)

    async def _write(self, value: bool) -> None:
        data = self.coordinator.data
        if data is None or data.port_ctl is None:
            return
        
        current_mask = data.port_ctl
        if value:
            new_mask = current_mask | (1 << self.entity_description.bit_index)
        else:
            new_mask = current_mask & ~(1 << self.entity_description.bit_index)
            
        # Optimistically update the state BEFORE yielding to prevent race
        # conditions if multiple ports are toggled concurrently.
        data.port_ctl = new_mask
        self.async_write_ha_state()

        try:
            await self.coordinator.async_set_property(2, 0x0010, new_mask)
        except Exception:
            # Revert optimistic update on failure (async_refresh will also fix it later)
            data.port_ctl = current_mask
            self.async_write_ha_state()
            raise
        
        # In case async_refresh replaced the data object with a snapshot from
        # before the device fully settled, re-apply our optimistic value.
        if self.coordinator.data is not None:
            self.coordinator.data.port_ctl = new_mask
            self.async_write_ha_state()
