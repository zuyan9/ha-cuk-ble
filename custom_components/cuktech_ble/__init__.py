"""Home Assistant integration for the CUKTECH AD1204U charger."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr

from .const import (
    CONF_BLUEZ_START_NOTIFY,
    CONF_CONNECTION_TIMEOUT,
    CONF_IDLE_RELEASE,
    CONF_LOCAL_NAME,
    CONF_UPDATE_PERIOD,
    DEFAULT_CONNECTION_TIMEOUT,
    DEFAULT_DEVICE_NAME,
    DEFAULT_IDLE_RELEASE,
    DEFAULT_UPDATE_PERIOD,
    DOMAIN,
    MANUFACTURER,
    MODEL,
)
from .coordinator import AD1204UCoordinator
from .lib.ports import PORTS

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.SENSOR,
    Platform.SWITCH,
]
_LOGGER = logging.getLogger(__name__)


@dataclass
class AD1204URuntimeData:
    coordinator: AD1204UCoordinator


AD1204UConfigEntry = ConfigEntry[AD1204URuntimeData]  # type: ignore[valid-type]


async def async_setup_entry(hass: HomeAssistant, entry: AD1204UConfigEntry) -> bool:
    address = entry.data[CONF_ADDRESS]
    if not bluetooth.async_address_present(hass, address, connectable=True):
        raise ConfigEntryNotReady(f"{address} not currently visible over Bluetooth")

    try:
        token = bytes.fromhex(entry.data[CONF_TOKEN])
    except (KeyError, ValueError) as exc:
        raise ConfigEntryNotReady(f"bad token in entry: {exc}") from exc

    options = entry.options
    coordinator = AD1204UCoordinator(
        hass,
        address=address,
        token=token,
        name=entry.data.get(CONF_LOCAL_NAME) or entry.title,
        update_interval=float(options.get(CONF_UPDATE_PERIOD, DEFAULT_UPDATE_PERIOD)),
        idle_release=float(options.get(CONF_IDLE_RELEASE, DEFAULT_IDLE_RELEASE)),
        connection_timeout=float(
            options.get(CONF_CONNECTION_TIMEOUT, DEFAULT_CONNECTION_TIMEOUT)
        ),
        bluez_start_notify=bool(options.get(CONF_BLUEZ_START_NOTIFY, False)),
    )
    await coordinator.async_config_entry_first_refresh()

    entry.runtime_data = AD1204URuntimeData(coordinator=coordinator)
    _ensure_device_hierarchy(hass, entry, address)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


def _ensure_device_hierarchy(
    hass: HomeAssistant, entry: AD1204UConfigEntry, address: str
) -> None:
    """Register the parent device up-front and relink orphaned sub-devices.

    If sub-devices were created before the parent existed, their via_device_id
    stays None and the UI won't nest them. We repair that on every setup, and
    also propagate the parent's area to any sub-devices that don't have one.
    """
    registry = dr.async_get(hass)
    parent = registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, address)},
        connections={(dr.CONNECTION_BLUETOOTH, address)},
        name=DEFAULT_DEVICE_NAME,
        manufacturer=MANUFACTURER,
        model=MODEL,
    )
    for port in PORTS:
        child = registry.async_get_device(
            identifiers={(DOMAIN, f"{address}_{port}")}
        )
        if child is None:
            continue
        updates: dict = {}
        if child.via_device_id != parent.id:
            updates["via_device_id"] = parent.id
        if child.area_id is None and parent.area_id is not None:
            updates["area_id"] = parent.area_id
        if updates:
            registry.async_update_device(child.id, **updates)


async def async_unload_entry(hass: HomeAssistant, entry: AD1204UConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        await entry.runtime_data.coordinator.async_shutdown()
    return ok


async def _async_update_listener(hass: HomeAssistant, entry: AD1204UConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
