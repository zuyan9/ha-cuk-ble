"""Home Assistant integration for the CUKTECH AD1204U charger."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

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
from .lib.xiaomi.auth import MiAuthInvalidTokenError

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.SELECT,
    Platform.SENSOR,
    Platform.SWITCH,
]
_LOGGER = logging.getLogger(__name__)

UNSAFE_LEGACY_SWITCH_KEYS = (
    "port_c1_power",
    "port_c2_power",
    "port_c3_power",
    "port_a_power",
    "c1_pd_protocol",
    "c1_pps_protocol",
    "c1_ufcs_protocol",
    "c2_pd_protocol",
    "c2_pps_protocol",
    "c2_ufcs_protocol",
    "c3_ufcs_protocol",
    "c3_scp_protocol",
    "a_ufcs_protocol",
    "a_scp_protocol",
)


@dataclass
class AD1204URuntimeData:
    coordinator: AD1204UCoordinator


AD1204UConfigEntry = ConfigEntry[AD1204URuntimeData]  # type: ignore[valid-type]


async def async_setup_entry(hass: HomeAssistant, entry: AD1204UConfigEntry) -> bool:
    address = entry.data[CONF_ADDRESS]
    _remove_unsafe_legacy_entities(hass, entry, address)
    if not bluetooth.async_address_present(hass, address, connectable=True):
        raise ConfigEntryNotReady(f"{address} not currently visible over Bluetooth")

    try:
        token = bytes.fromhex(entry.data[CONF_TOKEN])
    except (KeyError, ValueError) as exc:
        raise ConfigEntryAuthFailed("The saved BLE token is not valid hex") from exc
    if len(token) != 12:
        raise ConfigEntryAuthFailed(
            "The saved BLE token must contain exactly 12 bytes"
        )

    options = entry.options
    coordinator = AD1204UCoordinator(
        hass,
        config_entry=entry,
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
    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryNotReady as exc:
        if _is_invalid_token_failure(exc):
            raise ConfigEntryAuthFailed(
                "The charger rejected the configured BLE token"
            ) from exc
        raise

    entry.runtime_data = AD1204URuntimeData(coordinator=coordinator)
    _ensure_device_hierarchy(
        hass, entry, address, firmware_version=coordinator.firmware_version
    )
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


def _is_invalid_token_failure(error: BaseException) -> bool:
    """Return whether an exception chain contains a confirmed token rejection."""
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        if isinstance(current, MiAuthInvalidTokenError):
            return True
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    return False


def _remove_unsafe_legacy_entities(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    address: str,
) -> None:
    """Remove writable entities whose protocol mappings were never verified."""
    registry = er.async_get(hass)
    for key in UNSAFE_LEGACY_SWITCH_KEYS:
        entity_id = registry.async_get_entity_id(
            Platform.SWITCH,
            DOMAIN,
            f"{address}_{key}",
        )
        if entity_id is None:
            continue
        legacy_entity = registry.async_get(entity_id)
        if legacy_entity is not None and legacy_entity.config_entry_id == entry.entry_id:
            registry.async_remove(entity_id)


def _ensure_device_hierarchy(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
    address: str,
    *,
    firmware_version: str | None,
) -> None:
    """Register the parent device up-front and relink orphaned sub-devices.

    If sub-devices were created before the parent existed, their via_device_id
    stays None and the UI won't nest them. We repair that on every setup, and
    also propagate the parent's area to any sub-devices that don't have one.
    """
    registry = dr.async_get(hass)
    parent_info = {
        "config_entry_id": entry.entry_id,
        "identifiers": {(DOMAIN, address)},
        "connections": {(dr.CONNECTION_BLUETOOTH, address)},
        "name": DEFAULT_DEVICE_NAME,
        "manufacturer": MANUFACTURER,
        "model": MODEL,
    }
    # Home Assistant's device registry stores firmware/software version here.
    if firmware_version is not None:
        parent_info["sw_version"] = firmware_version

    parent = registry.async_get_or_create(**parent_info)
    if firmware_version is not None and parent.sw_version != firmware_version:
        registry.async_update_device(parent.id, sw_version=firmware_version)
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
        if child.sw_version is not None:
            updates["sw_version"] = None
        if updates:
            registry.async_update_device(child.id, **updates)


async def async_unload_entry(hass: HomeAssistant, entry: AD1204UConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        await entry.runtime_data.coordinator.async_shutdown()
    return ok


async def _async_update_listener(hass: HomeAssistant, entry: AD1204UConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)
