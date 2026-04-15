"""Diagnostics for the AD1204U integration."""

from __future__ import annotations

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import AD1204UConfigEntry

REDACT = {"token", "address"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: AD1204UConfigEntry,
) -> dict[str, object]:
    coordinator = entry.runtime_data.coordinator
    data = coordinator.data
    snapshot = None
    if data is not None:
        snapshot = {
            "ports": {p: info.to_dict() for p, info in data.ports.items()},
            "total_power_w": data.total_power_w,
            "pdo_caps_w": data.pdo_caps_w,
            "scene_mode": data.scene_mode,
            "port_ctl": data.port_ctl,
            "usb_a_always_on": data.usb_a_always_on,
            "screenoff_while_idle": data.screenoff_while_idle,
            "screen_dir_lock": data.screen_dir_lock,
        }
    return {
        "entry": async_redact_data(
            {"data": dict(entry.data), "options": dict(entry.options)}, REDACT
        ),
        "state": snapshot,
    }
