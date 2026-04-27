"""Base entity for the AD1204U integration."""

from __future__ import annotations

from homeassistant.helpers.device_registry import CONNECTION_BLUETOOTH, DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DEFAULT_DEVICE_NAME, DOMAIN, MANUFACTURER, MODEL
from .coordinator import AD1204UCoordinator

PORT_LABELS = {"c1": "C1", "c2": "C2", "c3": "C3", "a": "USB-A"}


class AD1204UEntity(CoordinatorEntity[AD1204UCoordinator]):
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: AD1204UCoordinator,
        *,
        port: str | None = None,
    ) -> None:
        super().__init__(coordinator)
        parent_id = (DOMAIN, coordinator.address)
        parent_name = DEFAULT_DEVICE_NAME
        
        # Hardcoding the known firmware version for now since dynamic BLE fetching of siid=1
        # frequently crashes the connection stack on this particular firmware revision.
        fw_version = "2.1.2_0073"
        
        if port is None:
            self._attr_device_info = DeviceInfo(
                identifiers={parent_id},
                connections={(CONNECTION_BLUETOOTH, coordinator.address)},
                name=parent_name,
                manufacturer=MANUFACTURER,
                model=MODEL,
                sw_version=fw_version,
            )
        else:
            label = PORT_LABELS.get(port, port.upper())
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, f"{coordinator.address}_{port}")},
                name=f"{parent_name} {label}",
                manufacturer=MANUFACTURER,
                model=f"{MODEL} {label}",
                via_device=parent_id,
                sw_version=fw_version,
            )
