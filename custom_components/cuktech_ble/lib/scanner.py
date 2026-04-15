"""BLE scanner helpers for finding AD1204U chargers."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from .constants import AD1204_LOCAL_NAME, AD1204_PRODUCT_ID, FE95_UUID
from .fe95 import FE95Frame, parse_fe95
from .models import ChargerSnapshot, DiscoveredCharger
from .util import normalize_uuid

AdvertisementCallback = Callable[[DiscoveredCharger, ChargerSnapshot], Any]


def get_service_data(advertisement_data: Any, uuid: str = FE95_UUID) -> bytes | None:
    """Return service data for a UUID from a Bleak AdvertisementData-like object."""
    service_data = getattr(advertisement_data, "service_data", None) or {}
    wanted = normalize_uuid(uuid)
    for key, value in service_data.items():
        if normalize_uuid(str(key)) == wanted:
            return bytes(value)
    return None


def advertisement_name(device: Any, advertisement_data: Any) -> str | None:
    """Prefer advertisement local name, then device name."""
    local_name = getattr(advertisement_data, "local_name", None)
    device_name = getattr(device, "name", None)
    return local_name or device_name


def is_ad1204_advertisement(
    device: Any,
    advertisement_data: Any,
    *,
    expected_name: str = AD1204_LOCAL_NAME,
    expected_product_id: int = AD1204_PRODUCT_ID,
) -> bool:
    """Return True when an advertisement looks like the AD1204U charger."""
    name = advertisement_name(device, advertisement_data)
    if name == expected_name:
        return True

    service_data = get_service_data(advertisement_data)
    if service_data is None:
        return False
    try:
        frame = parse_fe95(service_data)
    except ValueError:
        return False
    return frame.product_id == expected_product_id


def discovered_from_advertisement(
    device: Any,
    advertisement_data: Any,
) -> DiscoveredCharger | None:
    """Convert Bleak objects into a DiscoveredCharger when FE95 data exists."""
    service_data = get_service_data(advertisement_data)
    if service_data is None:
        return None

    beacon: FE95Frame | None
    try:
        beacon = parse_fe95(service_data)
    except ValueError:
        beacon = None

    return DiscoveredCharger(
        address=str(getattr(device, "address", "")),
        name=advertisement_name(device, advertisement_data),
        rssi=getattr(advertisement_data, "rssi", None),
        service_data=service_data,
        beacon=beacon,
        metadata={
            "manufacturer_data_keys": [
                f"0x{int(key):04x}"
                for key in (getattr(advertisement_data, "manufacturer_data", None) or {})
            ],
            "service_uuids": list(getattr(advertisement_data, "service_uuids", None) or []),
        },
    )


async def scan_chargers(
    *,
    timeout: float = 20.0,
    address: str | None = None,
    expected_name: str = AD1204_LOCAL_NAME,
    expected_product_id: int = AD1204_PRODUCT_ID,
    scanner_factory: Any | None = None,
) -> list[DiscoveredCharger]:
    """Scan for AD1204U candidates using Bleak."""
    scanner_factory = scanner_factory or _bleak_scanner()
    results = await scanner_factory.discover(timeout=timeout, return_adv=True)
    chargers: list[DiscoveredCharger] = []

    for device, advertisement_data in _iter_discovery_results(results):
        if address and str(getattr(device, "address", "")).upper() != address.upper():
            continue
        if not is_ad1204_advertisement(
            device,
            advertisement_data,
            expected_name=expected_name,
            expected_product_id=expected_product_id,
        ):
            continue
        charger = discovered_from_advertisement(device, advertisement_data)
        if charger is not None:
            chargers.append(charger)

    return chargers


async def watch_advertisements(
    *,
    timeout: float,
    address: str | None = None,
    expected_name: str = AD1204_LOCAL_NAME,
    expected_product_id: int = AD1204_PRODUCT_ID,
    callback: AdvertisementCallback | None = None,
    scanner_factory: Any | None = None,
) -> list[ChargerSnapshot]:
    """Watch AD1204U advertisements and return raw snapshots."""
    scanner_factory = scanner_factory or _bleak_scanner()
    snapshots: list[ChargerSnapshot] = []

    def detection_callback(device: Any, advertisement_data: Any) -> None:
        if address and str(getattr(device, "address", "")).upper() != address.upper():
            return
        if not is_ad1204_advertisement(
            device,
            advertisement_data,
            expected_name=expected_name,
            expected_product_id=expected_product_id,
        ):
            return

        charger = discovered_from_advertisement(device, advertisement_data)
        if charger is None:
            return

        snapshot = ChargerSnapshot.now(
            source_type="advertisement",
            source_frame=charger.service_data,
            address=charger.address,
            decoded_metrics={
                "name": charger.name,
                "rssi": charger.rssi,
                "beacon": None if charger.beacon is None else charger.beacon.to_dict(),
            },
        )
        snapshots.append(snapshot)
        if callback is not None:
            result = callback(charger, snapshot)
            if isinstance(result, Awaitable):
                asyncio.create_task(result)

    scanner = scanner_factory(detection_callback=detection_callback)
    async with scanner:
        await asyncio.sleep(timeout)

    return snapshots


def _iter_discovery_results(results: Any) -> list[tuple[Any, Any]]:
    """Handle Bleak return_adv=True results and fake test fixtures."""
    if isinstance(results, dict):
        return [(device, adv) for device, adv in results.values()]
    return list(results)


def _bleak_scanner() -> Any:
    try:
        from bleak import BleakScanner
    except ImportError as exc:
        raise RuntimeError(
            "bleak is required for BLE scanning. Install with: "
            '.venv/bin/python -m pip install -e ".[test]"'
        ) from exc
    return BleakScanner
