"""Lifecycle coverage using a real, current Home Assistant test harness."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_ADDRESS, CONF_TOKEN
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.update_coordinator import UpdateFailed
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cuktech_ble import (
    UNSAFE_LEGACY_SWITCH_KEYS,
    async_setup_entry,
)
from custom_components.cuktech_ble.const import DOMAIN
from custom_components.cuktech_ble.coordinator import AD1204UCoordinator
from custom_components.cuktech_ble.lib.xiaomi.auth import MiAuthInvalidTokenError

TEST_TOKEN_HEX = "00" * 12


async def test_setup_and_unload_entry(hass, enable_custom_integrations) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_TOKEN: TEST_TOKEN_HEX,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    registry = er.async_get(hass)
    for key in UNSAFE_LEGACY_SWITCH_KEYS:
        registry.async_get_or_create(
            "switch",
            DOMAIN,
            f"AA:BB:CC:DD:EE:FF_{key}",
            config_entry=entry,
        )
    safe_unique_id = "AA:BB:CC:DD:EE:FF_usb_a_trickle_charging"
    registry.async_get_or_create(
        "switch",
        DOMAIN,
        safe_unique_id,
        config_entry=entry,
    )

    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock()
    coordinator.async_shutdown = AsyncMock()
    coordinator.firmware_version = "2.1.2_0073"

    with (
        patch(
            "custom_components.cuktech_ble.bluetooth.async_address_present",
            return_value=True,
        ),
        patch(
            "custom_components.cuktech_ble.AD1204UCoordinator",
            return_value=coordinator,
        ),
        patch.object(
            hass.config_entries,
            "async_forward_entry_setups",
            new=AsyncMock(),
        ),
        patch.object(
            hass.config_entries,
            "async_unload_platforms",
            new=AsyncMock(return_value=True),
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.LOADED
        coordinator.async_config_entry_first_refresh.assert_awaited_once()
        for key in UNSAFE_LEGACY_SWITCH_KEYS:
            assert (
                registry.async_get_entity_id(
                    "switch",
                    DOMAIN,
                    f"AA:BB:CC:DD:EE:FF_{key}",
                )
                is None
            )
        assert registry.async_get_entity_id("switch", DOMAIN, safe_unique_id)

        assert await hass.config_entries.async_unload(entry.entry_id)
        await hass.async_block_till_done()
        assert entry.state is ConfigEntryState.NOT_LOADED
        coordinator.async_shutdown.assert_awaited_once()


async def test_setup_maps_confirmed_token_rejection_to_reauth(hass) -> None:
    """A protocol-confirmed rejection must start reauth instead of BLE retries."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_TOKEN: TEST_TOKEN_HEX,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    invalid_token = MiAuthInvalidTokenError("device HMAC mismatch")
    update_failed = UpdateFailed("MiAuthInvalidTokenError: device HMAC mismatch")
    update_failed.__cause__ = invalid_token
    not_ready = ConfigEntryNotReady()
    not_ready.__cause__ = update_failed

    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(side_effect=not_ready)

    with (
        patch(
            "custom_components.cuktech_ble.bluetooth.async_address_present",
            return_value=True,
        ),
        patch(
            "custom_components.cuktech_ble.AD1204UCoordinator",
            return_value=coordinator,
        ),
        pytest.raises(ConfigEntryAuthFailed, match="rejected"),
    ):
        await async_setup_entry(hass, entry)


async def test_setup_keeps_transient_failures_retryable(hass) -> None:
    """A radio or timeout failure must remain ConfigEntryNotReady."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_TOKEN: TEST_TOKEN_HEX,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    not_ready = ConfigEntryNotReady("Bluetooth timeout")
    not_ready.__cause__ = TimeoutError("connection timed out")
    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock(side_effect=not_ready)

    with (
        patch(
            "custom_components.cuktech_ble.bluetooth.async_address_present",
            return_value=True,
        ),
        patch(
            "custom_components.cuktech_ble.AD1204UCoordinator",
            return_value=coordinator,
        ),
        pytest.raises(ConfigEntryNotReady) as raised,
    ):
        await async_setup_entry(hass, entry)

    assert raised.value is not_ready


async def test_runtime_token_rejection_starts_reauth(hass) -> None:
    """A scheduled refresh must associate auth failure with its config entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_TOKEN: TEST_TOKEN_HEX,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)
    coordinator = AD1204UCoordinator(
        hass,
        config_entry=entry,
        address="AA:BB:CC:DD:EE:FF",
        token=bytes.fromhex(TEST_TOKEN_HEX),
        name="CUKTECH AD1204U",
        update_interval=30,
        idle_release=300,
        connection_timeout=10,
        bluez_start_notify=False,
    )
    coordinator._async_update_data = AsyncMock(  # type: ignore[method-assign]
        side_effect=ConfigEntryAuthFailed("token rejected")
    )

    with patch.object(entry, "async_start_reauth") as start_reauth:
        await coordinator.async_refresh()

    assert coordinator.config_entry is entry
    assert coordinator.last_update_success is False
    start_reauth.assert_called_once()
    assert start_reauth.call_args.args[0] is hass
    await coordinator.async_shutdown()


@pytest.mark.parametrize("token", ["not-hex", "001122"])
async def test_setup_requests_reauth_for_malformed_saved_token(
    hass,
    token: str,
) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_TOKEN: token,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.cuktech_ble.bluetooth.async_address_present",
            return_value=True,
        ),
        pytest.raises(ConfigEntryAuthFailed, match="saved BLE token"),
    ):
        await async_setup_entry(hass, entry)
