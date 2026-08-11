"""Config-flow coverage for replacing a rejected BLE token."""

from __future__ import annotations

from unittest.mock import patch

from homeassistant.config_entries import SOURCE_REAUTH
from homeassistant.const import CONF_ADDRESS, CONF_TOKEN
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.cuktech_ble.const import CONF_LOCAL_NAME, DOMAIN

ORIGINAL_TOKEN_HEX = "00" * 12
UPDATED_TOKEN_HEX = "ab" * 12


async def test_reauth_updates_canonical_token_and_reloads(
    hass,
    enable_custom_integrations,
) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="CUKTECH AD1204U",
        data={
            CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
            CONF_LOCAL_NAME: "njcuk.fitting.ad1204",
            CONF_TOKEN: ORIGINAL_TOKEN_HEX,
        },
        unique_id="AA:BB:CC:DD:EE:FF",
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=dict(entry.data),
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "reauth_confirm"

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {CONF_TOKEN: "not-a-token"},
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {CONF_TOKEN: "token_not_hex"}

    with patch.object(hass.config_entries, "async_schedule_reload") as reload_entry:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_TOKEN: " ".join(["AB"] * 12)},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data == {
        CONF_ADDRESS: "AA:BB:CC:DD:EE:FF",
        CONF_LOCAL_NAME: "njcuk.fitting.ad1204",
        CONF_TOKEN: UPDATED_TOKEN_HEX,
    }
    reload_entry.assert_called_once_with(entry.entry_id)
