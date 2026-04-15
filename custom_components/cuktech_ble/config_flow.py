"""Config flow for the CUKTECH AD1204U BLE integration."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_ADDRESS, CONF_TOKEN
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .lib.constants import AD1204_LOCAL_NAME, FE95_UUID
from .lib.xiaomi_cloud import (
    SERVERS,
    CloudAuth,
    CloudError,
    QRLogin,
    find_token_by_mac,
    list_devices,
    start_qr_login,
    wait_for_qr_scan,
)

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
)

_LOGGER = logging.getLogger(__name__)

CONF_METHOD = "method"
CONF_REGION = "region"
METHOD_MANUAL = "manual"
METHOD_CLOUD = "cloud"


class AD1204UConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle AD1204U config flows."""

    VERSION = 1

    def __init__(self) -> None:
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered: dict[str, BluetoothServiceInfoBleak] = {}
        self._address: str | None = None
        self._name: str | None = None
        self._region: str | None = None
        self._qr: QRLogin | None = None
        self._qr_task: asyncio.Task[CloudAuth] | None = None
        self._qr_error: str | None = None
        self._auth: CloudAuth | None = None
        self._fetch_task: asyncio.Task[str | None] | None = None
        self._fetch_error: str | None = None
        self._fetched_token: str | None = None

    async def async_step_bluetooth(
        self,
        discovery_info: BluetoothServiceInfoBleak,
    ) -> ConfigFlowResult:
        if not _looks_like_ad1204u(discovery_info):
            return self.async_abort(reason="not_supported")

        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        self._discovery_info = discovery_info
        self._address = discovery_info.address
        self._name = discovery_info.name or AD1204_LOCAL_NAME
        self.context["title_placeholders"] = {"name": self._name}
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        assert self._discovery_info is not None
        if user_input is not None:
            return await self.async_step_method()

        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={"name": self._name or AD1204_LOCAL_NAME},
            data_schema=vol.Schema({}),
        )

    async def async_step_user(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if user_input is not None:
            address = user_input[CONF_ADDRESS]
            discovery_info = self._discovered[address]
            await self.async_set_unique_id(address)
            self._abort_if_unique_id_configured()
            self._discovery_info = discovery_info
            self._address = address
            self._name = discovery_info.name or AD1204_LOCAL_NAME
            return await self.async_step_method()

        current_addresses = self._async_current_ids()
        self._discovered = {
            info.address: info
            for info in async_discovered_service_info(self.hass)
            if info.address not in current_addresses and _looks_like_ad1204u(info)
        }
        if not self._discovered:
            return self.async_abort(reason="no_devices_found")

        choices = {
            address: f"{info.name or AD1204_LOCAL_NAME} ({address})"
            for address, info in self._discovered.items()
        }
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({vol.Required(CONF_ADDRESS): vol.In(choices)}),
        )

    async def async_step_method(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if user_input is not None:
            if user_input[CONF_METHOD] == METHOD_CLOUD:
                return await self.async_step_cloud_region()
            return await self.async_step_token()
        return self.async_show_menu(
            step_id="method",
            menu_options=[METHOD_CLOUD, METHOD_MANUAL],
        )

    async def async_step_manual(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        return await self.async_step_token(user_input)

    async def async_step_cloud(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        return await self.async_step_cloud_region(user_input)

    async def async_step_cloud_region(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if user_input is not None:
            self._region = user_input[CONF_REGION]
            return await self.async_step_cloud_qr()
        return self.async_show_form(
            step_id="cloud_region",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_REGION, default="cn"): SelectSelector(
                        SelectSelectorConfig(
                            options=list(SERVERS),
                            translation_key="cloud_region",
                            mode=SelectSelectorMode.DROPDOWN,
                        )
                    )
                }
            ),
        )

    async def async_step_cloud_qr(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if self._qr is None:
            session = async_get_clientsession(self.hass)
            try:
                self._qr = await start_qr_login(session)
            except CloudError as exc:
                _LOGGER.warning("QR login start failed: %s", exc)
                return self.async_abort(reason="cloud_qr_start_failed")

        if self._qr_task is None:
            session = async_get_clientsession(self.hass)
            self._qr_task = self.hass.async_create_task(
                wait_for_qr_scan(session, self._qr)
            )

        if not self._qr_task.done():
            return self.async_show_progress(
                step_id="cloud_qr",
                progress_action="waiting_for_scan",
                description_placeholders={"qr_url": self._qr.qr_image_url},
                progress_task=self._qr_task,
            )

        try:
            self._auth = self._qr_task.result()
        except CloudError as exc:
            _LOGGER.warning("QR login failed: %s", exc)
            self._qr_error = "cloud_qr_failed"
            self._qr = None
            self._qr_task = None
            return self.async_show_progress_done(next_step_id="cloud_error")
        except asyncio.CancelledError:
            self._qr_error = "cloud_qr_cancelled"
            return self.async_show_progress_done(next_step_id="cloud_error")

        return self.async_show_progress_done(next_step_id="cloud_fetch")

    async def async_step_cloud_fetch(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if self._fetch_task is None:
            assert self._auth is not None
            assert self._region is not None
            assert self._address is not None
            session = async_get_clientsession(self.hass)
            address = self._address
            auth = self._auth
            region = self._region

            async def _do_fetch() -> str | None:
                devices = await list_devices(session, auth, region)
                return find_token_by_mac(devices, address)

            self._fetch_task = self.hass.async_create_task(_do_fetch())

        if not self._fetch_task.done():
            return self.async_show_progress(
                step_id="cloud_fetch",
                progress_action="fetching_devices",
                progress_task=self._fetch_task,
            )

        try:
            token_hex = self._fetch_task.result()
        except CloudError as exc:
            _LOGGER.warning("Device list fetch failed: %s", exc)
            self._fetch_error = "cloud_fetch_failed"
            return self.async_show_progress_done(next_step_id="cloud_error")

        if not token_hex:
            self._fetch_error = "cloud_device_not_found"
            return self.async_show_progress_done(next_step_id="cloud_error")

        self._fetched_token = token_hex
        return self.async_show_progress_done(next_step_id="cloud_done")

    async def async_step_cloud_done(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        assert self._fetched_token is not None
        return self._create_entry(self._fetched_token)

    async def async_step_cloud_error(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        reason = self._fetch_error or self._qr_error or "cloud_unknown"
        if user_input is not None:
            self._qr = None
            self._qr_task = None
            self._qr_error = None
            self._fetch_task = None
            self._fetch_error = None
            return await self.async_step_method()
        return self.async_show_form(
            step_id="cloud_error",
            data_schema=vol.Schema({}),
            description_placeholders={"reason": reason},
            errors={"base": reason},
        )

    async def async_step_token(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            token_hex = user_input[CONF_TOKEN].strip().lower().replace(" ", "")
            try:
                token = bytes.fromhex(token_hex)
            except ValueError:
                errors[CONF_TOKEN] = "token_not_hex"
            else:
                if len(token) != 12:
                    errors[CONF_TOKEN] = "token_wrong_length"
                else:
                    return self._create_entry(token_hex)

        return self.async_show_form(
            step_id="token",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_TOKEN): TextSelector(
                        TextSelectorConfig(type=TextSelectorType.TEXT)
                    )
                }
            ),
            errors=errors,
            description_placeholders={"name": self._name or AD1204_LOCAL_NAME},
        )

    @staticmethod
    def async_get_options_flow(config_entry: Any) -> OptionsFlow:
        return AD1204UOptionsFlow(config_entry)

    def _create_entry(self, token_hex: str) -> ConfigFlowResult:
        assert self._address is not None
        return self.async_create_entry(
            title=DEFAULT_DEVICE_NAME,
            data={
                CONF_ADDRESS: self._address,
                CONF_LOCAL_NAME: self._name or AD1204_LOCAL_NAME,
                CONF_TOKEN: token_hex,
            },
        )


class AD1204UOptionsFlow(OptionsFlow):
    def __init__(self, config_entry: Any) -> None:
        self._config_entry = config_entry

    async def async_step_init(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        options = self._config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_UPDATE_PERIOD,
                        default=options.get(CONF_UPDATE_PERIOD, DEFAULT_UPDATE_PERIOD),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=5, max=3600, step=1, mode=NumberSelectorMode.BOX,
                            unit_of_measurement="s",
                        )
                    ),
                    vol.Optional(
                        CONF_IDLE_RELEASE,
                        default=options.get(CONF_IDLE_RELEASE, DEFAULT_IDLE_RELEASE),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=0, max=3600, step=1, mode=NumberSelectorMode.BOX,
                            unit_of_measurement="s",
                        )
                    ),
                    vol.Optional(
                        CONF_CONNECTION_TIMEOUT,
                        default=options.get(
                            CONF_CONNECTION_TIMEOUT, DEFAULT_CONNECTION_TIMEOUT
                        ),
                    ): NumberSelector(
                        NumberSelectorConfig(
                            min=5, max=120, step=1, mode=NumberSelectorMode.BOX,
                            unit_of_measurement="s",
                        )
                    ),
                    vol.Optional(
                        CONF_BLUEZ_START_NOTIFY,
                        default=options.get(CONF_BLUEZ_START_NOTIFY, False),
                    ): BooleanSelector(),
                }
            ),
        )


def _looks_like_ad1204u(info: BluetoothServiceInfoBleak) -> bool:
    advertisement = info.advertisement
    if advertisement.local_name == AD1204_LOCAL_NAME:
        return True
    service_data = {
        str(key).lower(): value
        for key, value in (advertisement.service_data or {}).items()
    }
    return FE95_UUID in service_data
