"""DataUpdateCoordinator for the CUKTECH AD1204U charger.

Strategy: persistent BLE connection with configurable "release on idle".

- On first refresh, connect + Mi standard-auth login + subscribe to MIOT channels.
- Poll siid=2 properties every ``update_interval`` seconds over the live session.
- If nothing consumes data for ``idle_release`` seconds, drop the connection so
  Mi Home (or another client) can talk to the charger. Reconnect on demand.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection

from homeassistant.components import bluetooth
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .lib.ports import (
    PIID_TO_PORT,
    PORTS,
    PortInfo,
    decode_pdo_caps,
    decode_port_info,
)
from .lib.xiaomi import MiAuthClient
from .lib.xiaomi.properties import get_properties, set_property
from .lib.xiaomi.session import MiSession

_LOGGER = logging.getLogger(__name__)


@dataclass
class AD1204UData:
    """Snapshot exposed to entities."""

    ports: dict[str, PortInfo] = field(default_factory=dict)
    total_power_w: float = 0.0
    pdo_caps_w: dict[str, int | None] = field(default_factory=dict)
    scene_mode: int | None = None
    screen_save_time: int | None = None
    device_language: int | None = None
    port_ctl: int | None = None
    protocol_ctl: int | None = None
    protocol_ctl_extend: int | None = None
    usb_a_always_on: bool | None = None
    screenoff_while_idle: bool | None = None
    screen_dir_lock: bool | None = None


class AD1204UCoordinator(DataUpdateCoordinator[AD1204UData]):
    """Owns the live BLE+MIOT session and polls it on a schedule."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        address: str,
        token: bytes,
        name: str,
        update_interval: float,
        idle_release: float,
        connection_timeout: float,
        bluez_start_notify: bool,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"ad1204u {address}",
            update_interval=timedelta(seconds=update_interval),
        )
        self.address = address
        self.device_name = name
        self._token = token
        self._idle_release = idle_release
        self._connection_timeout = connection_timeout
        self._bluez_start_notify = bluez_start_notify

        self._client: BleakClient | None = None
        self._auth: MiAuthClient | None = None
        self._session: MiSession | None = None
        self._lock = asyncio.Lock()
        self._last_success_ts: float = 0.0
        self._idle_task: asyncio.Task | None = None

    # ------------------------------------------------------------ lifecycle
    def _on_disconnect(self, client: BleakClient) -> None:
        """Handle unexpected disconnects."""
        if self._client is not client:
            return
        _LOGGER.debug("AD1204U %s disconnected unexpectedly", self.address)
        self._session = None
        self._auth = None
        self._client = None
        # Notify the coordinator immediately so entities go unavailable
        # instead of waiting for the next 30-second poll interval.
        self.hass.loop.call_soon_threadsafe(
            self.async_set_update_error, BleakError("Device disconnected unexpectedly")
        )

    async def async_shutdown(self) -> None:
        if self._idle_task is not None:
            self._idle_task.cancel()
            self._idle_task = None
        await self._disconnect()

    # ---------------------------------------------------------- connection
    async def _ensure_connected(self) -> MiSession:
        if self._session is not None and self._client is not None and self._client.is_connected:
            return self._session

        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if ble_device is None:
            raise UpdateFailed(f"{self.address} not currently visible over Bluetooth")

        _LOGGER.debug("connecting to %s", self.address)
        client = await establish_connection(
            BleakClient,
            ble_device,
            self.device_name or self.address,
            max_attempts=3,
            timeout=self._connection_timeout,
            disconnected_callback=self._on_disconnect,
        )
        try:
            backend = getattr(client, "_backend", None)
            if backend is not None and hasattr(backend, "_acquire_mtu"):
                try:
                    await backend._acquire_mtu()
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("_acquire_mtu failed", exc_info=True)

            auth = MiAuthClient(
                client,
                timeout=self._connection_timeout,
                bluez_start_notify=self._bluez_start_notify,
            )
            await auth.subscribe(upnp=False)
            await auth.greet()
            await auth.subscribe_upnp()
            keys = await auth.login(self._token)

            session = MiSession(auth, keys, timeout=self._connection_timeout)
            await session.subscribe()
            # Post-login settle: the per-port measurement register can lag the
            # PD contract by up to ~300 ms, so the first get_properties right
            # after login occasionally catches mid-slew bytes (e.g. in_use=1
            # with b3 reading a non-standard voltage). A short delay here
            # prevents that glitch from ever reaching HA sensors.
            await asyncio.sleep(0.3)
        except Exception:
            try:
                await client.disconnect()
            except Exception:  # noqa: BLE001
                _LOGGER.debug("disconnect after failed setup", exc_info=True)
            raise

        self._client = client
        self._auth = auth
        self._session = session
        _LOGGER.info("AD1204U %s connected + logged in", self.address)
        return session

    async def _disconnect(self) -> None:
        session, auth, client = self._session, self._auth, self._client
        self._session = None
        self._auth = None
        self._client = None
        for label, obj, coro_name in (
            ("session", session, "unsubscribe"),
            ("auth", auth, "unsubscribe"),
            ("client", client, "disconnect"),
        ):
            if obj is None:
                continue
            try:
                await getattr(obj, coro_name)()
            except Exception:  # noqa: BLE001
                _LOGGER.debug("%s.%s() failed", label, coro_name, exc_info=True)
        if client is not None:
            _LOGGER.info("AD1204U %s disconnected", self.address)

    # ------------------------------------------------------------ writes
    async def async_set_property(
        self,
        siid: int,
        piid: int,
        value: int | bool,
        *,
        u32: bool = False,
    ) -> None:
        """Write a MIOT property under the same lock as polling.

        Triggers an immediate refresh so entity state reflects the write
        before HA services return.
        """
        async with self._lock:
            try:
                session = await self._ensure_connected()
                await set_property(session, siid, piid, value, u32=u32)
            except BleakError as exc:
                await self._disconnect()
                raise UpdateFailed(f"BLE error on set: {exc}") from exc
            except Exception as exc:
                await self._disconnect()
                raise UpdateFailed(f"set_property failed: {exc}") from exc
            self._last_success_ts = asyncio.get_event_loop().time()
        # Use async_refresh (immediate) rather than async_request_refresh
        # (debounced) so entity state mirrors the write before the service
        # call returns to the HA client.
        await asyncio.sleep(0.25)
        await self.async_refresh()

    # ----------------------------------------------------------- polling
    async def _async_update_data(self) -> AD1204UData:
        async with self._lock:
            try:
                session = await self._ensure_connected()
                values = await get_properties(session)
            except BleakError as exc:
                await self._disconnect()
                raise UpdateFailed(f"BLE error: {exc}") from exc
            except Exception as exc:
                await self._disconnect()
                raise UpdateFailed(f"{type(exc).__name__}: {exc}") from exc

        self._last_success_ts = asyncio.get_event_loop().time()
        self._schedule_idle_release()
        return _build_snapshot(values)

    def _schedule_idle_release(self) -> None:
        if self._idle_release <= 0:
            return
        if self._idle_task is not None and not self._idle_task.done():
            return
        self._idle_task = self.hass.async_create_background_task(
            self._idle_release_loop(), name=f"ad1204u_idle_{self.address}"
        )

    async def _idle_release_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._idle_release)
                now = asyncio.get_event_loop().time()
                if now - self._last_success_ts >= self._idle_release:
                    # No successful poll recently — release the connection.
                    # Next update tick will re-establish it.
                    async with self._lock:
                        if self._client is not None and self._client.is_connected:
                            _LOGGER.debug(
                                "idle release after %.1fs", now - self._last_success_ts
                            )
                            await self._disconnect()
                    return
        except asyncio.CancelledError:
            return


def _build_snapshot(values: dict[tuple[int, int], Any]) -> AD1204UData:
    ports: dict[str, PortInfo] = {}
    for piid, port in PIID_TO_PORT.items():
        item = values.get((2, piid))
        if item is None:
            continue
        ports[port] = decode_port_info(port, item.value)

    def _u32(piid: int) -> int | None:
        item = values.get((2, piid))
        return None if item is None else int(item.value)

    def _u8(piid: int) -> int | None:
        item = values.get((2, piid))
        return None if item is None else int(item.value)

    def _bool(piid: int) -> bool | None:
        item = values.get((2, piid))
        return None if item is None else bool(item.value)

    pdo: dict[str, int | None] = {p: None for p in PORTS}
    c1c2 = _u32(0x11)
    if c1c2 is not None:
        pdo.update(decode_pdo_caps(c1c2, high_port="c1", low_port="c2"))
    c3a = _u32(0x12)
    if c3a is not None:
        pdo.update(decode_pdo_caps(c3a, high_port="c3", low_port="a"))

    total = round(sum(info.power_w for info in ports.values()), 2)
    return AD1204UData(
        ports=ports,
        total_power_w=total,
        pdo_caps_w=pdo,
        scene_mode=_u8(5),
        screen_save_time=_u8(6),
        port_ctl=_u8(0x10),
        protocol_ctl=_u8(0x07),
        protocol_ctl_extend=_u32(0x15),
        device_language=_u8(0x0d),
        usb_a_always_on=_bool(0x0f),
        screenoff_while_idle=_bool(0x13),
        screen_dir_lock=_bool(0x14),
    )


