"""DataUpdateCoordinator for the CUKTECH AD1204U charger.

Strategy: push-driven BLE session with periodic reconciliation and an idle lease.

- On first refresh, connect + login + enter the MIOT application session.
- ACK and merge spontaneous property events as soon as they arrive.
- Reconcile all siid=2 properties every ``update_interval`` seconds when pushes
  are quiet.
- Release the connection ``idle_release`` seconds after login or the last explicit
  property write. Scheduled polls do not extend the lease; the next poll reconnects.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection
from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .lib.firmware import FIRMWARE_VERSION_UUID, decode_firmware_version
from .lib.ports import (
    PIID_TO_PORT,
    PORTS,
    PortInfo,
    decode_pdo_caps,
    decode_port_info,
)
from .lib.xiaomi import MiAuthClient
from .lib.xiaomi.auth import MiAuthInvalidTokenError
from .lib.xiaomi.properties import (
    MiotProtocolError,
    PropertyValue,
    get_properties,
    parse_notification,
    set_property,
)
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
    """Own the live BLE+MIOT session, push updates, and reconciliation reads."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        config_entry: ConfigEntry[Any],
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
            config_entry=config_entry,
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
        self._connecting_client: BleakClient | None = None
        self._auth: MiAuthClient | None = None
        self._session: MiSession | None = None
        self._connection_generation = 0
        self.firmware_version: str | None = None
        self._lock = asyncio.Lock()
        self._idle_task: asyncio.Task[None] | None = None
        self._disconnect_task: asyncio.Task[None] | None = None
        self._property_values: dict[tuple[int, int], PropertyValue] = {}
        self._pending_notification_values: dict[tuple[int, int], PropertyValue] = {}
        self._baseline_session: MiSession | None = None
        self._notification_publish_pending = False

    # ------------------------------------------------------------ lifecycle
    def _on_disconnect(self, client: BleakClient) -> None:
        """Handle unexpected disconnects."""
        self.hass.loop.call_soon_threadsafe(self._handle_disconnect, client)

    def _handle_disconnect(self, client: BleakClient) -> None:
        """Mark unavailable and clean up a disconnected session on the HA loop."""
        if self._connecting_client is client:
            # _ensure_connected() owns cleanup until the setup is published as
            # the current connection. Invalidating its generation prevents a
            # late successful login from installing this disconnected client.
            self._connection_generation += 1
            _LOGGER.debug("AD1204U %s disconnected during setup", self.address)
            return
        if self._client is not client:
            return
        _LOGGER.debug("AD1204U %s disconnected unexpectedly", self.address)
        self._connection_generation += 1
        # Invalidate push publication before marking the coordinator failed.
        # A notification already queued on the event loop must not make stale
        # data available again after this disconnect.
        self._baseline_session = None
        self._notification_publish_pending = False
        self.async_set_update_error(BleakError("Device disconnected unexpectedly"))
        if self._disconnect_task is not None and not self._disconnect_task.done():
            return
        task = self.hass.async_create_background_task(
            self._cleanup_disconnected_client(client),
            name=f"ad1204u_disconnect_{self.address}",
        )
        self._disconnect_task = task
        task.add_done_callback(self._disconnect_cleanup_finished)

    def _handle_session_error(
        self, session: MiSession | None, error: Exception
    ) -> None:
        """Fail and tear down a session whose notification reader stopped."""
        if session is None or self._session is not session:
            return
        client = self._client
        if client is None:
            return
        _LOGGER.debug("AD1204U %s MIOT session failed: %s", self.address, error)
        self._connection_generation += 1
        self._baseline_session = None
        self._notification_publish_pending = False
        self.async_set_update_error(error)
        if self._disconnect_task is not None and not self._disconnect_task.done():
            return
        task = self.hass.async_create_background_task(
            self._cleanup_disconnected_client(client),
            name=f"ad1204u_session_error_{self.address}",
        )
        self._disconnect_task = task
        task.add_done_callback(self._disconnect_cleanup_finished)

    def _disconnect_cleanup_finished(self, task: asyncio.Task[None]) -> None:
        if self._disconnect_task is task:
            self._disconnect_task = None

    async def _cleanup_disconnected_client(self, client: BleakClient) -> None:
        async with self._lock:
            if self._client is client:
                await self._disconnect()

    async def async_shutdown(self) -> None:
        """Stop refreshes and release all BLE resources."""
        await super().async_shutdown()

        # Waiting for the lock lets an in-flight poll, write, or idle disconnect
        # finish before cleanup. Cancel the timer only after owning the lock so
        # cancellation cannot interrupt it halfway through _disconnect().
        async with self._lock:
            idle_task = self._idle_task
            self._idle_task = None
            if idle_task is not None and idle_task is not asyncio.current_task():
                idle_task.cancel()
            await self._disconnect()

        if idle_task is not None and idle_task is not asyncio.current_task():
            with suppress(asyncio.CancelledError):
                await idle_task

        disconnect_task = self._disconnect_task
        if (
            disconnect_task is not None
            and disconnect_task is not asyncio.current_task()
        ):
            with suppress(asyncio.CancelledError):
                await disconnect_task

    # ---------------------------------------------------------- connection
    async def _ensure_connected(self) -> MiSession:
        if self._shutdown_requested:
            raise UpdateFailed("Coordinator is shutting down")

        if (
            self._session is not None
            and self._client is not None
            and self._client.is_connected
        ):
            if not self._session.requires_reauthentication:
                return self._session
            _LOGGER.debug(
                "reconnecting %s before MIOT encryption counter reuse",
                self.address,
            )
            await self._disconnect()

        # A missed/late disconnect callback can leave the old objects attached
        # even though the client is no longer connected. Release them before
        # establishing a replacement so setup can never overwrite resources.
        if (
            self._client is not None
            or self._auth is not None
            or self._session is not None
        ):
            await self._disconnect()

        ble_device = bluetooth.async_ble_device_from_address(
            self.hass, self.address, connectable=True
        )
        if ble_device is None:
            raise UpdateFailed(f"{self.address} not currently visible over Bluetooth")

        setup_generation = self._connection_generation
        _LOGGER.debug("connecting to %s", self.address)
        client = await establish_connection(
            BleakClient,
            ble_device,
            self.device_name or self.address,
            max_attempts=3,
            timeout=self._connection_timeout,
            disconnected_callback=self._on_disconnect,
        )
        self._connecting_client = client
        auth: MiAuthClient | None = None
        session: MiSession | None = None
        try:
            if self.firmware_version is None:
                self.firmware_version = await self._read_firmware_version(client)

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

            def _on_notification(plaintext: bytes) -> None:
                self._handle_notification(session, plaintext)

            def _on_fatal_error(error: Exception) -> None:
                self._handle_session_error(session, error)

            session = MiSession(
                auth,
                keys,
                timeout=self._connection_timeout,
                notification_callback=_on_notification,
                fatal_error_callback=_on_fatal_error,
            )
            await session.subscribe()
            await session.initialize()
            # Post-login settle: the per-port measurement register can lag the
            # PD contract by up to ~300 ms, so the first get_properties right
            # after login occasionally catches mid-slew bytes (e.g. in_use=1
            # with b3 reading a non-standard voltage). A short delay here
            # prevents that glitch from ever reaching HA sensors.
            await asyncio.sleep(0.3)
            if (
                self._shutdown_requested
                or setup_generation != self._connection_generation
                or not client.is_connected
            ):
                raise UpdateFailed("BLE connection changed during setup")
        except BaseException:
            if self._connecting_client is client:
                self._connecting_client = None
            cleanup_task = asyncio.create_task(
                self._cleanup_setup_resources(session, auth, client),
                name=f"ad1204u_failed_setup_{self.address}",
            )
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                # A second cancellation must not strand the established BLE
                # connection. Finish the already-running bounded cleanup.
                await cleanup_task
            raise

        self._connecting_client = None
        self._connection_generation += 1
        self._client = client
        self._auth = auth
        self._session = session
        self._arm_idle_release(client)
        _LOGGER.info("AD1204U %s connected + logged in", self.address)
        return session

    async def _cleanup_setup_resources(
        self,
        session: MiSession | None,
        auth: MiAuthClient | None,
        client: BleakClient,
    ) -> None:
        """Release a connection that failed or was cancelled during setup."""
        await self._cleanup_resources(
            (
                ("session", session, "unsubscribe"),
                ("auth", auth, "unsubscribe"),
                ("client", client, "disconnect"),
            ),
            context="after incomplete setup",
        )

    async def _read_firmware_version(self, client: BleakClient) -> str | None:
        """Read the plain GATT firmware-version characteristic, if present."""
        try:
            raw = await client.read_gatt_char(FIRMWARE_VERSION_UUID)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("firmware version read failed", exc_info=True)
            return None
        return decode_firmware_version(raw)

    async def _disconnect(self) -> None:
        session, auth, client = self._session, self._auth, self._client
        if session is not None or auth is not None or client is not None:
            self._connection_generation += 1
        self._session = None
        self._auth = None
        self._client = None
        self._property_values.clear()
        self._pending_notification_values.clear()
        self._baseline_session = None
        self._notification_publish_pending = False
        await self._cleanup_resources(
            (
                ("session", session, "unsubscribe"),
                ("auth", auth, "unsubscribe"),
                ("client", client, "disconnect"),
            ),
        )
        if client is not None:
            _LOGGER.info("AD1204U %s disconnected", self.address)

    async def _cleanup_resources(
        self,
        resources: tuple[tuple[str, Any | None, str], ...],
        *,
        context: str | None = None,
    ) -> None:
        """Best-effort cleanup with a finite timeout for each BLE operation."""
        timeout = min(max(self._connection_timeout, 0.1), 10.0)
        for label, obj, coro_name in resources:
            if obj is None:
                continue
            try:
                async with asyncio.timeout(timeout):
                    await getattr(obj, coro_name)()
            except TimeoutError:
                _LOGGER.warning(
                    "%s.%s() timed out after %.1fs%s",
                    label,
                    coro_name,
                    timeout,
                    f" {context}" if context else "",
                )
            except Exception:  # noqa: BLE001
                _LOGGER.debug(
                    "%s.%s() failed%s",
                    label,
                    coro_name,
                    f" {context}" if context else "",
                    exc_info=True,
                )

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
                client = self._client
                generation = self._connection_generation
                if client is None:
                    raise UpdateFailed("BLE connection disappeared before set")
                await set_property(session, siid, piid, value, u32=u32)
                if (
                    self._connection_generation != generation
                    or self._session is not session
                    or self._client is not client
                    or not client.is_connected
                ):
                    raise UpdateFailed("BLE connection changed during set")
            except UpdateFailed:
                await self._disconnect()
                raise
            except MiAuthInvalidTokenError as exc:
                await self._disconnect()
                raise ConfigEntryAuthFailed(
                    "The charger rejected the configured BLE token"
                ) from exc
            except BleakError as exc:
                await self._disconnect()
                raise UpdateFailed(f"BLE error on set: {exc}") from exc
            except Exception as exc:
                await self._disconnect()
                raise UpdateFailed(f"set_property failed: {exc}") from exc
            if self._client is not None:
                # Explicit user activity extends the lease. Scheduled polling
                # deliberately does not, otherwise a short poll interval keeps
                # the one-peer BLE connection forever.
                self._arm_idle_release(self._client)
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
                client = self._client
                generation = self._connection_generation
                if client is None:
                    raise UpdateFailed("BLE connection disappeared before refresh")
                self._pending_notification_values.clear()
                values = await get_properties(session)
                if (
                    self._connection_generation != generation
                    or self._session is not session
                    or self._client is not client
                    or not client.is_connected
                ):
                    raise UpdateFailed("BLE connection changed during refresh")
                values.update(self._pending_notification_values)
                self._pending_notification_values.clear()
                self._property_values = values
                self._baseline_session = session
            except UpdateFailed:
                await self._disconnect()
                raise
            except MiAuthInvalidTokenError as exc:
                await self._disconnect()
                raise ConfigEntryAuthFailed(
                    "The charger rejected the configured BLE token"
                ) from exc
            except BleakError as exc:
                await self._disconnect()
                raise UpdateFailed(f"BLE error: {exc}") from exc
            except Exception as exc:
                await self._disconnect()
                raise UpdateFailed(f"{type(exc).__name__}: {exc}") from exc

        return _build_snapshot(values)

    def _handle_notification(
        self, session: MiSession | None, plaintext: bytes
    ) -> None:
        """Merge one app-style property event into the coordinator snapshot."""
        if session is None or self._session is not session:
            return
        try:
            items = parse_notification(plaintext)
        except MiotProtocolError:
            _LOGGER.debug("ignoring unsupported MIOT event: %s", plaintext.hex())
            return

        changed = False
        for item in items:
            if item.status != 0:
                continue
            self._pending_notification_values[item.key] = item
            if self._property_values.get(item.key) != item:
                self._property_values[item.key] = item
                changed = True

        if (
            not changed
            or self._baseline_session is not session
            or self._notification_publish_pending
        ):
            return
        self._notification_publish_pending = True
        self.hass.loop.call_soon(self._publish_notification_update, session)

    def _publish_notification_update(self, session: MiSession) -> None:
        """Publish all events coalesced during the current event-loop turn."""
        self._notification_publish_pending = False
        if self._session is not session or self._baseline_session is not session:
            return
        self.async_set_updated_data(_build_snapshot(self._property_values))

    def _arm_idle_release(self, client: BleakClient) -> None:
        """Start a one-shot release timer for the current BLE connection."""
        if self._idle_task is not None and not self._idle_task.done():
            self._idle_task.cancel()
        self._idle_task = None
        if self._idle_release <= 0:
            return
        self._idle_task = self.hass.async_create_background_task(
            self._idle_release_after(client), name=f"ad1204u_idle_{self.address}"
        )

    async def _idle_release_after(self, client: BleakClient) -> None:
        """Release one specific BLE connection after its idle lease expires."""
        try:
            await asyncio.sleep(self._idle_release)
            async with self._lock:
                # A reconnect can replace the client while an older timer is
                # sleeping. Never let that stale timer drop the new session.
                if self._client is client:
                    _LOGGER.debug(
                        "releasing BLE connection after %.1fs idle lease",
                        self._idle_release,
                    )
                    await self._disconnect()
        finally:
            if self._idle_task is asyncio.current_task():
                self._idle_task = None


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
