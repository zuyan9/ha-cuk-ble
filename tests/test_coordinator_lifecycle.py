import asyncio
import importlib.util
import sys
import types
from contextlib import suppress
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest


def _load_coordinator_module():
    """Load the coordinator without importing the HA-version-sensitive package."""
    class StubDataUpdateCoordinator:
        def __class_getitem__(cls, item):
            return cls

        async def async_shutdown(self) -> None:
            self._shutdown_requested = True

    class StubUpdateFailed(Exception):
        pass

    class StubConfigEntryAuthFailed(Exception):
        pass

    homeassistant = types.ModuleType("homeassistant")
    homeassistant.__path__ = []
    components = types.ModuleType("homeassistant.components")
    components.__path__ = []
    bluetooth = types.ModuleType("homeassistant.components.bluetooth")
    bluetooth.async_ble_device_from_address = Mock(
        side_effect=AssertionError("Bluetooth lookup was not stubbed by the test")
    )
    core = types.ModuleType("homeassistant.core")
    core.HomeAssistant = type("HomeAssistant", (), {})
    config_entries = types.ModuleType("homeassistant.config_entries")
    config_entries.ConfigEntry = type("ConfigEntry", (), {})
    exceptions = types.ModuleType("homeassistant.exceptions")
    exceptions.ConfigEntryAuthFailed = StubConfigEntryAuthFailed
    helpers = types.ModuleType("homeassistant.helpers")
    helpers.__path__ = []
    update_coordinator = types.ModuleType(
        "homeassistant.helpers.update_coordinator"
    )
    update_coordinator.DataUpdateCoordinator = StubDataUpdateCoordinator
    update_coordinator.UpdateFailed = StubUpdateFailed
    components.bluetooth = bluetooth

    stub_modules = {
        "homeassistant": homeassistant,
        "homeassistant.components": components,
        "homeassistant.components.bluetooth": bluetooth,
        "homeassistant.config_entries": config_entries,
        "homeassistant.core": core,
        "homeassistant.exceptions": exceptions,
        "homeassistant.helpers": helpers,
        "homeassistant.helpers.update_coordinator": update_coordinator,
    }
    missing = object()
    previous_modules = {
        name: sys.modules.get(name, missing) for name in stub_modules
    }
    sys.modules.update(stub_modules)

    package_name = "_cuktech_component_test"
    package = types.ModuleType(package_name)
    package.__path__ = [
        str(Path("custom_components/cuktech_ble").resolve())
    ]
    sys.modules[package_name] = package

    module_name = f"{package_name}.coordinator"
    path = Path("custom_components/cuktech_ble/coordinator.py").resolve()
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        for name, previous in previous_modules.items():
            if previous is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
    return module


coordinator_module = _load_coordinator_module()
AD1204UCoordinator = coordinator_module.AD1204UCoordinator


class FakeHass:
    def __init__(self) -> None:
        self.tasks: list[asyncio.Task] = []
        self.loop = asyncio.get_running_loop()

    def async_create_background_task(self, coro, *, name: str):
        task = asyncio.create_task(coro, name=name)
        self.tasks.append(task)
        return task


class FakeClient:
    def __init__(self) -> None:
        self.is_connected = True
        self.disconnect_calls = 0

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        self.is_connected = False


class FakeSubscription:
    def __init__(self) -> None:
        self.unsubscribe_calls = 0
        self.requires_reauthentication = False

    async def unsubscribe(self) -> None:
        self.unsubscribe_calls += 1


def _make_coordinator(*, idle_release: float) -> AD1204UCoordinator:
    coordinator = object.__new__(AD1204UCoordinator)
    coordinator.hass = FakeHass()
    coordinator.address = "AA:BB:CC:DD:EE:FF"
    coordinator._idle_release = idle_release
    coordinator._connection_timeout = 0.01
    coordinator._idle_task = None
    coordinator._disconnect_task = None
    coordinator._lock = asyncio.Lock()
    coordinator._client = None
    coordinator._connecting_client = None
    coordinator._auth = None
    coordinator._session = None
    coordinator._connection_generation = 0
    coordinator._property_values = {}
    coordinator._pending_notification_values = {}
    coordinator._baseline_session = None
    coordinator._notification_publish_pending = False
    coordinator._shutdown_requested = False
    coordinator.data = None
    return coordinator


def test_idle_release_disconnects_only_its_connection() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0.001)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session

        coordinator._arm_idle_release(client)
        idle_task = coordinator._idle_task
        assert idle_task is not None
        await asyncio.wait_for(idle_task, timeout=1)

        assert coordinator._client is None
        assert coordinator._auth is None
        assert coordinator._session is None
        assert client.disconnect_calls == 1
        assert auth.unsubscribe_calls == 1
        assert session.unsubscribe_calls == 1
        assert coordinator._idle_task is None

    asyncio.run(run())


def test_stale_idle_timer_does_not_disconnect_replacement_client() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        old_client = FakeClient()
        new_client = FakeClient()
        coordinator._client = new_client
        coordinator._auth = FakeSubscription()
        coordinator._session = FakeSubscription()

        await coordinator._idle_release_after(old_client)

        assert coordinator._client is new_client
        assert new_client.disconnect_calls == 0
        assert coordinator._auth.unsubscribe_calls == 0
        assert coordinator._session.unsubscribe_calls == 0

    asyncio.run(run())


def test_idle_release_cleans_up_matching_disconnected_client() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        client.is_connected = False
        auth = FakeSubscription()
        session = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session

        await coordinator._idle_release_after(client)

        assert coordinator._client is None
        assert coordinator._auth is None
        assert coordinator._session is None
        assert client.disconnect_calls == 1
        assert auth.unsubscribe_calls == 1
        assert session.unsubscribe_calls == 1

    asyncio.run(run())


def test_zero_idle_release_keeps_connection() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        coordinator._client = client

        coordinator._arm_idle_release(client)

        assert coordinator._idle_task is None
        assert coordinator.hass.tasks == []
        assert client.disconnect_calls == 0

    asyncio.run(run())


def test_rearming_keeps_replacement_timer_registered() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        client = FakeClient()
        coordinator._client = client

        coordinator._arm_idle_release(client)
        first_task = coordinator._idle_task
        assert first_task is not None

        coordinator._arm_idle_release(client)
        replacement_task = coordinator._idle_task
        assert replacement_task is not None
        assert replacement_task is not first_task

        await asyncio.sleep(0)
        assert first_task.cancelled()
        assert coordinator._idle_task is replacement_task

        replacement_task.cancel()
        with suppress(asyncio.CancelledError):
            await replacement_task

    asyncio.run(run())


def test_shutdown_guard_prevents_new_connection(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        coordinator._shutdown_requested = True
        device_lookup = Mock()
        establish_connection = AsyncMock()
        monkeypatch.setattr(
            coordinator_module.bluetooth,
            "async_ble_device_from_address",
            device_lookup,
        )
        monkeypatch.setattr(
            coordinator_module,
            "establish_connection",
            establish_connection,
        )

        with pytest.raises(
            coordinator_module.UpdateFailed,
            match="Coordinator is shutting down",
        ):
            await coordinator._ensure_connected()

        device_lookup.assert_not_called()
        establish_connection.assert_not_awaited()

    asyncio.run(run())


def test_new_connection_arms_idle_release(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        coordinator._token = b"token"
        coordinator.device_name = "charger"
        coordinator._connection_timeout = 15
        coordinator._bluez_start_notify = False
        coordinator.firmware_version = "known"
        coordinator._arm_idle_release = Mock()
        client = FakeClient()
        ble_device = object()
        device_lookup = Mock(return_value=ble_device)
        establish_connection = AsyncMock(return_value=client)

        class FakeAuth:
            def __init__(self, *args, **kwargs) -> None:
                pass

            async def subscribe(self, *, upnp: bool) -> None:
                pass

            async def greet(self) -> None:
                pass

            async def subscribe_upnp(self) -> None:
                pass

            async def login(self, token: bytes):
                assert token == b"token"
                return object()

            async def unsubscribe(self) -> None:
                pass

        class FakeSession:
            def __init__(
                self,
                auth,
                keys,
                *,
                timeout: float,
                notification_callback,
                fatal_error_callback,
            ) -> None:
                assert isinstance(auth, FakeAuth)
                assert timeout == 15
                self.notification_callback = notification_callback
                self.fatal_error_callback = fatal_error_callback
                self.requires_reauthentication = False

            async def subscribe(self) -> None:
                pass

            async def initialize(self) -> None:
                pass

            async def unsubscribe(self) -> None:
                pass

        monkeypatch.setattr(
            coordinator_module.bluetooth,
            "async_ble_device_from_address",
            device_lookup,
        )
        monkeypatch.setattr(
            coordinator_module,
            "establish_connection",
            establish_connection,
        )
        monkeypatch.setattr(coordinator_module, "MiAuthClient", FakeAuth)
        monkeypatch.setattr(coordinator_module, "MiSession", FakeSession)
        monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())

        session = await coordinator._ensure_connected()

        assert isinstance(session, FakeSession)
        assert coordinator._client is client
        assert coordinator._session is session
        coordinator._arm_idle_release.assert_called_once_with(client)
        device_lookup.assert_called_once_with(
            coordinator.hass,
            coordinator.address,
            connectable=True,
        )
        establish_connection.assert_awaited_once()

    asyncio.run(run())


def test_cancelled_setup_disconnects_established_client(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        coordinator._token = b"token"
        coordinator.device_name = "charger"
        coordinator._connection_timeout = 15
        coordinator._bluez_start_notify = False
        coordinator.firmware_version = "known"
        client = FakeClient()
        subscribe_started = asyncio.Event()
        auth_instances = []

        class BlockingAuth(FakeSubscription):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__()
                auth_instances.append(self)

            async def subscribe(self, *, upnp: bool) -> None:
                assert upnp is False
                subscribe_started.set()
                await asyncio.Event().wait()

        monkeypatch.setattr(
            coordinator_module.bluetooth,
            "async_ble_device_from_address",
            Mock(return_value=object()),
        )
        monkeypatch.setattr(
            coordinator_module,
            "establish_connection",
            AsyncMock(return_value=client),
        )
        monkeypatch.setattr(coordinator_module, "MiAuthClient", BlockingAuth)

        setup_task = asyncio.create_task(coordinator._ensure_connected())
        await subscribe_started.wait()
        setup_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await setup_task

        assert auth_instances[0].unsubscribe_calls == 1
        assert client.disconnect_calls == 1
        assert coordinator._connecting_client is None
        assert coordinator._client is None
        assert coordinator._session is None

    asyncio.run(run())


def test_disconnect_during_setup_cannot_install_client(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        coordinator._token = b"token"
        coordinator.device_name = "charger"
        coordinator._connection_timeout = 15
        coordinator._bluez_start_notify = False
        coordinator.firmware_version = "known"
        client = FakeClient()
        auth_instances = []

        class DisconnectingAuth(FakeSubscription):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__()
                auth_instances.append(self)

            async def subscribe(self, *, upnp: bool) -> None:
                coordinator._handle_disconnect(client)

            async def greet(self) -> None:
                pass

            async def subscribe_upnp(self) -> None:
                pass

            async def login(self, token: bytes):
                return object()

        class FakeSession(FakeSubscription):
            def __init__(self, *args, **kwargs) -> None:
                super().__init__()

            async def subscribe(self) -> None:
                pass

            async def initialize(self) -> None:
                pass

        monkeypatch.setattr(
            coordinator_module.bluetooth,
            "async_ble_device_from_address",
            Mock(return_value=object()),
        )
        monkeypatch.setattr(
            coordinator_module,
            "establish_connection",
            AsyncMock(return_value=client),
        )
        monkeypatch.setattr(coordinator_module, "MiAuthClient", DisconnectingAuth)
        monkeypatch.setattr(coordinator_module, "MiSession", FakeSession)
        monkeypatch.setattr(coordinator_module.asyncio, "sleep", AsyncMock())

        with pytest.raises(
            coordinator_module.UpdateFailed,
            match="connection changed during setup",
        ):
            await coordinator._ensure_connected()

        assert auth_instances[0].unsubscribe_calls == 1
        assert client.disconnect_calls == 1
        assert coordinator._client is None
        assert coordinator._session is None

    asyncio.run(run())


def test_expired_counter_session_is_released_before_reconnect(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        session.requires_reauthentication = True
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session
        lookup = Mock(return_value=None)
        monkeypatch.setattr(
            coordinator_module.bluetooth,
            "async_ble_device_from_address",
            lookup,
        )

        with pytest.raises(
            coordinator_module.UpdateFailed,
            match="not currently visible",
        ):
            await coordinator._ensure_connected()

        assert session.unsubscribe_calls == 1
        assert auth.unsubscribe_calls == 1
        assert client.disconnect_calls == 1
        lookup.assert_called_once()

    asyncio.run(run())


def test_scheduled_poll_does_not_rearm_idle_release(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        client = FakeClient()
        session = object()
        coordinator._client = client
        coordinator._session = session
        coordinator._ensure_connected = AsyncMock(return_value=session)
        coordinator._arm_idle_release = Mock()
        get_properties = AsyncMock(return_value={})
        monkeypatch.setattr(coordinator_module, "get_properties", get_properties)

        await coordinator._async_update_data()

        coordinator._arm_idle_release.assert_not_called()
        get_properties.assert_awaited_once()
        assert coordinator._property_values == {}

    asyncio.run(run())


def test_invalid_token_during_refresh_requests_reauthentication() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        invalid_token_error = coordinator_module.MiAuthInvalidTokenError(
            "confirmed token rejection"
        )
        coordinator._ensure_connected = AsyncMock(side_effect=invalid_token_error)

        with pytest.raises(
            coordinator_module.ConfigEntryAuthFailed,
            match="rejected the configured BLE token",
        ):
            await coordinator._async_update_data()

        assert coordinator._client is None
        assert coordinator._session is None

    asyncio.run(run())


def test_disconnect_generation_rejects_inflight_poll(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session
        coordinator._ensure_connected = AsyncMock(return_value=session)
        coordinator.async_set_update_error = Mock()

        async def disconnect_then_return(_session):
            coordinator._handle_disconnect(client)
            return {
                (2, 5): coordinator_module.PropertyValue(
                    2, 5, 0, 0x01, 0x10, 3
                )
            }

        monkeypatch.setattr(
            coordinator_module, "get_properties", disconnect_then_return
        )

        with pytest.raises(
            coordinator_module.UpdateFailed,
            match="connection changed during refresh",
        ):
            await coordinator._async_update_data()

        cleanup_task = coordinator._disconnect_task
        if cleanup_task is not None:
            await cleanup_task
        assert coordinator._baseline_session is None
        assert coordinator._property_values == {}
        coordinator.async_set_update_error.assert_called_once()

    asyncio.run(run())


def test_disconnect_generation_rejects_inflight_set(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session
        coordinator._ensure_connected = AsyncMock(return_value=session)
        coordinator.async_set_update_error = Mock()
        coordinator.async_refresh = AsyncMock()

        async def disconnect_during_set(*_args, **_kwargs) -> None:
            coordinator._handle_disconnect(client)

        monkeypatch.setattr(
            coordinator_module, "set_property", disconnect_during_set
        )

        with pytest.raises(
            coordinator_module.UpdateFailed,
            match="connection changed during set",
        ):
            await coordinator.async_set_property(2, 5, 1)

        cleanup_task = coordinator._disconnect_task
        if cleanup_task is not None:
            await cleanup_task
        coordinator.async_refresh.assert_not_awaited()
        assert coordinator._client is None

    asyncio.run(run())


def test_fatal_reader_error_marks_unavailable_and_cleans_up() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session
        coordinator._baseline_session = session
        coordinator.async_set_update_error = Mock()
        error = RuntimeError("notification reader stopped")

        coordinator._handle_session_error(session, error)

        coordinator.async_set_update_error.assert_called_once_with(error)
        assert coordinator._baseline_session is None
        cleanup_task = coordinator._disconnect_task
        assert cleanup_task is not None
        await cleanup_task
        assert coordinator._client is None
        assert session.unsubscribe_calls == 1
        assert auth.unsubscribe_calls == 1
        assert client.disconnect_calls == 1

    asyncio.run(run())


def test_property_notification_merges_partial_snapshot() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        session = object()
        coordinator._session = session
        coordinator._baseline_session = session
        property_value = coordinator_module.PropertyValue
        coordinator._property_values = {
            (2, 1): property_value(2, 1, 0, 0x04, 0x50, 0x32010A01),
            (2, 2): property_value(2, 2, 0, 0x04, 0x50, 0x64020A01),
            (2, 5): property_value(2, 5, 0, 0x01, 0x10, 3),
        }
        coordinator.data = coordinator_module._build_snapshot(
            coordinator._property_values
        )

        published = []

        def set_updated(data) -> None:
            published.append(data)
            coordinator.data = data

        coordinator.async_set_updated_data = set_updated
        coordinator._handle_notification(
            session,
            bytes.fromhex("0f 20 34 12 04 01 02 01 00 04 50 01 0a 32 c8"),
        )
        await asyncio.sleep(0)

        assert len(published) == 1
        assert published[0].ports["c1"].power_w == 100.0
        assert published[0].ports["c2"].power_w == 2.0
        assert published[0].scene_mode == 3
        assert published[0].total_power_w == 102.0

    asyncio.run(run())


def test_setting_echo_merges_and_stale_session_is_ignored() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        current_session = object()
        stale_session = object()
        coordinator._session = current_session
        coordinator._baseline_session = current_session
        property_value = coordinator_module.PropertyValue
        coordinator._property_values = {
            (2, 0x13): property_value(2, 0x13, 0, 0x01, 0x00, True),
        }
        coordinator.data = coordinator_module._build_snapshot(
            coordinator._property_values
        )
        coordinator.async_set_updated_data = Mock()
        event = bytes.fromhex("0c 20 22 00 04 01 02 13 00 01 00 00")

        coordinator._handle_notification(stale_session, event)
        await asyncio.sleep(0)
        coordinator.async_set_updated_data.assert_not_called()

        coordinator._handle_notification(current_session, event)
        await asyncio.sleep(0)
        updated = coordinator.async_set_updated_data.call_args.args[0]
        assert updated.screenoff_while_idle is False

    asyncio.run(run())


def test_reconnect_push_waits_for_current_session_baseline() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        session = object()
        coordinator._session = session
        # Data from a previous connection remains visible while reconnecting.
        coordinator.data = coordinator_module.AD1204UData(scene_mode=3)
        coordinator.async_set_updated_data = Mock()

        first = bytes.fromhex(
            "0f 20 34 12 04 01 02 01 00 04 50 01 0a 31 c8"
        )
        coordinator._handle_notification(session, first)
        await asyncio.sleep(0)
        coordinator.async_set_updated_data.assert_not_called()

        coordinator._baseline_session = session
        second = bytes.fromhex(
            "0f 20 35 12 04 01 02 01 00 04 50 01 0a 32 c8"
        )
        coordinator._handle_notification(session, second)
        await asyncio.sleep(0)
        coordinator.async_set_updated_data.assert_called_once()

    asyncio.run(run())


def test_queued_push_cannot_restore_success_after_disconnect() -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        client = FakeClient()
        session = FakeSubscription()
        auth = FakeSubscription()
        coordinator._client = client
        coordinator._session = session
        coordinator._auth = auth
        coordinator._baseline_session = session
        property_value = coordinator_module.PropertyValue
        coordinator._property_values = {
            (2, 1): property_value(2, 1, 0, 0x04, 0x50, 0x32010A01),
        }
        coordinator.data = coordinator_module._build_snapshot(
            coordinator._property_values
        )
        coordinator.async_set_updated_data = Mock()
        coordinator.async_set_update_error = Mock()

        coordinator._handle_notification(
            session,
            bytes.fromhex("0f 20 34 12 04 01 02 01 00 04 50 01 0a 32 c8"),
        )
        coordinator._handle_disconnect(client)
        cleanup_task = coordinator._disconnect_task
        assert cleanup_task is not None
        await cleanup_task
        await asyncio.sleep(0)

        coordinator.async_set_update_error.assert_called_once()
        coordinator.async_set_updated_data.assert_not_called()
        assert coordinator._baseline_session is None

    asyncio.run(run())


def test_successful_write_rearms_idle_release(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        client = FakeClient()
        session = object()
        coordinator._client = client
        coordinator._session = session
        coordinator._ensure_connected = AsyncMock(return_value=session)
        coordinator._arm_idle_release = Mock()
        coordinator.async_refresh = AsyncMock()
        set_property = AsyncMock()
        monkeypatch.setattr(coordinator_module, "set_property", set_property)

        await coordinator.async_set_property(2, 5, 1)

        coordinator._arm_idle_release.assert_called_once_with(client)
        set_property.assert_awaited_once_with(session, 2, 5, 1, u32=False)
        coordinator.async_refresh.assert_awaited_once()

    asyncio.run(run())


def test_shutdown_waits_for_inflight_work_and_is_idempotent(monkeypatch) -> None:
    async def fake_parent_shutdown(self) -> None:
        self._shutdown_requested = True
        self.parent_shutdown_calls = getattr(self, "parent_shutdown_calls", 0) + 1

    monkeypatch.setattr(
        coordinator_module.DataUpdateCoordinator,
        "async_shutdown",
        fake_parent_shutdown,
    )

    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = FakeSubscription()
        work_started = asyncio.Event()
        finish_work = asyncio.Event()

        async def in_flight_work() -> None:
            async with coordinator._lock:
                work_started.set()
                await finish_work.wait()
                coordinator._client = client
                coordinator._auth = auth
                coordinator._session = session

        work_task = asyncio.create_task(in_flight_work())
        await work_started.wait()
        shutdown_task = asyncio.create_task(coordinator.async_shutdown())
        await asyncio.sleep(0)

        assert coordinator.parent_shutdown_calls == 1
        assert coordinator._shutdown_requested is True
        assert shutdown_task.done() is False
        assert client.disconnect_calls == 0

        finish_work.set()
        await work_task
        await asyncio.wait_for(shutdown_task, timeout=1)

        assert client.disconnect_calls == 1
        assert auth.unsubscribe_calls == 1
        assert session.unsubscribe_calls == 1
        assert coordinator._client is None

        await coordinator.async_shutdown()
        assert coordinator.parent_shutdown_calls == 2
        assert client.disconnect_calls == 1

    asyncio.run(run())


def test_disconnect_times_out_wedged_cleanup_and_continues() -> None:
    class HangingSubscription:
        def __init__(self) -> None:
            self.cancelled = False

        async def unsubscribe(self) -> None:
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True

    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        auth = FakeSubscription()
        session = HangingSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session

        await asyncio.wait_for(coordinator._disconnect(), timeout=0.2)

        assert session.cancelled is True
        assert auth.unsubscribe_calls == 1
        assert client.disconnect_calls == 1
        assert coordinator._client is None
        assert coordinator._auth is None
        assert coordinator._session is None

    asyncio.run(run())


def test_shutdown_does_not_cancel_active_idle_cleanup(monkeypatch) -> None:
    async def fake_parent_shutdown(self) -> None:
        self._shutdown_requested = True

    monkeypatch.setattr(
        coordinator_module.DataUpdateCoordinator,
        "async_shutdown",
        fake_parent_shutdown,
    )

    async def run() -> None:
        coordinator = _make_coordinator(idle_release=0)
        client = FakeClient()
        cleanup_started = asyncio.Event()
        finish_cleanup = asyncio.Event()

        class BlockingSession(FakeSubscription):
            async def unsubscribe(self) -> None:
                self.unsubscribe_calls += 1
                cleanup_started.set()
                await finish_cleanup.wait()

        session = BlockingSession()
        auth = FakeSubscription()
        coordinator._client = client
        coordinator._auth = auth
        coordinator._session = session
        idle_task = asyncio.create_task(coordinator._idle_release_after(client))
        coordinator._idle_task = idle_task

        await cleanup_started.wait()
        shutdown_task = asyncio.create_task(coordinator.async_shutdown())
        await asyncio.sleep(0)

        assert shutdown_task.done() is False
        assert idle_task.cancelled() is False
        assert client.disconnect_calls == 0

        finish_cleanup.set()
        await idle_task
        await asyncio.wait_for(shutdown_task, timeout=1)

        assert session.unsubscribe_calls == 1
        assert auth.unsubscribe_calls == 1
        assert client.disconnect_calls == 1
        assert coordinator._idle_task is None

    asyncio.run(run())
