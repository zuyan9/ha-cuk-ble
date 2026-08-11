import asyncio
from contextlib import suppress
import importlib.util
import sys
import types
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
        "homeassistant.core": core,
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

    async def unsubscribe(self) -> None:
        self.unsubscribe_calls += 1


def _make_coordinator(*, idle_release: float) -> AD1204UCoordinator:
    coordinator = object.__new__(AD1204UCoordinator)
    coordinator.hass = FakeHass()
    coordinator.address = "AA:BB:CC:DD:EE:FF"
    coordinator._idle_release = idle_release
    coordinator._idle_task = None
    coordinator._lock = asyncio.Lock()
    coordinator._client = None
    coordinator._auth = None
    coordinator._session = None
    coordinator._shutdown_requested = False
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

        class FakeSession:
            def __init__(self, auth, keys, *, timeout: float) -> None:
                assert isinstance(auth, FakeAuth)
                assert timeout == 15

            async def subscribe(self) -> None:
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


def test_scheduled_poll_does_not_rearm_idle_release(monkeypatch) -> None:
    async def run() -> None:
        coordinator = _make_coordinator(idle_release=300)
        coordinator._ensure_connected = AsyncMock(return_value=object())
        coordinator._arm_idle_release = Mock()
        get_properties = AsyncMock(return_value={})
        monkeypatch.setattr(coordinator_module, "get_properties", get_properties)

        await coordinator._async_update_data()

        coordinator._arm_idle_release.assert_not_called()
        get_properties.assert_awaited_once()

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
