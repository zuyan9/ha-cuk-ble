import json
from pathlib import Path
import tomllib

from cuktech_ble.constants import AD1204_LOCAL_NAME, FE95_UUID


def test_home_assistant_manifest_is_connectable_sensor_only_shape() -> None:
    manifest = json.loads(
        Path("custom_components/cuktech_ble/manifest.json").read_text()
    )

    assert manifest["domain"] == "cuktech_ble"
    assert manifest["config_flow"] is True
    assert manifest["iot_class"] == "local_push"
    assert manifest["bluetooth"] == [
        {
            "local_name": AD1204_LOCAL_NAME,
            "service_uuid": FE95_UUID,
            "connectable": True,
        }
    ]


def test_release_metadata_stays_in_sync() -> None:
    manifest = json.loads(
        Path("custom_components/cuktech_ble/manifest.json").read_text()
    )
    hacs = json.loads(Path("hacs.json").read_text())
    pyproject = tomllib.loads(Path("pyproject.toml").read_text())

    assert manifest["version"] == pyproject["project"]["version"]
    assert hacs["homeassistant"] == "2025.3.0"


def test_hacs_requires_the_first_supported_home_assistant_release() -> None:
    hacs = json.loads(Path("hacs.json").read_text())

    assert hacs["homeassistant"] == "2025.3.0"


def test_config_flow_keeps_tokens_and_cloud_cookies_private() -> None:
    config_flow = Path("custom_components/cuktech_ble/config_flow.py").read_text()

    assert "TextSelectorType.PASSWORD" in config_flow
    assert "async_create_clientsession" in config_flow
    assert "cookie_jar=aiohttp.CookieJar()" in config_flow
    assert "parse_fe95(service_data).product_id == AD1204_PRODUCT_ID" in config_flow


def test_home_assistant_skeleton_registers_expected_platforms() -> None:
    init_py = Path("custom_components/cuktech_ble/__init__.py").read_text()

    assert "Platform.SENSOR" in init_py
    assert "Platform.BINARY_SENSOR" in init_py
    # Writable booleans (usb_a_always_on, screenoff_while_idle, screen_dir_lock)
    # use the set_properties wire format reversed from a tablet Mi Home capture.
    assert "Platform.SWITCH" in init_py
    # scene_mode enum reversed from a second capture — AI/Hybrid/Single/Dual.
    assert "Platform.SELECT" in init_py
    # Number and button writes still not exercised.
    assert "Platform.NUMBER" not in init_py
    assert "Platform.BUTTON" not in init_py


def test_only_capture_verified_switches_are_exposed() -> None:
    switch_py = Path("custom_components/cuktech_ble/switch.py").read_text()

    assert "AD1204UPortSwitch" not in switch_py
    assert "AD1204UProtocolSwitch" not in switch_py
    assert "0x0010" not in switch_py
    assert "0x0015" not in switch_py
    assert "0x000e" not in switch_py


def test_sensor_builder_has_one_voltage_and_current_entity_per_port() -> None:
    sensor_py = Path("custom_components/cuktech_ble/sensor.py").read_text()

    assert sensor_py.count('key=f"{port}_voltage"') == 1
    assert sensor_py.count('key=f"{port}_current"') == 1
