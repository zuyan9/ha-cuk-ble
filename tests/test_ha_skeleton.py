import json
from pathlib import Path

from cuktech_ble.constants import AD1204_LOCAL_NAME, FE95_UUID


def test_home_assistant_manifest_is_connectable_sensor_only_shape() -> None:
    manifest = json.loads(
        Path("custom_components/cuktech_ble/manifest.json").read_text()
    )

    assert manifest["domain"] == "cuktech_ble"
    assert manifest["config_flow"] is True
    assert manifest["iot_class"] == "local_polling"
    assert manifest["bluetooth"] == [
        {
            "local_name": AD1204_LOCAL_NAME,
            "service_uuid": FE95_UUID,
            "connectable": True,
        }
    ]


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
