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


def test_home_assistant_skeleton_does_not_define_control_platforms() -> None:
    init_py = Path("custom_components/cuktech_ble/__init__.py").read_text()

    assert "Platform.SENSOR" in init_py
    assert "Platform.SWITCH" not in init_py
    assert "Platform.SELECT" not in init_py
    assert "Platform.NUMBER" not in init_py
    assert "Platform.BUTTON" not in init_py
