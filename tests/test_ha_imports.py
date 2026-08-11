"""Import the integration against the declared minimum Home Assistant."""

from __future__ import annotations

from importlib import import_module
from importlib.metadata import PackageNotFoundError, version

import pytest


INTEGRATION_MODULES = (
    "custom_components.cuktech_ble",
    "custom_components.cuktech_ble.binary_sensor",
    "custom_components.cuktech_ble.config_flow",
    "custom_components.cuktech_ble.const",
    "custom_components.cuktech_ble.coordinator",
    "custom_components.cuktech_ble.diagnostics",
    "custom_components.cuktech_ble.entity",
    "custom_components.cuktech_ble.select",
    "custom_components.cuktech_ble.sensor",
    "custom_components.cuktech_ble.switch",
)


def _require_supported_home_assistant() -> None:
    try:
        installed = version("homeassistant")
    except PackageNotFoundError:
        pytest.skip("Home Assistant is not installed in the unit-test environment")

    release = tuple(int(part) for part in installed.split(".")[:2])
    if release < (2025, 3):
        pytest.skip(f"Home Assistant {installed} predates the supported minimum")


@pytest.mark.parametrize("module_name", INTEGRATION_MODULES)
def test_integration_module_imports(module_name: str) -> None:
    _require_supported_home_assistant()
    import_module(module_name)
