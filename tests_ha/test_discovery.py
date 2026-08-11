"""Discovery filtering against real Home Assistant imports."""

from __future__ import annotations

from types import SimpleNamespace

from custom_components.cuktech_ble.config_flow import _looks_like_ad1204u
from custom_components.cuktech_ble.lib.constants import (
    AD1204_LOCAL_NAME,
    FE95_UUID,
)


def _service_info(
    *,
    local_name: str | None,
    service_data: dict[str, bytes] | None = None,
):
    advertisement = SimpleNamespace(
        local_name=local_name,
        service_data=service_data or {},
    )
    return SimpleNamespace(advertisement=advertisement)


async def test_discovery_accepts_only_name_or_matching_product_id() -> None:
    matching_fe95 = bytes.fromhex("10 59 0e 66 00 ff ee dd cc bb aa")
    other_xiaomi_fe95 = bytes.fromhex("58 58 5b 05 c8 64 42 b8 38 c1 a4")

    assert _looks_like_ad1204u(
        _service_info(local_name=AD1204_LOCAL_NAME)
    )
    assert _looks_like_ad1204u(
        _service_info(
            local_name=None,
            service_data={FE95_UUID.upper(): matching_fe95},
        )
    )
    assert not _looks_like_ad1204u(
        _service_info(
            local_name="unrelated.xiaomi.device",
            service_data={FE95_UUID: other_xiaomi_fe95},
        )
    )
    assert not _looks_like_ad1204u(
        _service_info(local_name=None, service_data={FE95_UUID: b"\x01"})
    )
    assert not _looks_like_ad1204u(_service_info(local_name=None))
