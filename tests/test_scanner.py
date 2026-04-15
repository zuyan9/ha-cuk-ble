import asyncio
from dataclasses import dataclass, field

from cuktech_ble.constants import FE95_UUID
from cuktech_ble.scanner import scan_chargers
from cuktech_ble.util import parse_hex


@dataclass
class FakeDevice:
    address: str
    name: str | None = None


@dataclass
class FakeAdvertisementData:
    local_name: str | None = None
    rssi: int | None = None
    service_data: dict[str, bytes] = field(default_factory=dict)
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    service_uuids: list[str] = field(default_factory=list)


class FakeScanner:
    @staticmethod
    async def discover(timeout: float, return_adv: bool) -> dict[str, tuple[object, object]]:
        assert timeout == 1
        assert return_adv is True
        return {
            "charger": (
                FakeDevice("AA:BB:CC:DD:EE:FF", None),
                FakeAdvertisementData(
                    local_name="njcuk.fitting.ad1204",
                    rssi=-51,
                    service_data={
                        FE95_UUID: parse_hex("10 59 0e 66 00 ff ee dd cc bb aa")
                    },
                    manufacturer_data={0x0969: b"\x01"},
                    service_uuids=[FE95_UUID],
                ),
            ),
            "other": (
                FakeDevice("00:11:22:33:44:55", "other"),
                FakeAdvertisementData(
                    local_name="LYWSD03MMC",
                    rssi=-70,
                    service_data={
                        FE95_UUID: parse_hex(
                            "58 58 5b 05 c8 64 42 b8 38 c1 a4 b3 4a"
                        )
                    },
                ),
            ),
        }


def test_scan_chargers_filters_and_parses_fe95_fixture() -> None:
    chargers = asyncio.run(scan_chargers(timeout=1, scanner_factory=FakeScanner))

    assert len(chargers) == 1
    charger = chargers[0]
    assert charger.address == "AA:BB:CC:DD:EE:FF"
    assert charger.name == "njcuk.fitting.ad1204"
    assert charger.rssi == -51
    assert charger.product_id == 0x660E
    assert charger.beacon is not None
    assert charger.beacon.mac_address == "AA:BB:CC:DD:EE:FF"
    assert charger.service_data_hex == "10 59 0e 66 00 ff ee dd cc bb aa"


def test_scan_chargers_can_filter_by_address() -> None:
    chargers = asyncio.run(
        scan_chargers(
            timeout=1,
            address="00:11:22:33:44:55",
            scanner_factory=FakeScanner,
        )
    )

    assert chargers == []
