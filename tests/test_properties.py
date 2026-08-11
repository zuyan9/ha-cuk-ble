import asyncio

import pytest
from cuktech_ble.xiaomi.properties import (
    MiotProtocolError,
    encode_get_properties,
    encode_set_property,
    parse_notification,
    parse_response,
    parse_set_response,
    set_property,
)


def test_encode_get_properties_matches_reversed_wire_format() -> None:
    # seq=0x000b, three siid=2 properties
    body = encode_get_properties(0x000B, ((2, 1), (2, 2), (2, 0x0F)))

    assert body.hex(" ") == "33 20 0b 00 02 03 02 01 00 02 02 00 02 0f 00"


def test_encode_set_property_bool_matches_reversed_wire_format() -> None:
    # Matches the tablet-capture frame: opcode 0c 20, seq, 00 01, siid=2,
    # piid=0x000f (usb_a_always_on), type=01 marker=00 value=01.
    body = encode_set_property(0x000D, 2, 0x000F, True)

    assert body.hex(" ") == "0c 20 0d 00 00 01 02 0f 00 01 00 01"


def test_encode_set_property_u32_uses_type_04_marker_50() -> None:
    body = encode_set_property(0x0001, 2, 0x0015, 0x03030F0F, u32=True)

    assert body.hex(" ") == "0c 20 01 00 00 01 02 15 00 04 50 0f 0f 03 03"


def test_encode_set_property_u8_uses_type_01_marker_10() -> None:
    body = encode_set_property(0x0002, 2, 0x0005, 3)

    assert body.hex(" ") == "0c 20 02 00 00 01 02 05 00 01 10 03"


def test_parse_set_response_ok() -> None:
    # Real tablet-capture response for usb_a_always_on=True
    pt = bytes.fromhex("0b 20 0d 00 01 01 02 0f 00 00 00".replace(" ", ""))

    results = parse_set_response(pt)

    assert results == [(2, 0x000F, 0)]


def test_parse_set_response_rejects_other_opcodes() -> None:
    pt = bytes.fromhex("93 20 0d 00 03 00")

    with pytest.raises(MiotProtocolError):
        parse_set_response(pt)

    with pytest.raises(MiotProtocolError, match="bad set-response header"):
        parse_set_response(bytes.fromhex("0b 20 0d 00 00 00"))

    with pytest.raises(MiotProtocolError, match="trailing set-response"):
        parse_set_response(
            bytes.fromhex("0b 20 0d 00 01 01 02 0f 00 00 00 ff")
        )


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (bytes.fromhex("0b 20 0d 00 01 00"), "exactly one result, got 0"),
        (
            bytes.fromhex("0b 20 0d 00 01 01 02 06 00 00 00"),
            "got result for siid=2, piid=0x6",
        ),
        (
            bytes.fromhex("0b 20 0d 00 01 01 02 0f 00 01 00"),
            "failed with status 0x0001",
        ),
        (
            bytes.fromhex(
                "0b 20 0d 00 01 02"
                "02 0f 00 00 00"
                "02 0f 00 00 00"
            ),
            "exactly one result, got 2",
        ),
    ),
)
def test_set_property_requires_one_matching_success(
    response: bytes, message: str
) -> None:
    class FakeSession:
        async def send_request(self, request: bytes) -> bytes:
            assert request[:4] == bytes.fromhex("0c 20 0d 00")
            return response

    async def run() -> None:
        with pytest.raises(MiotProtocolError, match=message):
            await set_property(  # type: ignore[arg-type]
                FakeSession(), 2, 0x0F, True, seq=0x000D
            )

    asyncio.run(run())


def test_set_property_accepts_exact_matching_success() -> None:
    class FakeSession:
        async def send_request(self, request: bytes) -> bytes:
            assert request[:4] == bytes.fromhex("0c 20 0d 00")
            return bytes.fromhex("0b 20 0d 00 01 01 02 0f 00 00 00")

    asyncio.run(
        set_property(  # type: ignore[arg-type]
            FakeSession(), 2, 0x0F, True, seq=0x000D
        )
    )


def test_parse_response_accepts_0x0e_single_property_opcode() -> None:
    # Single-property response seen on live firmware.
    pt = bytes.fromhex(
        "0e 20 34 12 03 01 02 13 00 00 00 01 10 00".replace(" ", "")
    )
    items = parse_response(pt)

    assert len(items) == 1
    assert items[0].key == (2, 0x13)
    assert items[0].marker == 0x10
    assert items[0].value == 0


def test_parse_response_accepts_0x1c_opcode_variant() -> None:
    # Same body layout as 0x93, but with opcode 0x1c (seen live on the charger).
    pt = bytes.fromhex(
        "1c 20 02 01 03 02"
        "02 01 00 00 00 04 50 01 0a 00 33"
        "02 11 00 00 00 04 50 00 00 0f 07".replace(" ", "")
    )
    items = parse_response(pt)

    assert len(items) == 2
    assert items[0].key == (2, 1)
    assert items[0].value == 0x33000A01
    assert items[1].key == (2, 0x11)


def test_parse_port_notification_without_status_field() -> None:
    pt = bytes.fromhex("0f 20 34 12 04 01 02 01 00 04 50 01 0a 32 c8")

    items = parse_notification(pt)

    assert len(items) == 1
    assert items[0].key == (2, 1)
    assert items[0].status == 0
    assert items[0].value == 0xC8320A01


def test_parse_setting_echo_normalizes_bool() -> None:
    pt = bytes.fromhex("0c 20 22 00 04 01 02 13 00 01 00 00")

    items = parse_notification(pt)

    assert len(items) == 1
    assert items[0].key == (2, 0x13)
    assert items[0].value is False


def test_parse_notification_rejects_request_and_truncation() -> None:
    with pytest.raises(MiotProtocolError, match="bad notification header"):
        parse_notification(bytes.fromhex("0c 20 22 00 00 01 02 13 00 01 00 00"))

    with pytest.raises(MiotProtocolError, match="truncated property value"):
        parse_notification(bytes.fromhex("0f 20 22 00 04 01 02 01 00 04 50 01"))


def test_parse_response_accepts_uint16_value() -> None:
    pt = bytes.fromhex("66 20 01 00 03 01 02 08 00 00 00 02 20 2c 01")

    # 0x66 is a different app query response and is not accepted by the
    # regular get-properties parser yet; exercise the shared typed entry
    # layout through a known response opcode instead.
    pt = b"\x1c" + pt[1:]
    items = parse_response(pt)

    assert items[0].value == 300
