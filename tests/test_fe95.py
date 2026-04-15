from cuktech_ble.fe95 import parse_fe95
from cuktech_ble.util import parse_hex


def test_parse_observed_ad1204u_fe95_frame() -> None:
    frame = parse_fe95(parse_hex("10 59 0e 66 00 ff ee dd cc bb aa"))

    assert frame.frame_control == 0x5910
    assert frame.product_id == 0x660E
    assert frame.product_id_hex == "0x660e"
    assert frame.frame_counter == 0
    assert frame.mac_address == "AA:BB:CC:DD:EE:FF"
    assert frame.payload == b""
    assert frame.raw_hex == "10 59 0e 66 00 ff ee dd cc bb aa"


def test_parse_fe95_preserves_unknown_payload_bytes() -> None:
    frame = parse_fe95(
        parse_hex("10 59 0e 66 07 88 1b 2b 73 cd 3c aa bb cc")
    )

    assert frame.frame_counter == 7
    assert frame.payload_hex == "aa bb cc"
    assert frame.to_dict()["payload_hex"] == "aa bb cc"
    assert frame.to_dict()["payload_length"] == 3


def test_parse_hex_accepts_common_separators() -> None:
    assert parse_hex("0x10:59-0e 66") == b"\x10\x59\x0e\x66"
