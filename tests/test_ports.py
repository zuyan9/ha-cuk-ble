import pytest

from cuktech_ble.ports import decode_pdo_caps, decode_port_info


def test_decode_port_info_splits_bytes_into_voltage_current_protocol() -> None:
    # b0=01 in-use, b1=0a pd_fixed, b2=32 (5.0 A), b3=c8 (20.0 V) -> 100 W
    info = decode_port_info("c1", 0xC8320A01)

    assert info.port == "c1"
    assert info.raw_uint32_le == 0xC8320A01
    assert info.in_use is True
    assert info.protocol_code == 0x0A
    assert info.protocol_name == "pd_fixed"
    assert info.voltage_v == 20.0
    assert info.current_a == 5.0
    assert info.power_w == 100.0


def test_decode_port_info_idle_port_reports_zero_power() -> None:
    info = decode_port_info("a", 0x00_00_01_00)

    assert info.in_use is False
    assert info.protocol_name == "idle"
    assert info.power_w == 0.0


def test_decode_port_info_rejects_unknown_port_or_out_of_range_value() -> None:
    with pytest.raises(ValueError):
        decode_port_info("c4", 0)
    with pytest.raises(ValueError):
        decode_port_info("c1", -1)
    with pytest.raises(ValueError):
        decode_port_info("c1", 0x1_0000_0000)


def test_decode_pdo_caps_maps_watt_code_byte_to_known_wattage() -> None:
    # low half 0x0064 (100 W), high half 0x003c (60 W)
    caps = decode_pdo_caps(0x003C_0064, high_port="c1", low_port="c2")

    assert caps == {"c2": 100, "c1": 60}


def test_decode_pdo_caps_returns_none_for_zero_byte() -> None:
    # low half 0x0064 (100 W), high half 0x0000 (idle/no contract).
    caps = decode_pdo_caps(0x0000_0064, high_port="c3", low_port="a")

    assert caps == {"a": 100, "c3": None}
