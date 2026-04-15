import pytest

from cuktech_ble.miot.spec import (
    AD1204U_SAFE_READ_PROPERTIES,
    get_property,
    properties_for_ports,
    validate_safe_read,
)


def test_default_port_properties_are_safe_read_only_targets() -> None:
    props = properties_for_ports("all")

    assert [prop.key for prop in props] == ["2.1", "2.2", "2.3", "2.4"]
    assert {prop.key for prop in props} == set(AD1204U_SAFE_READ_PROPERTIES)
    assert all(prop.readable for prop in props)
    assert all(not prop.writable for prop in props)


def test_include_protocol_adds_only_read_only_protocol_properties() -> None:
    props = properties_for_ports("c1", include_protocol=True)

    assert [prop.key for prop in props] == ["2.1", "2.17", "2.18"]
    assert all(prop.readable for prop in props)
    assert all(prop.safe_read for prop in props)


def test_control_and_settings_properties_are_rejected_by_allowlist() -> None:
    for key in ("2.5", "2.8", "2.14", "2.16"):
        with pytest.raises(ValueError):
            validate_safe_read(get_property(key))


def test_unknown_or_invalid_ports_are_rejected() -> None:
    with pytest.raises(ValueError):
        properties_for_ports("c4")
