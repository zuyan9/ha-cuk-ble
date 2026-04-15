"""Checked-in AD1204U MIOT property metadata and safety allowlists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

PortName = Literal["c1", "c2", "c3", "a"]


@dataclass(frozen=True)
class MiotProperty:
    siid: int
    piid: int
    prop: str
    description: str
    fmt: str
    gatt_access: tuple[str, ...]
    port: PortName | None = None
    category: str = "diagnostic"

    @property
    def key(self) -> str:
        return f"{self.siid}.{self.piid}"

    @property
    def readable(self) -> bool:
        return "read" in self.gatt_access

    @property
    def writable(self) -> bool:
        return "write" in self.gatt_access

    @property
    def safe_read(self) -> bool:
        return self.key in AD1204U_SAFE_READ_WITH_PROTOCOL_PROPERTIES

    def to_dict(self) -> dict[str, object]:
        return {
            "siid": self.siid,
            "piid": self.piid,
            "key": self.key,
            "prop": self.prop,
            "description": self.description,
            "format": self.fmt,
            "gatt_access": list(self.gatt_access),
            "port": self.port,
            "category": self.category,
            "safe_read": self.safe_read,
        }


AD1204U_PROPERTIES: dict[str, MiotProperty] = {
    "2.1": MiotProperty(
        2,
        1,
        "port_c_one_info",
        "Port C1 info",
        "uint32",
        ("read", "notify"),
        port="c1",
        category="metric",
    ),
    "2.2": MiotProperty(
        2,
        2,
        "port_c_two_info",
        "Port C2 info",
        "uint32",
        ("read", "notify"),
        port="c2",
        category="metric",
    ),
    "2.3": MiotProperty(
        2,
        3,
        "port_c_three_info",
        "Port C3 info",
        "uint32",
        ("read", "notify"),
        port="c3",
        category="metric",
    ),
    "2.4": MiotProperty(
        2,
        4,
        "port_a_info",
        "Port USB-A info",
        "uint32",
        ("read", "notify"),
        port="a",
        category="metric",
    ),
    "2.5": MiotProperty(
        2, 5, "scene_mode", "Scene Mode", "uint8", ("read", "write", "notify")
    ),
    "2.6": MiotProperty(
        2, 6, "screen_save_time", "ScreenOn Time", "uint8", ("read", "write", "notify")
    ),
    "2.7": MiotProperty(
        2, 7, "protocol_ctl", "Protocol control", "uint8", ("read", "write", "notify")
    ),
    "2.8": MiotProperty(
        2, 8, "count_down_setting", "Port Close", "uint8", ("read", "write", "notify")
    ),
    "2.9": MiotProperty(
        2,
        9,
        "c_one_countdown_time",
        "C1 Close",
        "uint16",
        ("read", "write", "notify"),
    ),
    "2.10": MiotProperty(
        2,
        10,
        "c_two_countdown_time",
        "C2 Close",
        "uint16",
        ("read", "write", "notify"),
    ),
    "2.11": MiotProperty(
        2,
        11,
        "c_three_down_time",
        "C3 Close",
        "uint16",
        ("read", "write", "notify"),
    ),
    "2.12": MiotProperty(
        2,
        12,
        "usb_a_countdown_time",
        "USB-A Close",
        "uint16",
        ("read", "write", "notify"),
    ),
    "2.13": MiotProperty(
        2,
        13,
        "device_language",
        "Device Language",
        "uint8",
        ("read", "write", "notify"),
    ),
    "2.14": MiotProperty(
        2, 14, "enter", "Enter App", "uint8", ("write",), category="enter"
    ),
    "2.15": MiotProperty(
        2,
        15,
        "usb_a_always_on",
        "USB-A Always-on",
        "bool",
        ("read", "write", "notify"),
    ),
    "2.16": MiotProperty(
        2, 16, "port_ctl", "Port control", "uint8", ("read", "write", "notify")
    ),
    "2.17": MiotProperty(
        2,
        17,
        "c_one_c_two_protocol",
        "C1/C2 Protocol",
        "uint32",
        ("read", "notify"),
        category="protocol",
    ),
    "2.18": MiotProperty(
        2,
        18,
        "c_three_a_protocol",
        "C3/A Protocol",
        "uint32",
        ("read", "notify"),
        category="protocol",
    ),
    "2.19": MiotProperty(
        2,
        19,
        "screenoff_while_idle",
        "screenOffIdle",
        "bool",
        ("write", "read", "notify"),
    ),
    "2.20": MiotProperty(
        2,
        20,
        "screen_dir_lock",
        "screenDirLock",
        "bool",
        ("read", "write", "notify"),
    ),
    "2.21": MiotProperty(
        2,
        21,
        "protocol_ctl_extend",
        "ExtPtl",
        "uint32",
        ("read", "write", "notify"),
    ),
}

AD1204U_SAFE_READ_PROPERTIES = frozenset({"2.1", "2.2", "2.3", "2.4"})
AD1204U_SAFE_READ_WITH_PROTOCOL_PROPERTIES = frozenset(
    {*AD1204U_SAFE_READ_PROPERTIES, "2.17", "2.18"}
)
AD1204U_ENTER_PROPERTY_KEY = "2.14"


def get_property(key: str) -> MiotProperty:
    try:
        return AD1204U_PROPERTIES[key]
    except KeyError as exc:
        raise ValueError(f"unknown AD1204U MIOT property: {key}") from exc


def validate_safe_read(prop: MiotProperty) -> None:
    if not prop.readable:
        raise ValueError(f"{prop.key} {prop.prop} is not readable")
    if not prop.safe_read:
        raise ValueError(f"{prop.key} {prop.prop} is not in the safe read allowlist")


def properties_for_ports(
    ports: list[str] | tuple[str, ...] | str,
    *,
    include_protocol: bool = False,
) -> list[MiotProperty]:
    if isinstance(ports, str):
        port_values = ["c1", "c2", "c3", "a"] if ports == "all" else ports.split(",")
    else:
        port_values = list(ports)

    by_port = {
        prop.port: prop
        for prop in AD1204U_PROPERTIES.values()
        if prop.port is not None
    }
    result: list[MiotProperty] = []
    for port in port_values:
        normalized = port.strip().lower()
        if not normalized:
            continue
        if normalized not in by_port:
            raise ValueError(f"unsupported port {port!r}; use c1,c2,c3,a, or all")
        prop = by_port[normalized]
        validate_safe_read(prop)
        result.append(prop)

    if include_protocol:
        result.extend([get_property("2.17"), get_property("2.18")])

    return result
