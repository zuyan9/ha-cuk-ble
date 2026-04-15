"""MIOT property metadata (reference / spec-only)."""

from .spec import (
    AD1204U_PROPERTIES,
    AD1204U_SAFE_READ_PROPERTIES,
    AD1204U_SAFE_READ_WITH_PROTOCOL_PROPERTIES,
    MiotProperty,
    get_property,
    properties_for_ports,
    validate_safe_read,
)

__all__ = [
    "AD1204U_PROPERTIES",
    "AD1204U_SAFE_READ_PROPERTIES",
    "AD1204U_SAFE_READ_WITH_PROTOCOL_PROPERTIES",
    "MiotProperty",
    "get_property",
    "properties_for_ports",
    "validate_safe_read",
]
