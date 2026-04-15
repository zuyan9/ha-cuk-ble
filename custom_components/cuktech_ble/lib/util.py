"""Small byte and JSON helpers."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any


def bytes_to_hex(data: bytes | bytearray | memoryview | None) -> str:
    """Render bytes as lowercase, space-separated hex."""
    if data is None:
        return ""
    return " ".join(f"{byte:02x}" for byte in bytes(data))


def parse_hex(value: str) -> bytes:
    """Parse hex with optional whitespace, colons, dashes, or 0x prefixes."""
    cleaned = (
        value.lower()
        .replace("0x", "")
        .replace(":", "")
        .replace("-", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\t", "")
    )
    if len(cleaned) % 2:
        raise ValueError("hex input must contain an even number of digits")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"invalid hex input: {value!r}") from exc


def normalize_uuid(uuid: str) -> str:
    """Normalize a UUID string for case-insensitive comparisons."""
    return uuid.lower()


def json_default(value: Any) -> Any:
    """JSON serializer for dataclasses, datetimes, bytes, and simple objects."""
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes_to_hex(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise TypeError(f"{type(value).__name__} is not JSON serializable")


def dumps_json(value: Any, *, pretty: bool = True) -> str:
    """Dump JSON with stable formatting."""
    if pretty:
        return json.dumps(value, default=json_default, indent=2, sort_keys=True)
    return json.dumps(value, default=json_default, separators=(",", ":"), sort_keys=True)


def compact_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    """Drop keys whose values are None while keeping falsey data like 0 or ''."""
    return {key: item for key, item in value.items() if item is not None}


def first_present(values: Sequence[Any]) -> Any | None:
    """Return the first non-None value from a sequence."""
    for value in values:
        if value is not None:
            return value
    return None
