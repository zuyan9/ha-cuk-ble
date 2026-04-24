"""Decrypt AD1204U MIOT frames from an Android btsnoop HCI log.

The tool reconstructs the Mi BLE login keys from the app/device randoms in
the auth exchange, then decrypts post-login MIOT frames on the AD1204U's
write/notify ATT handles.

Usage:
    .venv/bin/python tools/decrypt_btsnoop_miot.py /tmp/btsnoop.log \
        --mac 3C:CD:73:2B:1B:88 --token 00112233445566778899aabb
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cuktech_ble.xiaomi.crypto import derive_login
from cuktech_ble.xiaomi.session import mible_v1_nonce


DEFAULT_AUTH_HANDLE = 0x0010
DEFAULT_MIOT_WRITE_HANDLE = 0x0019
DEFAULT_MIOT_NOTIFY_HANDLE = 0x001C

CSV_FIELDS = (
    "ts_ms",
    "direction",
    "counter",
    "opcode",
    "seq",
    "action",
    "siid",
    "piid",
    "status",
    "type",
    "marker",
    "value",
    "raw_value",
    "plaintext_hex",
)


@dataclass(frozen=True)
class BtsnoopRecord:
    ts_us: int
    flags: int
    packet_type: int
    payload: bytes


@dataclass(frozen=True)
class AttFrame:
    ts_ms: float
    direction: str  # "tx" or "rx", host-relative
    acl_handle: int
    attr_handle: int
    value: bytes


@dataclass(frozen=True)
class MiotFrame:
    ts_ms: float
    direction: str  # "tx" or "rx", host-relative
    counter: int
    ciphertext: bytes


@dataclass(frozen=True)
class LoginRandoms:
    app_rand: bytes
    dev_rand: bytes


def parse_mac_le(mac: str) -> bytes:
    parts = mac.split(":")
    if len(parts) != 6:
        raise ValueError(f"bad MAC address: {mac!r}")
    return bytes(int(part, 16) for part in reversed(parts))


def parse_handle(value: str) -> int:
    return int(value, 0)


def iter_btsnoop(path: Path) -> Iterator[BtsnoopRecord]:
    with path.open("rb") as f:
        header = f.read(16)
        if len(header) < 16 or header[:8] != b"btsnoop\x00":
            raise ValueError(f"not a btsnoop file: {path}")
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                return
            _, incl_len, flags, _, ts_hi, ts_lo = struct.unpack(">IIIIII", hdr)
            data = f.read(incl_len)
            if len(data) < incl_len:
                return
            if not data:
                continue
            yield BtsnoopRecord(
                ts_us=(ts_hi << 32) | ts_lo,
                flags=flags,
                packet_type=data[0],
                payload=data[1:],
            )


def _parse_acl(payload: bytes) -> tuple[int, int, bytes] | None:
    if len(payload) < 4:
        return None
    handle_flags, acl_len = struct.unpack("<HH", payload[:4])
    handle = handle_flags & 0x0FFF
    pb_flag = (handle_flags >> 12) & 0x3
    data = payload[4 : 4 + acl_len]
    return handle, pb_flag, data


def find_connection_handles(path: Path, mac: str) -> set[int]:
    mac_le = parse_mac_le(mac)
    handles: set[int] = set()
    for rec in iter_btsnoop(path):
        if rec.packet_type != 4 or len(rec.payload) < 2:
            continue
        event_code = rec.payload[0]
        event_len = rec.payload[1]
        event = rec.payload[2 : 2 + event_len]
        if event_code != 0x3E or not event:
            continue
        subevent = event[0]
        if subevent not in (0x01, 0x0A) or len(event) < 19:
            continue
        status = event[1]
        peer_mac = event[6:12]
        if status == 0 and peer_mac == mac_le:
            handles.add(event[2] | (event[3] << 8))
    return handles


def extract_att_frames(path: Path, mac: str) -> list[AttFrame]:
    """Return write/notify ATT value frames for connections to ``mac``."""
    handles = find_connection_handles(path, mac)
    if not handles:
        return []

    frames: list[AttFrame] = []
    l2cap_buffers: dict[int, tuple[int, bytes, int]] = {}
    start_ts: int | None = None

    for rec in iter_btsnoop(path):
        if rec.packet_type != 2:
            continue
        parsed = _parse_acl(rec.payload)
        if parsed is None:
            continue
        acl_handle, pb_flag, data = parsed
        if acl_handle not in handles:
            continue
        if start_ts is None:
            start_ts = rec.ts_us
        direction = "tx" if (rec.flags & 1) == 0 else "rx"

        if pb_flag in (0, 2):
            if len(data) < 4:
                continue
            l2_len, cid = struct.unpack("<HH", data[:4])
            fragment = data[4:]
            if len(fragment) >= l2_len:
                _append_att_frame(
                    frames,
                    rec.ts_us,
                    start_ts,
                    direction,
                    acl_handle,
                    cid,
                    fragment[:l2_len],
                )
            else:
                l2cap_buffers[acl_handle] = (cid, fragment, l2_len)
        elif pb_flag == 1 and acl_handle in l2cap_buffers:
            cid, partial, l2_len = l2cap_buffers[acl_handle]
            partial += data
            if len(partial) >= l2_len:
                _append_att_frame(
                    frames,
                    rec.ts_us,
                    start_ts,
                    direction,
                    acl_handle,
                    cid,
                    partial[:l2_len],
                )
                del l2cap_buffers[acl_handle]
            else:
                l2cap_buffers[acl_handle] = (cid, partial, l2_len)

    return frames


def _append_att_frame(
    frames: list[AttFrame],
    ts_us: int,
    start_ts: int,
    direction: str,
    acl_handle: int,
    cid: int,
    pdu: bytes,
) -> None:
    if cid != 0x0004 or len(pdu) < 3:
        return
    opcode = pdu[0]
    if opcode not in (0x12, 0x1B, 0x1D, 0x52):
        return
    attr_handle = pdu[1] | (pdu[2] << 8)
    frames.append(
        AttFrame(
            ts_ms=(ts_us - start_ts) / 1000.0,
            direction=direction,
            acl_handle=acl_handle,
            attr_handle=attr_handle,
            value=bytes(pdu[3:]),
        )
    )


def extract_login_randoms(
    frames: list[AttFrame],
    *,
    auth_handle: int = DEFAULT_AUTH_HANDLE,
) -> LoginRandoms:
    """Extract the first app/device random pair from the auth channel."""
    app_rand: bytes | None = None
    dev_rand: bytes | None = None
    app_pending: dict[int, bytes] | None = None
    app_expected = 0
    dev_pending: dict[int, bytes] | None = None
    dev_expected = 0

    for frame in frames:
        if frame.attr_handle != auth_handle:
            continue
        value = frame.value

        if frame.direction == "tx":
            if value.startswith(b"\x00\x00\x00\x0b") and len(value) >= 6:
                app_pending = {}
                app_expected = int.from_bytes(value[4:6], "little")
                continue
            if app_pending is not None and len(value) >= 2:
                idx = int.from_bytes(value[:2], "little")
                if 1 <= idx <= app_expected:
                    app_pending[idx] = value[2:]
                if len(app_pending) == app_expected:
                    app_rand = b"".join(
                        app_pending[i] for i in sorted(app_pending)
                    )
                    app_pending = None
                continue

        if frame.direction == "rx":
            # Official inline variant: 00 00 02 <code> <payload>
            if value.startswith(b"\x00\x00\x02\x0d"):
                dev_rand = value[4:]
            # Parcel variant: 00 00 00 <code> <count_le2>, then idx+payload.
            elif value.startswith(b"\x00\x00\x00\x0d") and len(value) >= 6:
                dev_pending = {}
                dev_expected = int.from_bytes(value[4:6], "little")
                continue
            elif dev_pending is not None and len(value) >= 2:
                idx = int.from_bytes(value[:2], "little")
                if 1 <= idx <= dev_expected:
                    dev_pending[idx] = value[2:]
                if len(dev_pending) == dev_expected:
                    dev_rand = b"".join(
                        dev_pending[i] for i in sorted(dev_pending)
                    )
                    dev_pending = None

        if app_rand is not None and dev_rand is not None:
            break

    if app_rand is None:
        raise ValueError("could not find app random on auth channel")
    if dev_rand is None:
        raise ValueError("could not find device random on auth channel")
    if len(app_rand) != 16 or len(dev_rand) != 16:
        raise ValueError(
            f"login randoms must be 16 bytes, got app={len(app_rand)} dev={len(dev_rand)}"
        )
    return LoginRandoms(app_rand=app_rand, dev_rand=dev_rand)


def extract_miot_frames(
    frames: list[AttFrame],
    *,
    write_handle: int = DEFAULT_MIOT_WRITE_HANDLE,
    notify_handle: int = DEFAULT_MIOT_NOTIFY_HANDLE,
) -> list[MiotFrame]:
    out: list[MiotFrame] = []
    pending: dict[str, Any] | None = None

    for frame in frames:
        value = frame.value
        if frame.attr_handle not in (write_handle, notify_handle):
            continue

        if frame.attr_handle == write_handle and frame.direction == "tx":
            if value.startswith(b"\x00\x00\x00\x00") and len(value) >= 6:
                pending = {
                    "direction": "tx",
                    "expected": int.from_bytes(value[4:6], "little"),
                    "parts": {},
                    "counter": None,
                    "ts_ms": frame.ts_ms,
                }
                continue
            if pending is not None and pending["direction"] == "tx":
                _collect_miot_part(pending, value)
                _flush_if_complete(out, pending)
                if len(pending["parts"]) == pending["expected"]:
                    pending = None
                continue

        if frame.attr_handle == notify_handle and frame.direction == "rx":
            if value.startswith(b"\x00\x00\x02\x00") and len(value) >= 6:
                out.append(
                    MiotFrame(
                        ts_ms=frame.ts_ms,
                        direction="rx",
                        counter=int.from_bytes(value[4:6], "little"),
                        ciphertext=value[6:],
                    )
                )
                continue
            if value.startswith(b"\x00\x00\x00\x00") and len(value) >= 6:
                pending = {
                    "direction": "rx",
                    "expected": int.from_bytes(value[4:6], "little"),
                    "parts": {},
                    "counter": None,
                    "ts_ms": frame.ts_ms,
                }
                continue
            if pending is not None and pending["direction"] == "rx":
                _collect_miot_part(pending, value)
                _flush_if_complete(out, pending)
                if len(pending["parts"]) == pending["expected"]:
                    pending = None

    return out


def _collect_miot_part(pending: dict[str, Any], value: bytes) -> None:
    if len(value) < 2:
        return
    idx = int.from_bytes(value[:2], "little")
    if idx < 1 or idx > pending["expected"]:
        return
    if idx == 1:
        if len(value) < 4:
            return
        pending["counter"] = int.from_bytes(value[2:4], "little")
        pending["parts"][idx] = value[4:]
    else:
        pending["parts"][idx] = value[2:]


def _flush_if_complete(out: list[MiotFrame], pending: dict[str, Any]) -> None:
    if len(pending["parts"]) != pending["expected"]:
        return
    counter = pending["counter"]
    if counter is None:
        return
    out.append(
        MiotFrame(
            ts_ms=pending["ts_ms"],
            direction=pending["direction"],
            counter=counter,
            ciphertext=b"".join(pending["parts"][i] for i in sorted(pending["parts"])),
        )
    )


def decrypt_miot_frame(frame: MiotFrame, token: bytes, randoms: LoginRandoms) -> bytes:
    keys = derive_login(token, randoms.app_rand, randoms.dev_rand)
    if frame.direction == "tx":
        key = keys.app_key
        iv = keys.app_iv
    else:
        key = keys.dev_key
        iv = keys.dev_iv
    nonce = mible_v1_nonce(iv, frame.counter)
    return AESCCM(key, tag_length=4).decrypt(nonce, frame.ciphertext, None)


def decode_miot_plaintext(frame: MiotFrame, plaintext: bytes) -> list[dict[str, Any]]:
    base: dict[str, Any] = {
        "ts_ms": f"{frame.ts_ms:.2f}",
        "direction": frame.direction,
        "counter": frame.counter,
        "opcode": plaintext[:2].hex() if len(plaintext) >= 2 else plaintext.hex(),
        "seq": int.from_bytes(plaintext[2:4], "little") if len(plaintext) >= 4 else "",
        "plaintext_hex": plaintext.hex(" "),
    }
    if len(plaintext) < 6 or plaintext[1:2] != b"\x20":
        return [_row(base, action="unknown")]

    opcode = plaintext[:2]
    if opcode == b"\x33\x20":
        return _decode_get_request(base, plaintext)
    if opcode in (b"\x93\x20", b"\x1c\x20", b"\x0e\x20"):
        return _decode_property_values(base, plaintext, action="get_response")
    if opcode == b"\x0c\x20":
        return _decode_property_values(base, plaintext, action="set_request", statusless=True)
    if opcode == b"\x0b\x20":
        return _decode_set_response(base, plaintext)
    if opcode == b"\x0f\x20":
        return _decode_property_values(base, plaintext, action="notify", statusless=True)
    return [_row(base, action="unknown")]


def _decode_get_request(base: dict[str, Any], plaintext: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    count = plaintext[5]
    offset = 6
    for _ in range(count):
        if offset + 3 > len(plaintext):
            break
        siid = plaintext[offset]
        piid = int.from_bytes(plaintext[offset + 1 : offset + 3], "little")
        rows.append(_row(base, action="get_request", siid=siid, piid=piid))
        offset += 3
    return rows or [_row(base, action="get_request")]


def _decode_property_values(
    base: dict[str, Any],
    plaintext: bytes,
    *,
    action: str,
    statusless: bool = False,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    count = plaintext[5]
    offset = 6
    for _ in range(count):
        if offset + 5 > len(plaintext):
            break
        siid = plaintext[offset]
        piid = int.from_bytes(plaintext[offset + 1 : offset + 3], "little")
        status: int | str = ""
        if statusless:
            type_offset = offset + 3
        else:
            status = int.from_bytes(plaintext[offset + 3 : offset + 5], "little")
            type_offset = offset + 5
        if type_offset + 2 > len(plaintext):
            break
        type_byte = plaintext[type_offset]
        marker = plaintext[type_offset + 1]
        value_offset = type_offset + 2
        value, raw_value, next_offset = _decode_value(plaintext, value_offset, type_byte, marker)
        rows.append(
            _row(
                base,
                action=action,
                siid=siid,
                piid=piid,
                status=status,
                type_byte=type_byte,
                marker=marker,
                value=value,
                raw_value=raw_value,
            )
        )
        offset = next_offset
    return rows or [_row(base, action=action)]


def _decode_set_response(base: dict[str, Any], plaintext: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    count = plaintext[5]
    offset = 6
    for _ in range(count):
        if offset + 5 > len(plaintext):
            break
        siid = plaintext[offset]
        piid = int.from_bytes(plaintext[offset + 1 : offset + 3], "little")
        status = int.from_bytes(plaintext[offset + 3 : offset + 5], "little")
        rows.append(
            _row(base, action="set_response", siid=siid, piid=piid, status=status)
        )
        offset += 5
    return rows or [_row(base, action="set_response")]


def _decode_value(
    plaintext: bytes, offset: int, type_byte: int, marker: int
) -> tuple[int | bool | str, str, int]:
    if type_byte == 0x04:
        raw = plaintext[offset : offset + 4]
        return int.from_bytes(raw, "little"), raw.hex(), offset + 4
    if type_byte == 0x01:
        raw = plaintext[offset : offset + 1]
        if not raw:
            return "", "", offset
        value: int | bool = bool(raw[0]) if marker == 0x00 else raw[0]
        return value, raw.hex(), offset + 1
    raw = plaintext[offset:]
    return raw.hex(), raw.hex(), len(plaintext)


def _row(base: dict[str, Any], **values: Any) -> dict[str, Any]:
    row = {field: "" for field in CSV_FIELDS}
    row.update(base)
    row.update(values)
    if isinstance(row.get("piid"), int):
        row["piid"] = f"0x{row['piid']:04x}"
    if isinstance(row.get("status"), int):
        row["status"] = f"0x{row['status']:04x}"
    if isinstance(row.get("type_byte"), int):
        row["type"] = f"0x{row.pop('type_byte'):02x}"
    if isinstance(row.get("marker"), int):
        row["marker"] = f"0x{row['marker']:02x}"
    return row


def load_token(token_hex: str | None, token_file: Path | None) -> bytes:
    if token_hex:
        raw = token_hex.strip().replace(" ", "")
    else:
        path = token_file or Path.home() / ".cuktech_ble.token"
        data = json.loads(path.read_text())
        raw = str(data["token_hex"]).strip().replace(" ", "")
    token = bytes.fromhex(raw)
    if len(token) != 12:
        raise ValueError(f"token must be 12 bytes, got {len(token)}")
    return token


def decrypt_log(
    path: Path,
    *,
    mac: str,
    token: bytes,
    auth_handle: int = DEFAULT_AUTH_HANDLE,
    write_handle: int = DEFAULT_MIOT_WRITE_HANDLE,
    notify_handle: int = DEFAULT_MIOT_NOTIFY_HANDLE,
) -> list[dict[str, Any]]:
    att_frames = extract_att_frames(path, mac)
    if not att_frames:
        raise ValueError(f"no ATT frames found for {mac}")
    randoms = extract_login_randoms(att_frames, auth_handle=auth_handle)
    miot_frames = extract_miot_frames(
        att_frames,
        write_handle=write_handle,
        notify_handle=notify_handle,
    )
    rows: list[dict[str, Any]] = []
    failures = 0
    for frame in miot_frames:
        try:
            plaintext = decrypt_miot_frame(frame, token, randoms)
        except Exception:
            failures += 1
            continue
        rows.extend(decode_miot_plaintext(frame, plaintext))
    if not rows and failures:
        raise ValueError(f"{failures} MIOT frames found, but none decrypted")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="Android btsnoop_hci.log path")
    parser.add_argument("--mac", required=True, help="charger BLE MAC")
    parser.add_argument("--token", help="12-byte BLE token as 24 hex characters")
    parser.add_argument(
        "--token-file",
        type=Path,
        help="JSON token file with token_hex; defaults to ~/.cuktech_ble.token",
    )
    parser.add_argument("--auth-handle", type=parse_handle, default=DEFAULT_AUTH_HANDLE)
    parser.add_argument(
        "--miot-write-handle", type=parse_handle, default=DEFAULT_MIOT_WRITE_HANDLE
    )
    parser.add_argument(
        "--miot-notify-handle", type=parse_handle, default=DEFAULT_MIOT_NOTIFY_HANDLE
    )
    args = parser.parse_args()

    try:
        token = load_token(args.token, args.token_file)
        rows = decrypt_log(
            args.log,
            mac=args.mac,
            token=token,
            auth_handle=args.auth_handle,
            write_handle=args.miot_write_handle,
            notify_handle=args.miot_notify_handle,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    writer = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
    writer.writeheader()
    writer.writerows(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
