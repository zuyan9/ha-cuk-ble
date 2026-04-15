"""Live MIOT property read: login, send get_properties, decrypt response.

Usage:
    .venv/bin/python tools/ad1204u_read_props.py --address AA:BB:CC:DD:EE:FF

Request format (reverse-engineered from Mi Home btsnoop):
  header: 33 20 <seq_le2> 02 <count>
  tuples: <siid(1)> <piid_le2>   -- one per property

Response format:
  header: 93 20 <seq_le2> <ok=03> <count>
  entries for each property:
    <siid(1)> <piid_le2> <status_le2> <type(04|01)> <marker> <value(len)>
      type=04 -> marker 0x50, 4-byte LE value (uint32)
      type=01 -> marker 0x10 (uint8) or 0x00 (bool), 1-byte value
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from bleak import BleakClient, BleakScanner

from cuktech_ble.xiaomi import MiAuthClient
from cuktech_ble.xiaomi.session import (
    MIOT_NOTIFY_UUID,
    MIOT_WRITE_UUID,
    MiSession,
)

# The full AD1204U property set Mi Home queries in one shot.
DEFAULT_QUERY: list[tuple[int, int]] = [
    (2, 1), (2, 2), (2, 3), (2, 4),   # port C1/C2/C3/A info (uint32)
    (2, 5), (2, 6), (2, 7),           # scene_mode, screen_save_time, protocol_ctl (u8)
    (2, 0x0f),                        # usb_a_always_on (bool)
    (2, 0x0d),                        # device_language (u8)
    (2, 0x15),                        # protocol_ctl_extend (u32)
    (2, 0x13), (2, 0x14),             # screenoff_while_idle, screen_dir_lock (bool)
    (2, 0x11), (2, 0x12),             # c1c2_protocol, c3a_protocol (u32)
    (2, 0x10),                        # port_ctl (u8)
]


def encode_get_properties(seq: int, tuples: list[tuple[int, int]]) -> bytes:
    body = b"\x33\x20" + seq.to_bytes(2, "little")
    body += bytes([0x02, len(tuples)])
    for siid, piid in tuples:
        body += bytes([siid]) + piid.to_bytes(2, "little")
    return body


def parse_response(pt: bytes) -> tuple[int, int, list[dict]]:
    if len(pt) < 6 or pt[0] != 0x93 or pt[1] != 0x20:
        raise ValueError(f"bad response header: {pt[:6].hex()}")
    seq = int.from_bytes(pt[2:4], "little")
    ok = pt[4]
    count = pt[5]
    i = 6
    items = []
    while i < len(pt):
        siid = pt[i]
        piid = int.from_bytes(pt[i + 1 : i + 3], "little")
        status = int.from_bytes(pt[i + 3 : i + 5], "little")
        type_byte = pt[i + 5]
        marker = pt[i + 6]
        if type_byte == 0x04:
            val = pt[i + 7 : i + 11]
            value = int.from_bytes(val, "little")
            items.append({
                "siid": siid, "piid": piid, "status": status,
                "type": "u32", "marker": marker,
                "value": value, "raw": val.hex(),
            })
            i += 11
        elif type_byte == 0x01:
            val = pt[i + 7 : i + 8]
            items.append({
                "siid": siid, "piid": piid, "status": status,
                "type": "bool" if marker == 0x00 else "u8",
                "marker": marker,
                "value": val[0], "raw": val.hex(),
            })
            i += 8
        else:
            raise ValueError(f"unknown type 0x{type_byte:02x} at offset {i}")
    return seq, ok, items


async def _run(address: str, token_file: Path) -> int:
    token = bytes.fromhex(json.loads(token_file.read_text())["token_hex"])
    print(f"scanning for {address}...", file=sys.stderr)
    device = await BleakScanner.find_device_by_address(address, timeout=120)
    if device is None:
        print(f"device {address} not advertising", file=sys.stderr)
        return 1

    async with BleakClient(device, timeout=60) as client:
        backend = getattr(client, "_backend", None)
        if backend is not None and hasattr(backend, "_acquire_mtu"):
            try:
                await backend._acquire_mtu()
                print(f"MTU: {client.mtu_size}", file=sys.stderr)
            except Exception as exc:  # noqa: BLE001
                print(f"_acquire_mtu failed: {exc}", file=sys.stderr)

        keys = None
        last_exc: Exception | None = None
        for attempt in range(4):
            auth = MiAuthClient(client, timeout=15, bluez_start_notify=True)
            try:
                await auth.subscribe(upnp=False)
                await auth.greet()
                await auth.subscribe_upnp()
                keys = await auth.login(token)
                break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                print(f"login attempt {attempt+1} failed: {exc}", file=sys.stderr)
                await auth.unsubscribe()
                await asyncio.sleep(1.5)
        if keys is None:
            assert last_exc is not None
            raise last_exc
        print("login OK", file=sys.stderr)

        session = MiSession(auth, keys, timeout=10.0)
        await session.subscribe()

        request = encode_get_properties(seq=0x001b, tuples=DEFAULT_QUERY)
        response_pt = await session.send_request(request)

        seq, ok, items = parse_response(response_pt)
        print(f"\nresponse seq=0x{seq:04x} ok=0x{ok:02x} items={len(items)}")
        for item in items:
            key = f"{item['siid']}.{item['piid']}"
            if item["type"] == "u32":
                v = item["value"]
                print(f"  {key:6s} status=0x{item['status']:04x}  u32={v}  (0x{v:08x})  raw={item['raw']}")
            else:
                print(f"  {key:6s} status=0x{item['status']:04x}  {item['type']}={item['value']}  raw={item['raw']}")

        await session.unsubscribe()
        await auth.unsubscribe()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path.home() / ".cuktech_ble.token",
    )
    args = parser.parse_args()
    return asyncio.run(_run(args.address, args.token_file))


if __name__ == "__main__":
    sys.exit(main())
