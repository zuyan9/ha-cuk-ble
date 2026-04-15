"""Probe the register DID-upload step with alternate announcement codes.

We've confirmed pub_key exchange works cleanly but the device goes silent
when we announce CMD_SEND_DID as `00 00 00 00 02 00`. Try variants to see
if any elicit a response.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from bleak import BleakClient, BleakScanner

from cuktech_ble.xiaomi import crypto
from cuktech_ble.xiaomi.auth import MiAuthClient
from cuktech_ble.xiaomi.protocol import (
    AVDTP_UUID,
    CMD_GET_INFO,
    CMD_SET_KEY,
    CMD_SEND_DATA,
    UPNP_UUID,
)

CANDIDATES = [
    bytes.fromhex("00 00 00 00 02 00"),  # miauth spec (what we use)
    bytes.fromhex("00 00 00 01 02 00"),
    bytes.fromhex("00 00 00 02 02 00"),
    bytes.fromhex("00 00 00 04 02 00"),
    bytes.fromhex("00 00 00 05 02 00"),
    bytes.fromhex("00 00 00 09 02 00"),
    bytes.fromhex("00 00 00 0f 02 00"),
]


async def _try_one(address: str, announcement: bytes) -> bool:
    print(f"\n=== announcement {announcement.hex()} ===", file=sys.stderr)
    device = await BleakScanner.find_device_by_address(address, timeout=120)
    if device is None:
        print("not advertising", file=sys.stderr)
        return False

    async with BleakClient(device, timeout=30) as client:
        auth = MiAuthClient(client, timeout=8, bluez_start_notify=True)
        async with auth:
            # Exchange pub_keys so the device is in the same state as a real register
            await auth._write(UPNP_UUID, CMD_GET_INFO)
            ann = await auth._recv(auth._avdtp)
            await auth._recv_parcel(ann)

            priv, pub = crypto.generate_keypair()
            pub_bytes = crypto.public_key_to_bytes(pub)
            await auth._write(UPNP_UUID, CMD_SET_KEY)
            await auth._send_parcel(AVDTP_UUID, CMD_SEND_DATA, pub_bytes)
            peer_ann = await auth._recv(auth._avdtp)
            await auth._recv_parcel(peer_ann)

            # Try the candidate announcement, see if device responds
            print(f"sending {announcement.hex()}", file=sys.stderr)
            await auth._write(AVDTP_UUID, announcement)
            try:
                resp = await asyncio.wait_for(auth._avdtp.queue.get(), 4)
                print(f"  RESP: {bytes(resp).hex()}", file=sys.stderr)
                return True
            except asyncio.TimeoutError:
                print("  silent", file=sys.stderr)
                return False


async def _run(address: str) -> int:
    for ann in CANDIDATES:
        try:
            await _try_one(address, ann)
        except Exception as exc:  # noqa: BLE001
            print(f"  error: {exc}", file=sys.stderr)
        await asyncio.sleep(1)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--address", required=True)
    args = p.parse_args()
    return asyncio.run(_run(args.address))


if __name__ == "__main__":
    sys.exit(main())
