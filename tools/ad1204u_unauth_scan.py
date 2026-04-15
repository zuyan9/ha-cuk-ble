"""Connect to the AD1204U without auth and explore what channels are open.

Goal: the Mi auth channels reject our login (e0 error) because the device
pins login to the binder's BD_ADDR. But the device also exposes a
proprietary CUKTECH service (0000af00) and several MIOT channels that may
stream telemetry unconditionally.

This tool:
  1. Connects
  2. Runs the a4 greeting (harmless)
  3. Subscribes to every notify/indicate characteristic
  4. Tries a handful of "poke" writes to see if anything wakes up
  5. Logs every notification with timestamp for N seconds

Usage:
    sudo .venv/bin/python tools/ad1204u_unauth_scan.py \\
        --address AA:BB:CC:DD:EE:FF --duration 30
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

from bleak import BleakClient, BleakScanner

from cuktech_ble.xiaomi.auth import MiAuthClient


POKE_WRITES = [
    # (uuid, payload, description)
    ("0000af07-0000-1000-8000-00805f9b34fb", b"\x00", "af07 zero byte"),
    ("0000af07-0000-1000-8000-00805f9b34fb", b"\x01", "af07 one byte"),
    ("00000017-0000-1000-8000-00805f9b34fb", b"\x00", "miot17 zero"),
    ("00000018-0000-1000-8000-00805f9b34fb", b"\x00", "miot18 zero"),
    ("0000001a-0000-1000-8000-00805f9b34fb", b"\x00\x00\x00\x00\x01\x00", "miot1a announce"),
]


async def _run(address: str, duration: float) -> int:
    print(f"scanning for {address}...", file=sys.stderr)
    device = await BleakScanner.find_device_by_address(address, timeout=120)
    if device is None:
        print("device not advertising", file=sys.stderr)
        return 1

    print(f"connecting to {address}...", file=sys.stderr)
    async with BleakClient(device, timeout=60) as client:
        # Enumerate all notify/indicate characteristics
        notify_uuids: list[str] = []
        for svc in client.services:
            print(f"service {svc.uuid}", file=sys.stderr)
            for char in svc.characteristics:
                props = ",".join(sorted(char.properties))
                print(f"  char {char.uuid}  [{props}]", file=sys.stderr)
                if {"notify", "indicate"} & set(char.properties):
                    notify_uuids.append(char.uuid)

        def make_handler(uuid: str):
            def _on(_sender, data: bytearray) -> None:
                ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                print(f"{ts} {uuid} [{len(data):3}] {bytes(data).hex()}")
            return _on

        print(f"\nsubscribing to {len(notify_uuids)} characteristics", file=sys.stderr)
        for uuid in notify_uuids:
            try:
                await client.start_notify(
                    uuid, make_handler(uuid), bluez={"use_start_notify": True}
                )
            except Exception as exc:  # noqa: BLE001
                print(f"  start_notify({uuid}) failed: {exc}", file=sys.stderr)

        # Run the a4 greeting via MiAuthClient — harmless, may change device state.
        print("running a4 greeting...", file=sys.stderr)
        auth = MiAuthClient(client, timeout=5, bluez_start_notify=True)
        try:
            await auth.greet()
            print("greeting OK", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001
            print(f"greeting failed (non-fatal): {exc}", file=sys.stderr)

        # Poke various characteristics to see if anything triggers telemetry
        print("\npoking characteristics...", file=sys.stderr)
        for uuid, payload, desc in POKE_WRITES:
            try:
                await client.write_gatt_char(uuid, bytearray(payload), response=False)
                print(f"  poked {desc}: {payload.hex()}", file=sys.stderr)
                await asyncio.sleep(0.3)
            except Exception as exc:  # noqa: BLE001
                print(f"  poke {desc} failed: {exc}", file=sys.stderr)

        print(f"\nlistening for {duration}s...", file=sys.stderr)
        await asyncio.sleep(duration)

        for uuid in notify_uuids:
            try:
                await client.stop_notify(uuid)
            except Exception:  # noqa: BLE001
                pass
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--address", required=True)
    p.add_argument("--duration", type=float, default=30.0)
    args = p.parse_args()
    return asyncio.run(_run(args.address, args.duration))


if __name__ == "__main__":
    sys.exit(main())
