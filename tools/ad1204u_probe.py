"""Log in to a bound AD1204U and capture post-auth traffic.

This connects with a stored token, runs the Mi BLE login handshake, then
subscribes to every GATT characteristic that supports notify/indicate and
logs everything it sees for the specified duration. Used to reverse-engineer
the MIOT encrypted framing on the charger.

Usage:
    .venv/bin/python tools/ad1204u_probe.py \\
        --address AA:BB:CC:DD:EE:FF \\
        --token-file ~/.cuktech_ble.token \\
        --duration 30
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from bleak import BleakClient, BleakScanner

from cuktech_ble.xiaomi import MiAuthClient
from cuktech_ble.xiaomi.protocol import AVDTP_UUID, UPNP_UUID


def _load_token(path: Path) -> bytes:
    data = json.loads(path.read_text())
    return bytes.fromhex(data["token_hex"])


async def _run(address: str, token_file: Path, duration: float, debug: bool) -> int:
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO)

    token = _load_token(token_file)

    print(f"scanning for {address}...", file=sys.stderr)
    device = await BleakScanner.find_device_by_address(address, timeout=120)
    if device is None:
        print(f"device {address} not advertising; aborting", file=sys.stderr)
        return 1

    print(f"connecting to {address}...", file=sys.stderr)
    async with BleakClient(device, timeout=60) as client:
        auth = MiAuthClient(client, timeout=15, bluez_start_notify=True)
        # Match Mi Home's subscribe order: AVDTP → greet → UPNP → login.
        await auth.subscribe(upnp=False)
        try:
            await auth.greet()
            await auth.subscribe_upnp()
            keys = await auth.login(token)
            print("login OK — session keys:", file=sys.stderr)
            print(
                json.dumps(
                    {
                        "dev_key_hex": keys.dev_key.hex(),
                        "app_key_hex": keys.app_key.hex(),
                        "dev_iv_hex": keys.dev_iv.hex(),
                        "app_iv_hex": keys.app_iv.hex(),
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
        finally:
            await auth.unsubscribe()

        notify_uuids: list[str] = []
        for svc in client.services:
            for char in svc.characteristics:
                props = set(char.properties)
                if props & {"notify", "indicate"}:
                    notify_uuids.append(char.uuid)

        # Deduplicate while preserving order
        seen: set[str] = set()
        notify_uuids = [u for u in notify_uuids if not (u in seen or seen.add(u))]
        # Skip the UPNP/AVDTP auth channels — we already consumed their data
        notify_uuids = [u for u in notify_uuids if u not in (UPNP_UUID, AVDTP_UUID)]

        print(f"subscribing to {len(notify_uuids)} characteristics:", file=sys.stderr)
        for u in notify_uuids:
            print(f"  - {u}", file=sys.stderr)

        def make_handler(uuid: str):
            def _on(_sender, data: bytearray) -> None:
                ts = datetime.now(timezone.utc).isoformat()
                print(f"{ts} {uuid} {bytes(data).hex()}")
            return _on

        for uuid in notify_uuids:
            try:
                await client.start_notify(uuid, make_handler(uuid))
            except Exception as exc:  # noqa: BLE001
                print(f"start_notify({uuid}) failed: {exc}", file=sys.stderr)

        print(f"listening for {duration}s...", file=sys.stderr)
        await asyncio.sleep(duration)

        for uuid in notify_uuids:
            try:
                await client.stop_notify(uuid)
            except Exception:  # noqa: BLE001
                pass

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True)
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path.home() / ".cuktech_ble.token",
    )
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    return asyncio.run(
        _run(args.address, args.token_file, args.duration, args.debug)
    )


if __name__ == "__main__":
    sys.exit(main())
