"""Passively capture FE95 advertisement payloads from the AD1204U.

Usage:
    sudo .venv/bin/python tools/ad1204u_adv_sniff.py \\
        --address AA:BB:CC:DD:EE:FF --duration 30

Prints each raw FE95 service-data blob seen from the target MAC so we can
see whether the charger broadcasts encrypted telemetry we could decode with
the beaconkey.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timezone

from bleak import BleakScanner

FE95_UUID = "0000fe95-0000-1000-8000-00805f9b34fb"


async def _run(address: str, duration: float) -> int:
    address = address.upper()
    seen: set[bytes] = set()

    def _cb(device, adv) -> None:
        if device.address.upper() != address:
            return
        blob = adv.service_data.get(FE95_UUID)
        if blob is None:
            return
        blob = bytes(blob)
        ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        marker = "NEW" if blob not in seen else "   "
        seen.add(blob)
        print(f"{ts} {marker} rssi={adv.rssi:>4} fe95[{len(blob)}]={blob.hex()}")

    print(f"listening for {duration}s for {address}...", file=sys.stderr)
    async with BleakScanner(detection_callback=_cb):
        await asyncio.sleep(duration)
    print(f"captured {len(seen)} unique payloads", file=sys.stderr)
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--address", required=True)
    p.add_argument("--duration", type=float, default=30.0)
    args = p.parse_args()
    return asyncio.run(_run(args.address, args.duration))


if __name__ == "__main__":
    sys.exit(main())
