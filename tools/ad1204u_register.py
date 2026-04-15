"""One-shot register: bind a factory-reset AD1204U to this machine.

Usage:
    .venv/bin/python tools/ad1204u_register.py \\
        --address AA:BB:CC:DD:EE:FF \\
        --token-file ~/.cuktech_ble.token

The charger must be unbound from Mi Home (factory reset) and advertising in
pairing mode. After success, the 12-byte token + 16-byte bind_key + DID are
written to the token file as JSON for reuse by the login flow.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from bleak import BleakClient

from cuktech_ble.xiaomi import MiAuthClient


async def _run(address: str, token_file: Path, did: str | None, debug: bool) -> int:
    if debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    print(f"connecting to {address}...", file=sys.stderr)
    async with BleakClient(address, timeout=20) as client:
        print(f"connected; starting register handshake", file=sys.stderr)
        auth = MiAuthClient(client, timeout=15, bluez_start_notify=True)
        async with auth:
            result = await auth.register(did=did)

    payload = {
        "address": address,
        "did": result.did_text,
        "remote_info_hex": result.remote_info.hex(),
        "token_hex": result.token.hex(),
        "bind_key_hex": result.bind_key.hex(),
    }
    token_file.parent.mkdir(parents=True, exist_ok=True)
    token_file.write_text(json.dumps(payload, indent=2))
    os.chmod(token_file, 0o600)
    print(f"register OK — token saved to {token_file}", file=sys.stderr)
    print(json.dumps(payload, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", required=True, help="BLE MAC of the AD1204U")
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path.home() / ".cuktech_ble.token",
        help="Path to write the resulting token (default: ~/.cuktech_ble.token)",
    )
    parser.add_argument(
        "--did",
        default=None,
        help="Optional fallback DID (19 ASCII chars), used if the device "
        "does not advertise one",
    )
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    return asyncio.run(_run(args.address, args.token_file, args.did, args.debug))


if __name__ == "__main__":
    sys.exit(main())
