"""Sweep logger: keep BLE + KM003C open, sample both at a fixed interval.

Usage:
    .venv/bin/python tools/sweep_logger.py \\
        --address AA:BB:CC:DD:EE:FF --port c1 --interval 2.0

Each interval, prints one line:
    [HH:MM:SS] c1 raw=01 03 18 c8 in_use=1 V=20.0 A=2.4 W=48.0 b1=0x03 cap=45W |
               km003c V=20.012 I=2.389 cc1/cc2=0.0008/1.6330

Ctrl-C to stop.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

import usb.core
import usb.util
import usbpdpy
from bleak import BleakClient, BleakScanner

from cuktech_ble.ports import (
    PIID_TO_PORT,
    PORTS,
    PORT_PROPERTY_PIID,
    decode_port_info,
)
from cuktech_ble.xiaomi import MiAuthClient
from cuktech_ble.xiaomi.session import MiSession


KM003C_VID = 0x5FC9
KM003C_PID = 0x0063


class Km003c:
    def __init__(self) -> None:
        self.dev = usb.core.find(idVendor=KM003C_VID, idProduct=KM003C_PID)
        if self.dev is None:
            raise RuntimeError("KM003C not found (USB VID:PID 5fc9:0063)")
        try:
            if self.dev.is_kernel_driver_active(0):
                self.dev.detach_kernel_driver(0)
        except Exception:
            pass
        usb.util.claim_interface(self.dev, 0)
        self._tid = 0
        self._last_src_cap_pdos: list[dict] | None = None
        self._last_contract: str | None = None

    def close(self) -> None:
        try:
            usb.util.release_interface(self.dev, 0)
        except Exception:
            pass

    def _request(self, attr_val: int) -> bytes:
        # attribute field occupies bits 17:31 of the 32-bit control header, so the
        # request byte[2] = (attr << 1) & 0xFF, byte[3] = (attr >> 7) & 0xFF.
        self._tid = (self._tid + 1) & 0xFF
        b2 = (attr_val << 1) & 0xFF
        b3 = (attr_val >> 7) & 0xFF
        req = bytes([0x0C, self._tid, b2, b3])
        self.dev.write(0x01, req, timeout=500)
        return bytes(self.dev.read(0x81, 4096, timeout=500))

    def read_adc(self) -> dict:
        pkt = self._request(0x0001)
        vbus_uV, ibus_uA = struct.unpack_from("<ii", pkt, 8)
        cc1, cc2 = struct.unpack_from("<HH", pkt, 8 + 26)
        return {
            "v": vbus_uV / 1e6,
            "i": ibus_uA / 1e6,
            "cc1": cc1 / 10000,
            "cc2": cc2 / 10000,
        }

    def read_pd_events(self) -> list[str]:
        """Poll PD event buffer, parse wrapped messages, update _last_contract.

        Returns a list of human-readable event labels added since last poll.
        """
        pkt = self._request(0x0010)
        if len(pkt) < 8:
            return []
        # 4-byte main hdr, 4-byte ext hdr, then the PD payload.
        # Payload begins with a 12-byte preamble (PD-only form) and then events.
        payload = pkt[8:]
        if len(payload) < 12:
            return []
        i = 12
        events: list[str] = []
        while i < len(payload):
            marker = payload[i]
            if marker == 0x45:
                if i + 6 > len(payload):
                    break
                code = payload[i + 5]
                if code == 0x21:
                    events.append("connect")
                elif code == 0x22:
                    events.append("disconnect")
                else:
                    events.append(f"status 0x{code:02x}")
                i += 6
                continue
            if 0x80 <= marker <= 0x9F:
                wire_len = (marker & 0x3F) - 5
                if wire_len <= 0 or i + 6 + wire_len > len(payload):
                    break
                wire = payload[i + 6 : i + 6 + wire_len]
                try:
                    msg = usbpdpy.parse_pd_message(wire)
                except Exception:
                    i += 6 + wire_len
                    continue
                mtype = msg.header.message_type if msg.header else "?"
                if mtype == "Source_Capabilities" and msg.data_objects:
                    pdos: list[dict] = []
                    for idx, d in enumerate(msg.data_objects, start=1):
                        pdos.append({
                            "pos": idx,
                            "type": d.pdo_type,
                            "v": d.voltage_v,
                            "min_v": d.min_voltage_v,
                            "max_v": d.max_voltage_v,
                            "max_a": d.max_current_a,
                        })
                    self._last_src_cap_pdos = pdos
                    events.append(f"SrcCap[{len(pdos)}]")
                elif mtype == "Request" and msg.request_objects:
                    rdo = msg.request_objects[0]
                    pos = getattr(rdo, "object_position", None)
                    is_pps = getattr(rdo, "is_pps", False) or (
                        pos
                        and self._last_src_cap_pdos
                        and pos <= len(self._last_src_cap_pdos)
                        and self._last_src_cap_pdos[pos - 1]["type"] != "FixedSupply"
                    )
                    op_v = getattr(rdo, "operating_voltage_mv", None)
                    op_i = getattr(rdo, "operating_current_a", None)
                    if op_i is None:
                        op_i_ma = getattr(rdo, "operating_current_ma", None)
                        op_i = (op_i_ma / 1000) if op_i_ma else None
                    pdo = None
                    if pos and self._last_src_cap_pdos and pos <= len(self._last_src_cap_pdos):
                        pdo = self._last_src_cap_pdos[pos - 1]
                    if is_pps and pdo:
                        v_desc = f"{(op_v / 1000) if op_v else pdo['min_v']}V (PPS {pdo['min_v']}-{pdo['max_v']}V)"
                    elif pdo:
                        v_desc = f"{pdo['v']}V Fixed"
                    else:
                        v_desc = "?V"
                    a_desc = f"{op_i:.1f}A" if op_i else "?A"
                    self._last_contract = f"{v_desc} @ {a_desc} (pos={pos})"
                    events.append(f"Req→ {self._last_contract}")
                elif mtype == "Accept":
                    events.append("Accept")
                elif mtype == "PS_RDY":
                    events.append("PS_RDY")
                i += 6 + wire_len
                continue
            # Unknown marker — stop parsing.
            break
        return events

    @property
    def last_contract(self) -> str | None:
        return self._last_contract


def encode_get_properties(seq: int, tuples: list[tuple[int, int]]) -> bytes:
    body = b"\x33\x20" + seq.to_bytes(2, "little")
    body += bytes([0x02, len(tuples)])
    for siid, piid in tuples:
        body += bytes([siid]) + piid.to_bytes(2, "little")
    return body


def parse_port_u32(pt: bytes, want_siid: int, want_piid: int) -> int | None:
    # Charger returns either 0x93 (original capture) or 0x1c (seen on live
    # get_properties too). Same body layout either way.
    if len(pt) < 6 or pt[1] != 0x20 or pt[0] not in (0x93, 0x1c):
        return None
    i = 6
    while i < len(pt):
        siid = pt[i]
        piid = int.from_bytes(pt[i + 1 : i + 3], "little")
        type_byte = pt[i + 5]
        if type_byte == 0x04:
            val = int.from_bytes(pt[i + 7 : i + 11], "little")
            if siid == want_siid and piid == want_piid:
                return val
            i += 11
        elif type_byte == 0x01:
            i += 8
        else:
            return None
    return None


def parse_port_cap(pt: bytes, pair: str) -> int | None:
    """Extract low-byte watt cap for the requested port from c1c2/c3a piid."""
    # c1c2 u32 = low16=C2, high16=C1; c3a u32 = low16=A, high16=C3
    pair_piid = {"c1c2": 0x11, "c3a": 0x12}[pair]
    # Charger returns either 0x93 (original capture) or 0x1c (seen on live
    # get_properties too). Same body layout either way.
    if len(pt) < 6 or pt[1] != 0x20 or pt[0] not in (0x93, 0x1c):
        return None
    i = 6
    while i < len(pt):
        siid = pt[i]
        piid = int.from_bytes(pt[i + 1 : i + 3], "little")
        type_byte = pt[i + 5]
        if type_byte == 0x04:
            val = int.from_bytes(pt[i + 7 : i + 11], "little")
            if siid == 2 and piid == pair_piid:
                return val
            i += 11
        elif type_byte == 0x01:
            i += 8
        else:
            return None
    return None


async def sweep(address: str, port: str, interval: float, token_file: Path, outpath: Path | None) -> int:
    if port not in PORTS:
        raise ValueError(f"port must be one of {PORTS}, got {port}")
    siid = 2
    port_piid = PORT_PROPERTY_PIID[port]
    pair = "c1c2" if port in {"c1", "c2"} else "c3a"
    pair_piid = {"c1c2": 0x11, "c3a": 0x12}[pair]

    token = bytes.fromhex(json.loads(token_file.read_text())["token_hex"])

    device = None
    for attempt in range(10):
        print(f"scan attempt {attempt+1}/10...", file=sys.stderr, flush=True)
        device = await BleakScanner.find_device_by_address(address, timeout=30)
        if device is not None:
            break
        print("  not advertising, retrying...", file=sys.stderr, flush=True)
    if device is None:
        print(f"device {address} never showed up after 10 attempts", file=sys.stderr)
        return 1

    km = Km003c()
    try:
        async with BleakClient(device, timeout=30) as client:
            backend = getattr(client, "_backend", None)
            if backend is not None and hasattr(backend, "_acquire_mtu"):
                try:
                    await backend._acquire_mtu()
                except Exception:
                    pass

            # Login (retry up to 3x — BLE auth is flaky on first connect)
            keys = None
            last_exc = None
            for attempt in range(3):
                auth = MiAuthClient(client, timeout=15, bluez_start_notify=True)
                try:
                    await auth.subscribe(upnp=False)
                    await auth.greet()
                    await auth.subscribe_upnp()
                    keys = await auth.login(token)
                    break
                except Exception as exc:
                    last_exc = exc
                    print(f"login attempt {attempt + 1} failed: {exc}", file=sys.stderr)
                    await auth.unsubscribe()
                    await asyncio.sleep(1.0)
            if keys is None:
                raise last_exc or RuntimeError("login failed")
            print("login OK, starting loop (Ctrl-C to stop)", file=sys.stderr)

            session = MiSession(auth, keys, timeout=5.0)
            await session.subscribe()

            out_fh = open(outpath, "w") if outpath else None
            seq = 0x0100
            try:
                while True:
                    seq = (seq + 1) & 0xFFFF
                    req = encode_get_properties(
                        seq,
                        [(siid, port_piid), (siid, pair_piid)],
                    )
                    try:
                        pt = await session.send_request(req)
                    except Exception as exc:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] charger read failed: {exc}", flush=True)
                        await asyncio.sleep(interval)
                        continue
                    port_word = parse_port_u32(pt, siid, port_piid)
                    pair_word = parse_port_cap(pt, pair)
                    if port_word is None:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] raw response: {pt.hex(' ', 1)}", flush=True)

                    km_reading = km.read_adc()
                    pd_events = km.read_pd_events()

                    ts = datetime.now().strftime("%H:%M:%S")
                    if port_word is None:
                        print(f"[{ts}] (charger returned no value for {port})", flush=True)
                    else:
                        info = decode_port_info(port, port_word)
                        # Decode pair cap: the target port is either low16 or high16 of pair_word.
                        if pair_word is not None:
                            if (port in {"c2", "a"}):
                                half = pair_word & 0xFFFF
                            else:
                                half = (pair_word >> 16) & 0xFFFF
                            cap_byte = half & 0xFF
                            cap_w = cap_byte or None  # byte encodes watts directly
                            high = (half >> 8) & 0xFF
                        else:
                            cap_byte, cap_w, high = None, None, None
                        row = (
                            f"[{ts}] {port} raw={info.raw_uint32_le:08x} "
                            f"b0={port_word & 0xFF:#04x} b1={info.protocol_code:#04x} "
                            f"in_use={int(info.in_use)} V={info.voltage_v:.1f} A={info.current_a:.1f} W={info.power_w:.1f} "
                            f"cap={cap_w}W (byte={cap_byte:#04x}, high={high:#04x}) | "
                            f"km003c V={km_reading['v']:.3f} I={km_reading['i']:+.3f} "
                            f"cc1/cc2={km_reading['cc1']:.4f}/{km_reading['cc2']:.4f}"
                            f" | pd={km.last_contract or 'no-contract'}"
                        )
                        print(row, flush=True)
                        if pd_events:
                            print(f"    pd_events: {', '.join(pd_events)}", flush=True)
                        if out_fh:
                            out_fh.write(json.dumps({
                                "ts": ts,
                                "port": port,
                                "raw_hex": info.raw_uint32_le.to_bytes(4, "little").hex(),
                                "b0": port_word & 0xFF,
                                "b1": info.protocol_code,
                                "in_use": info.in_use,
                                "v": info.voltage_v,
                                "a": info.current_a,
                                "w": info.power_w,
                                "cap_byte": cap_byte,
                                "cap_w": cap_w,
                                "pdo_high_byte": high,
                                "km003c": km_reading,
                                "pd_contract": km.last_contract,
                                "pd_events": pd_events,
                            }) + "\n")
                            out_fh.flush()
                    await asyncio.sleep(interval)
            finally:
                if out_fh:
                    out_fh.close()
                try:
                    await session.unsubscribe()
                    await auth.unsubscribe()
                except Exception:
                    pass
    finally:
        km.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--address", required=True, help="charger BLE MAC")
    ap.add_argument("--port", required=True, choices=PORTS)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--token-file", type=Path, default=Path.home() / ".cuktech_ble.token")
    ap.add_argument("--out", type=Path, help="optional jsonl path")
    args = ap.parse_args()
    try:
        return asyncio.run(sweep(args.address, args.port, args.interval, args.token_file, args.out))
    except KeyboardInterrupt:
        print("\nstopped", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
