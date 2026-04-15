"""Extract ATT traffic for a target BLE peer from a BTSnoop v1 (H4) log."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from typing import Iterator


@dataclass
class Record:
    ts_us: int
    direction: str
    packet_type: int
    payload: bytes


def iter_records(path: str) -> Iterator[Record]:
    with open(path, "rb") as f:
        header = f.read(16)
        if len(header) < 16 or header[:8] != b"btsnoop\x00":
            raise ValueError(f"not a btsnoop file: {path}")
        while True:
            hdr = f.read(24)
            if len(hdr) < 24:
                return
            orig_len, incl_len, flags, drops, ts_hi, ts_lo = struct.unpack(
                ">IIIIII", hdr
            )
            ts_us = (ts_hi << 32) | ts_lo
            data = f.read(incl_len)
            if len(data) < incl_len:
                return
            if not data:
                continue
            # H4: first byte is packet type: 1=HCI_CMD, 2=ACL, 3=SCO, 4=HCI_EVT
            ptype = data[0]
            payload = data[1:]
            direction = "host→ctrl" if (flags & 1) == 0 else "ctrl→host"
            yield Record(ts_us, direction, ptype, payload)


def parse_acl(payload: bytes) -> tuple[int, bytes] | None:
    if len(payload) < 4:
        return None
    handle_flags, acl_len = struct.unpack("<HH", payload[:4])
    handle = handle_flags & 0x0FFF
    pb_flag = (handle_flags >> 12) & 0x3
    data = payload[4 : 4 + acl_len]
    return handle, data, pb_flag


ATT_OPCODES = {
    0x01: "ERROR_RSP",
    0x02: "MTU_REQ",
    0x03: "MTU_RSP",
    0x04: "FIND_INFO_REQ",
    0x05: "FIND_INFO_RSP",
    0x06: "FIND_BY_TYPE_REQ",
    0x07: "FIND_BY_TYPE_RSP",
    0x08: "READ_BY_TYPE_REQ",
    0x09: "READ_BY_TYPE_RSP",
    0x0A: "READ_REQ",
    0x0B: "READ_RSP",
    0x0C: "READ_BLOB_REQ",
    0x0D: "READ_BLOB_RSP",
    0x10: "READ_BY_GROUP_REQ",
    0x11: "READ_BY_GROUP_RSP",
    0x12: "WRITE_REQ",
    0x13: "WRITE_RSP",
    0x16: "PREP_WRITE_REQ",
    0x17: "PREP_WRITE_RSP",
    0x18: "EXEC_WRITE_REQ",
    0x19: "EXEC_WRITE_RSP",
    0x1B: "HANDLE_NOTIFY",
    0x1D: "HANDLE_INDICATE",
    0x1E: "HANDLE_CONFIRM",
    0x52: "WRITE_CMD",
}


def hexs(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def find_connection_handles_for_mac(
    path: str, mac_bytes_le: bytes
) -> dict[int, tuple[int, int]]:
    """Return {acl_handle: (start_ts_us, end_ts_us_or_0)} for connections to MAC."""
    handles: dict[int, tuple[int, int]] = {}
    pending_create = False
    for rec in iter_records(path):
        # HCI Event, look for LE Meta / Connection Complete
        if rec.packet_type == 4 and len(rec.payload) >= 2:
            evt_code = rec.payload[0]
            plen = rec.payload[1]
            ev = rec.payload[2 : 2 + plen]
            if evt_code == 0x3E and ev:  # LE Meta
                sub = ev[0]
                if sub in (0x01, 0x0A) and len(ev) >= 19:
                    # LE Connection Complete / Enhanced
                    status = ev[1]
                    handle = ev[2] | (ev[3] << 8)
                    # peer address at offset 6..12
                    peer_mac = ev[6:12]
                    if status == 0 and peer_mac == mac_bytes_le:
                        handles[handle] = (rec.ts_us, 0)
            elif evt_code == 0x05 and plen >= 4:
                # Disconnect Complete
                handle = ev[1] | (ev[2] << 8)
                if handle in handles:
                    start, _ = handles[handle]
                    handles[handle] = (start, rec.ts_us)
    return handles


def extract_att(path: str, mac: str) -> None:
    mac_bytes_le = bytes(int(x, 16) for x in reversed(mac.split(":")))
    conns = find_connection_handles_for_mac(path, mac_bytes_le)
    if not conns:
        print(f"no connections to {mac} in {path}", file=sys.stderr)
        return
    print(
        f"# connections to {mac}: "
        + ", ".join(f"handle=0x{h:04x}" for h in conns),
        file=sys.stderr,
    )

    # reassembly: per (handle) keep buffer of L2CAP fragments until complete
    l2_buf: dict[int, tuple[int, bytes]] = {}  # handle -> (cid, partial)
    start_ts = None
    for rec in iter_records(path):
        if rec.packet_type != 2:
            continue
        res = parse_acl(rec.payload)
        if res is None:
            continue
        handle, data, pb = res
        if handle not in conns:
            continue
        if start_ts is None:
            start_ts = rec.ts_us

        if pb in (0, 2):  # first fragment
            if len(data) < 4:
                continue
            l2_len, cid = struct.unpack("<HH", data[:4])
            frag = data[4:]
            if len(frag) >= l2_len:
                emit_att(rec, handle, cid, frag[:l2_len], start_ts)
            else:
                l2_buf[handle] = (cid, frag, l2_len)
        elif pb == 1:  # continuation
            if handle not in l2_buf:
                continue
            cid, partial, l2_len = l2_buf[handle]
            partial = partial + data
            if len(partial) >= l2_len:
                emit_att(rec, handle, cid, partial[:l2_len], start_ts)
                del l2_buf[handle]
            else:
                l2_buf[handle] = (cid, partial, l2_len)


def emit_att(
    rec: Record, handle: int, cid: int, pdu: bytes, start_ts: int
) -> None:
    if cid != 0x0004:  # ATT CID
        return
    if not pdu:
        return
    op = pdu[0]
    name = ATT_OPCODES.get(op, f"0x{op:02x}")
    t_ms = (rec.ts_us - start_ts) / 1000.0
    dir_arrow = "→" if rec.direction == "host→ctrl" else "←"
    extra = ""
    if op in (0x12, 0x52, 0x1B, 0x1D) and len(pdu) >= 3:
        att_handle = pdu[1] | (pdu[2] << 8)
        value = pdu[3:]
        extra = f" h=0x{att_handle:04x} val[{len(value)}]={hexs(value)}"
    elif op in (0x0A, 0x0C) and len(pdu) >= 3:
        att_handle = pdu[1] | (pdu[2] << 8)
        extra = f" h=0x{att_handle:04x}"
    elif op in (0x0B, 0x0D):
        extra = f" val[{len(pdu)-1}]={hexs(pdu[1:])}"
    else:
        extra = f" pdu={hexs(pdu)}"
    print(f"{t_ms:10.2f}ms  h{handle:04x} {dir_arrow} {name:18s}{extra}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--mac", required=True, help="charger BLE MAC, e.g. AA:BB:CC:DD:EE:FF")
    args = ap.parse_args()
    extract_att(args.log, args.mac)
    return 0


if __name__ == "__main__":
    sys.exit(main())
