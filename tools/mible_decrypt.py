"""Attempt MiBeacon standard-auth decryption against an AD1204U btsnoop capture."""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ---------- btsnoop / ATT plumbing ----------


@dataclass
class Frame:
    ts_ms: float
    direction: str  # TX / RX
    handle: int
    pdu: bytes


def iter_btsnoop(
    path: Path,
) -> Iterator[tuple[int, int, int, bytes]]:
    with path.open("rb") as f:
        hdr = f.read(16)
        if len(hdr) < 16 or hdr[:8] != b"btsnoop\x00":
            raise ValueError(f"not btsnoop: {path}")
        while True:
            rec = f.read(24)
            if len(rec) < 24:
                return
            _, incl, flags, _, ts_hi, ts_lo = struct.unpack(">IIIIII", rec)
            data = f.read(incl)
            if len(data) < incl:
                return
            if not data:
                continue
            yield (ts_hi << 32) | ts_lo, flags, data[0], data[1:]


def extract_att(path: Path, target_mac: str) -> list[Frame]:
    mac_le = bytes(int(x, 16) for x in reversed(target_mac.split(":")))
    handles: set[int] = set()
    frames: list[Frame] = []
    l2buf: dict[int, tuple[int, bytes, int]] = {}
    start_ts: int | None = None

    for ts_us, flags, ptype, payload in iter_btsnoop(path):
        if ptype == 4 and len(payload) >= 2:
            evt = payload[0]
            ev = payload[2 : 2 + payload[1]]
            if evt == 0x3E and ev and ev[0] in (0x01, 0x0A) and len(ev) >= 19:
                if ev[1] == 0 and ev[6:12] == mac_le:
                    handle = ev[2] | (ev[3] << 8)
                    handles.add(handle)
            continue
        if ptype != 2 or len(payload) < 4:
            continue
        handle_flags, acl_len = struct.unpack("<HH", payload[:4])
        handle = handle_flags & 0x0FFF
        pb = (handle_flags >> 12) & 0x3
        data = payload[4 : 4 + acl_len]
        if handle not in handles:
            continue
        if start_ts is None:
            start_ts = ts_us
        direction = "TX" if (flags & 1) == 0 else "RX"

        if pb in (0, 2):
            if len(data) < 4:
                continue
            l2_len, cid = struct.unpack("<HH", data[:4])
            frag = data[4:]
            if len(frag) >= l2_len:
                if cid == 0x0004:
                    frames.append(
                        Frame(
                            (ts_us - start_ts) / 1000.0,
                            direction,
                            handle,
                            frag[:l2_len],
                        )
                    )
            else:
                l2buf[handle] = (cid, frag, l2_len)
        elif pb == 1 and handle in l2buf:
            cid, partial, l2_len = l2buf[handle]
            partial = partial + data
            if len(partial) >= l2_len:
                if cid == 0x0004:
                    frames.append(
                        Frame(
                            (ts_us - start_ts) / 1000.0,
                            direction,
                            handle,
                            partial[:l2_len],
                        )
                    )
                del l2buf[handle]
            else:
                l2buf[handle] = (cid, partial, l2_len)
    return frames


def att_value(f: Frame) -> tuple[int, bytes] | None:
    """Return (attr_handle, value) for WRITE_CMD (0x52) / HANDLE_NOTIFY (0x1B) only."""
    p = f.pdu
    if len(p) < 3:
        return None
    if p[0] == 0x52 or p[0] == 0x1B:
        attr_handle = p[1] | (p[2] << 8)
        return attr_handle, p[3:]
    if p[0] == 0x12 and len(p) >= 3:  # WRITE_REQ
        attr_handle = p[1] | (p[2] << 8)
        return attr_handle, p[3:]
    return None


# ---------- Xiaomi framing helpers ----------


def classify_auth_frame(direction: str, val: bytes) -> tuple[str, bytes] | None:
    """Classify a value on UUID 0x0019 (handle 0x0010) during auth.

    Returns (kind, body) where body is the ciphertext/payload without the
    transport header. Header layouts (empirically):
      TX control : 00 00 00 <cmd> <arg_lo> <arg_hi>
      RX control : 00 00 01 <state>                     (state 0x01=RDY, 0x00=OK)
      TX/RX ACK  : 00 00 03 00
      RX data    : 00 00 02 <frame_index>  <16B|32B|...>
      TX data    : 01 00 <16B|32B|...>
    """
    if direction == "TX":
        if val.startswith(b"\x00\x00\x00"):
            return "ctl_tx", val[3:]
        if val.startswith(b"\x00\x00\x03"):
            return "ack_tx", b""
        if val.startswith(b"\x01\x00"):
            return "data_tx", val[2:]
    else:
        if val.startswith(b"\x00\x00\x01"):
            return "ctl_rx", val[3:]
        if val.startswith(b"\x00\x00\x03"):
            return "ack_rx", b""
        if val.startswith(b"\x00\x00\x02"):
            return "data_rx", val[3:]
    return None


# ---------- Crypto helpers ----------


def aes_ecb(key: bytes, data: bytes, decrypt: bool = True) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(data) + ctx.finalize()


def hkdf_sha256(
    ikm: bytes, salt: bytes, info: bytes, length: int = 64
) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)


def entropy(b: bytes) -> float:
    """Byte-level Shannon entropy (bits)."""
    from math import log2

    if not b:
        return 0.0
    counts: dict[int, int] = {}
    for x in b:
        counts[x] = counts.get(x, 0) + 1
    n = len(b)
    return -sum((c / n) * log2(c / n) for c in counts.values())


def looks_printable(pt: bytes) -> bool:
    if not pt:
        return False
    ok = sum(1 for b in pt if 0x20 <= b < 0x7F or b in (0x0A, 0x09, 0x0D))
    return ok >= max(4, int(len(pt) * 0.6))


# ---------- Main ----------


def run(path: Path, mac: str, bindkey: bytes) -> None:
    frames = extract_att(path, mac)
    print(f"# total ATT PDUs on connections to {mac}: {len(frames)}")

    # --- Phase 1 auth: handle 0x0010 = UUID 0x0019 (AVDTP) ---
    auth_events = []
    for f in frames:
        v = att_value(f)
        if v is None:
            continue
        attr_handle, val = v
        if attr_handle != 0x0010:
            continue
        cls = classify_auth_frame(f.direction, val)
        if cls is None:
            continue
        kind, body = cls
        auth_events.append((f, kind, body))

    print(f"\n# Phase-1 auth events on UUID 0x0019: {len(auth_events)}")
    for f, kind, body in auth_events[:30]:
        tag = f"{kind:8s}"
        if body:
            ent = entropy(body)
            print(
                f"  {f.ts_ms:8.1f}ms {f.direction} {tag} "
                f"len={len(body):3d} H={ent:4.2f} {body.hex()}"
            )
        else:
            print(f"  {f.ts_ms:8.1f}ms {f.direction} {tag}")

    # Collect 16-byte data bodies (candidate RandomA/RandomB encrypted with bindkey).
    sixteen_byte = [
        (f, kind, body)
        for (f, kind, body) in auth_events
        if kind in ("data_tx", "data_rx") and len(body) == 16
    ]
    longer = [
        (f, kind, body)
        for (f, kind, body) in auth_events
        if kind in ("data_tx", "data_rx") and 16 < len(body) <= 240
    ]

    print(
        f"\n# 16-byte auth blobs: {len(sixteen_byte)} ; longer blobs: {len(longer)}"
    )

    print("\n# AES-ECB(bindkey)^-1 on 16-byte blobs:")
    ecb16 = []
    for f, kind, body in sixteen_byte:
        pt = aes_ecb(bindkey, body, decrypt=True)
        ecb16.append((f, kind, body, pt))
        print(
            f"  {f.ts_ms:8.1f}ms {f.direction} {kind:8s} "
            f"CT={body.hex()}\n               → PT={pt.hex()} H={entropy(pt):4.2f}"
            f"  printable={looks_printable(pt)}"
        )

    print("\n# AES-ECB(bindkey)^-1 on each 16-byte chunk of longer blobs:")
    for f, kind, body in longer:
        chunks = [body[i : i + 16] for i in range(0, len(body) - len(body) % 16, 16)]
        pts = [aes_ecb(bindkey, c, decrypt=True) for c in chunks]
        print(
            f"  {f.ts_ms:8.1f}ms {f.direction} {kind:8s} "
            f"len={len(body):3d} chunks={len(chunks)}"
        )
        for i, (c, pt) in enumerate(zip(chunks, pts)):
            print(
                f"      [{i}] CT={c.hex()} PT={pt.hex()} "
                f"H={entropy(pt):4.2f} printable={looks_printable(pt)}"
            )

    # --- Try to derive session key assuming ECB(bindkey) reveals Random values ---
    tx_rand = [(f, pt) for (f, k, _, pt) in ecb16 if k == "data_tx"]
    rx_rand = [(f, pt) for (f, k, _, pt) in ecb16 if k == "data_rx"]
    if tx_rand and rx_rand:
        randA = tx_rand[0][1]
        randB = rx_rand[0][1]
        print(f"\n# Assuming RandA = first TX ECB result, RandB = first RX ECB result")
        print(f"#   RandA = {randA.hex()}  (entropy {entropy(randA):.2f})")
        print(f"#   RandB = {randB.hex()}  (entropy {entropy(randB):.2f})")

        # Try HKDF candidates to derive 32-byte session material.
        info_candidates = [
            b"mible-login-info",
            b"mible-setup-info",
            b"mible-shared-info",
            b"mible-login",
            b"mijia-blt-login",
            b"XiaomiIOTLoginInfo",
            b"",
        ]
        salt_candidates = [
            (randA + randB, "RandA||RandB"),
            (randB + randA, "RandB||RandA"),
            (bindkey, "bindkey"),
            (b"", "empty"),
        ]
        ikm_candidates = [
            (bindkey, "bindkey"),
            (randA + randB, "RandA||RandB"),
        ]

        # --- MIOT-channel frames: 0x0019 (TX), 0x001c (RX) ---
        miot: list[tuple[Frame, str, int, bytes]] = []
        for f in frames:
            v = att_value(f)
            if v is None:
                continue
            attr_handle, val = v
            if attr_handle == 0x0019 and val.startswith(b"\x01\x00") and len(val) >= 6:
                seq = val[2] | (val[3] << 8)
                miot.append((f, "TX", seq, val[4:]))
            elif (
                attr_handle == 0x001C
                and val.startswith(b"\x00\x00\x02\x00")
                and len(val) >= 6
            ):
                seq = val[4] | (val[5] << 8)
                miot.append((f, "RX", seq, val[6:]))

        print(f"\n# MIOT frames on 0x001a/0x001b: {len(miot)}")
        samples = [m for m in miot if 7 < len(m[3]) < 200][:30]
        print(f"# trying {len(samples)} samples against "
              f"{len(ikm_candidates)*len(salt_candidates)*len(info_candidates)} KDF combos "
              f"× 7 nonce layouts × 3 tag lens\n")

        mac_le = bytes(int(x, 16) for x in reversed(mac.split(":")))
        pid_le = b"\x0e\x66"

        def nonce_layouts(seq: int, direction: str) -> list[tuple[str, bytes]]:
            ctr_le = seq.to_bytes(4, "little")
            return [
                ("mac6+pid2+ctr4", mac_le + pid_le + ctr_le),
                ("pid2+ctr4+mac6", pid_le + ctr_le + mac_le),
                ("ctr4+mac6+pid2", ctr_le + mac_le + pid_le),
                ("mac6+dir1+ctr4+pid1",
                 mac_le + (b"\x01" if direction == "TX" else b"\x00")
                 + ctr_le + pid_le[:1]),
                ("zero8+ctr4", b"\x00" * 8 + ctr_le),
                ("pid2+mac6+ctr4", pid_le + mac_le + ctr_le),
                ("mac6+pid2+ctr4 (13B)", mac_le + pid_le + ctr_le + b"\x00"),
            ]

        hits = 0
        for ikm, ikm_label in ikm_candidates:
            for salt, salt_label in salt_candidates:
                for info in info_candidates:
                    try:
                        km = hkdf_sha256(ikm, salt, info, length=64)
                    except Exception:
                        continue
                    # candidate session keys: first 16B, second 16B, or split TX/RX
                    key_options = [
                        ("km[0:16]", km[:16]),
                        ("km[16:32]", km[16:32]),
                        ("km[32:48]", km[32:48]),
                    ]
                    for key_label, key in key_options:
                        for f, dir_, seq, ct in samples:
                            for nlabel, nonce in nonce_layouts(seq, dir_):
                                if len(nonce) not in range(7, 14):
                                    continue
                                for tag_len in (4, 8, 16):
                                    if len(ct) <= tag_len:
                                        continue
                                    try:
                                        pt = AESCCM(
                                            key, tag_length=tag_len
                                        ).decrypt(nonce, ct, b"")
                                    except Exception:
                                        continue
                                    # success means tag checked out — strong signal
                                    hits += 1
                                    print(
                                        f"  HIT ikm={ikm_label} salt={salt_label} "
                                        f"info={info!r} key={key_label} "
                                        f"nonce={nlabel} tag={tag_len} "
                                        f"dir={dir_} seq={seq}: {pt.hex()}"
                                    )
                                    if hits > 20:
                                        print("  …stopping after 20 hits")
                                        return

        if hits == 0:
            print(
                "\n# No KDF/nonce combo authenticated any MIOT frame.\n"
                "# Likely causes:\n"
                "# - ECB(bindkey) on the 16-byte blobs doesn't yield RandA/RandB\n"
                "#   (the phase-1 protocol uses something else — maybe ECDH or\n"
                "#    SMP-style pairing — and the 16 bytes aren't encrypted randoms)\n"
                "# - HKDF info string is different from any we tried\n"
                "# - Nonce layout is a variant we didn't include\n"
                "# - Firmware uses AES-CTR/GCM rather than CCM, or a 16-byte tag\n"
                "#   prefix instead of suffix."
            )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--mac", required=True, help="charger BLE MAC, e.g. AA:BB:CC:DD:EE:FF")
    ap.add_argument("--beaconkey", required=True)
    args = ap.parse_args()
    key = bytes.fromhex(args.beaconkey)
    if len(key) != 16:
        print("beaconkey must be 16 bytes", file=sys.stderr)
        return 2
    run(Path(args.log), args.mac, key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
