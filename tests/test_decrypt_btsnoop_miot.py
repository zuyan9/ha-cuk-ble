from pathlib import Path
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cuktech_ble.xiaomi.crypto import derive_login
from cuktech_ble.xiaomi.session import mible_v1_nonce
from tools.decrypt_btsnoop_miot import (
    AttFrame,
    LoginRandoms,
    MiotFrame,
    decode_miot_plaintext,
    decrypt_att_frames,
    decrypt_miot_frame,
    extract_login_randoms,
    iter_btsnoop,
    iter_login_sessions,
)


def test_decode_set_request_rows() -> None:
    frame = MiotFrame(ts_ms=12.5, direction="tx", counter=4, ciphertext=b"")
    plaintext = bytes.fromhex("0c 20 34 12 00 01 02 05 00 01 10 03")

    rows = decode_miot_plaintext(frame, plaintext)

    assert rows == [
        {
            "ts_ms": "12.50",
            "direction": "tx",
            "counter": 4,
            "opcode": "0c20",
            "seq": 0x1234,
            "action": "set_request",
            "siid": 2,
            "piid": "0x0005",
            "status": "",
            "type": "0x01",
            "marker": "0x10",
            "value": 3,
            "raw_value": "03",
            "plaintext_hex": "0c 20 34 12 00 01 02 05 00 01 10 03",
        }
    ]


def test_decode_get_response_rows() -> None:
    frame = MiotFrame(ts_ms=1.0, direction="rx", counter=2, ciphertext=b"")
    plaintext = bytes.fromhex(
        "1c 20 02 01 03 02"
        "02 01 00 00 00 04 50 01 0a 00 33"
        "02 13 00 00 00 01 00 01"
    )

    rows = decode_miot_plaintext(frame, plaintext)

    assert [row["action"] for row in rows] == ["get_response", "get_response"]
    assert rows[0]["piid"] == "0x0001"
    assert rows[0]["type"] == "0x04"
    assert rows[0]["value"] == 0x33000A01
    assert rows[1]["piid"] == "0x0013"
    assert rows[1]["marker"] == "0x00"
    assert rows[1]["value"] is True


def test_decrypt_miot_frame_uses_login_keys_and_counter() -> None:
    token = bytes.fromhex("00112233445566778899aabb")
    randoms = LoginRandoms(
        app_rand=bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
        dev_rand=bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
    )
    keys = derive_login(token, randoms.app_rand, randoms.dev_rand)
    plaintext = bytes.fromhex("33 20 01 00 02 01 02 01 00")
    counter = 7
    ciphertext = AESCCM(keys.app_key, tag_length=4).encrypt(
        mible_v1_nonce(keys.app_iv, counter), plaintext, None
    )

    frame = MiotFrame(ts_ms=0.0, direction="tx", counter=counter, ciphertext=ciphertext)

    assert decrypt_miot_frame(frame, token, randoms) == plaintext


def test_extract_login_randoms_supports_inline_device_random() -> None:
    app_rand = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    dev_rand = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    frames = [
        AttFrame(0.0, "tx", 1, 0x0010, bytes.fromhex("00 00 00 0b 01 00")),
        AttFrame(0.1, "rx", 1, 0x0010, bytes.fromhex("00 00 01 01")),
        AttFrame(0.2, "tx", 1, 0x0010, bytes.fromhex("01 00") + app_rand),
        AttFrame(0.3, "rx", 1, 0x0010, bytes.fromhex("00 00 02 0d") + dev_rand),
    ]

    randoms = extract_login_randoms(frames)

    assert randoms.app_rand == app_rand
    assert randoms.dev_rand == dev_rand


def test_decrypt_att_frames_uses_each_login_epoch_keys() -> None:
    token = bytes.fromhex("00112233445566778899aabb")
    first_app_rand = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    first_dev_rand = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    second_app_rand = bytes.fromhex("303132333435363738393a3b3c3d3e3f")
    second_dev_rand = bytes.fromhex("404142434445464748494a4b4c4d4e4f")

    frames = _session_frames(
        token,
        acl_handle=7,
        start_ms=0.0,
        app_rand=first_app_rand,
        dev_rand=first_dev_rand,
        plaintext=bytes.fromhex(
            "0f 20 01 00 00 01 02 10 00 01 10 0f"
        ),
    )
    # Reuse the ACL handle and counter to ensure the second frame can only be
    # decrypted with the randoms from the second login epoch.
    frames.extend(
        _session_frames(
            token,
            acl_handle=7,
            start_ms=10.0,
            app_rand=second_app_rand,
            dev_rand=second_dev_rand,
            plaintext=bytes.fromhex(
                "0f 20 02 00 00 01 02 15 00 04 50 0f 0f 03 03"
            ),
        )
    )

    rows = decrypt_att_frames(frames, token=token)

    assert [(row["piid"], row["value"]) for row in rows] == [
        ("0x0010", 0x0F),
        ("0x0015", 0x03030F0F),
    ]


def test_decrypt_att_frames_warns_but_keeps_valid_session() -> None:
    token = bytes.fromhex("00112233445566778899aabb")
    first = _session_frames(
        token,
        acl_handle=7,
        start_ms=0.0,
        app_rand=bytes.fromhex("101112131415161718191a1b1c1d1e1f"),
        dev_rand=bytes.fromhex("202122232425262728292a2b2c2d2e2f"),
        plaintext=bytes.fromhex("0f 20 01 00 00 01 02 10 00 01 10 0f"),
    )
    second = _session_frames(
        token,
        acl_handle=8,
        start_ms=10.0,
        app_rand=bytes.fromhex("303132333435363738393a3b3c3d3e3f"),
        dev_rand=bytes.fromhex("404142434445464748494a4b4c4d4e4f"),
        plaintext=bytes.fromhex("0f 20 02 00 00 01 02 15 00 01 10 01"),
    )
    encrypted = second[-1]
    second[-1] = AttFrame(
        encrypted.ts_ms,
        encrypted.direction,
        encrypted.acl_handle,
        encrypted.attr_handle,
        encrypted.value[:-1] + bytes([encrypted.value[-1] ^ 0xFF]),
    )

    with pytest.warns(RuntimeWarning, match=r"session 2 .*ACL handle 8"):
        rows = decrypt_att_frames(first + second, token=token)

    assert [(row["piid"], row["value"]) for row in rows] == [
        ("0x0010", 0x0F)
    ]


def test_login_session_frame_limit_fails_clearly() -> None:
    frames = [
        AttFrame(0.0, "tx", 7, 0x0010, bytes.fromhex("00 00 00 0b 01 00")),
        AttFrame(0.1, "tx", 7, 0x0010, bytes.fromhex("01 00")),
        AttFrame(0.2, "rx", 7, 0x0010, bytes.fromhex("00 00 01 00")),
    ]

    with pytest.raises(ValueError, match="exceeds 2 ATT frames"):
        list(iter_login_sessions(frames, max_frames=2))


def test_btsnoop_record_length_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "oversized.log"
    path.write_bytes(
        b"btsnoop\x00"
        + struct.pack(">II", 1, 1002)
        + struct.pack(">IIIIII", 0, 1024 * 1024 + 1, 0, 0, 0, 0)
    )

    with pytest.raises(ValueError, match="btsnoop record length"):
        list(iter_btsnoop(path))


def _session_frames(
    token: bytes,
    *,
    acl_handle: int,
    start_ms: float,
    app_rand: bytes,
    dev_rand: bytes,
    plaintext: bytes,
) -> list[AttFrame]:
    keys = derive_login(token, app_rand, dev_rand)
    counter = 1
    ciphertext = AESCCM(keys.dev_key, tag_length=4).encrypt(
        mible_v1_nonce(keys.dev_iv, counter), plaintext, None
    )
    return [
        AttFrame(
            start_ms,
            "tx",
            acl_handle,
            0x0010,
            bytes.fromhex("00 00 00 0b 01 00"),
        ),
        AttFrame(
            start_ms + 0.1,
            "tx",
            acl_handle,
            0x0010,
            bytes.fromhex("01 00") + app_rand,
        ),
        AttFrame(
            start_ms + 0.2,
            "rx",
            acl_handle,
            0x0010,
            bytes.fromhex("00 00 02 0d") + dev_rand,
        ),
        AttFrame(
            start_ms + 0.3,
            "rx",
            acl_handle,
            0x001C,
            bytes.fromhex("00 00 02 00")
            + counter.to_bytes(2, "little")
            + ciphertext,
        ),
    ]
