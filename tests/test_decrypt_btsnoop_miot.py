from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cuktech_ble.xiaomi.crypto import derive_login
from cuktech_ble.xiaomi.session import mible_v1_nonce
from tools.decrypt_btsnoop_miot import (
    LoginRandoms,
    MiotFrame,
    decode_miot_plaintext,
    decrypt_miot_frame,
    extract_login_randoms,
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
    from tools.decrypt_btsnoop_miot import AttFrame

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
