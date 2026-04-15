"""Crypto primitives for the Xiaomi Mi BLE standard-auth flow."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SETUP_INFO = b"mible-setup-info"
LOGIN_INFO = b"mible-login-info"


@dataclass(frozen=True)
class RegisterSecrets:
    token: bytes  # 12 bytes, persisted for future logins
    bind_key: bytes  # 16 bytes
    a_key: bytes  # 16 bytes, used to encrypt the DID during registration


@dataclass(frozen=True)
class SessionKeys:
    dev_key: bytes  # 16 bytes (device → app decrypt)
    app_key: bytes  # 16 bytes (app → device encrypt)
    dev_iv: bytes  # 4 bytes
    app_iv: bytes  # 4 bytes


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return priv, priv.public_key()


def public_key_to_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize a P-256 public key as 64 bytes (X||Y, no 0x04 prefix)."""
    raw = key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(raw) != 65 or raw[0] != 0x04:
        raise ValueError("unexpected public key encoding")
    return raw[1:]


def bytes_to_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    if len(data) != 64:
        raise ValueError(f"P-256 public key must be 64 bytes, got {len(data)}")
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b"\x04" + data
    )


def ecdh_shared(private_key: ec.EllipticCurvePrivateKey, peer_public: ec.EllipticCurvePublicKey) -> bytes:
    return private_key.exchange(ec.ECDH(), peer_public)


def hkdf(ikm: bytes, *, salt: bytes | None, info: bytes, length: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
        backend=default_backend(),
    ).derive(ikm)


def derive_register(shared: bytes) -> RegisterSecrets:
    out = hkdf(shared, salt=None, info=SETUP_INFO, length=64)
    return RegisterSecrets(token=out[0:12], bind_key=out[12:28], a_key=out[28:44])


def derive_login(token: bytes, app_rand: bytes, dev_rand: bytes) -> SessionKeys:
    salt = app_rand + dev_rand
    out = hkdf(token, salt=salt, info=LOGIN_INFO, length=64)
    return SessionKeys(
        dev_key=out[0:16],
        app_key=out[16:32],
        dev_iv=out[32:36],
        app_iv=out[36:40],
    )


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    mac = HMAC(key, hashes.SHA256(), backend=default_backend())
    mac.update(data)
    return mac.finalize()


def encrypt_did(a_key: bytes, did: bytes) -> bytes:
    """Register-time DID encryption: fixed nonce, AAD = 'devID'."""
    nonce = bytes(range(16, 28))  # 12 bytes: 0x10..0x1b
    return AESCCM(a_key, tag_length=4).encrypt(nonce, did, b"devID")
