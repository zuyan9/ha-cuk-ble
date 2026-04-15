"""Async Mi BLE standard-auth register + login implementation.

Protocol reference: dnandha/miauth, doc/ble_security_proto.txt.

This runs against a pre-connected bleak-compatible client that exposes:
    async start_notify(uuid, handler) / stop_notify(uuid)
    async write_gatt_char(uuid, data, response=bool)

The handler signature is (characteristic, bytearray) — matching bleak.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from . import crypto
from .protocol import (
    AUTH_ERRORS,
    AVDTP_UUID,
    CFM_LOGIN_ERR,
    CFM_LOGIN_OK,
    CFM_REGISTER_ERR,
    CFM_REGISTER_OK,
    CMD_AUTH,
    CMD_GET_INFO,
    CMD_LOGIN,
    CMD_SEND_DATA,
    CMD_SEND_DID,
    CMD_SEND_INFO,
    CMD_SEND_KEY,
    CMD_SET_KEY,
    GREETING_TRIGGER,
    OFFICIAL_ACK,
    PARCEL_CHUNK_SIZE,
    RCV_OK,
    RCV_RDY,
    UPNP_UUID,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class MiSessionKeys:
    dev_key: bytes
    app_key: bytes
    dev_iv: bytes
    app_iv: bytes


@dataclass(frozen=True)
class RegisterResult:
    token: bytes
    bind_key: bytes
    remote_info: bytes

    @property
    def did_text(self) -> str:
        return self.remote_info.rstrip(b"\x00").decode("ascii", errors="replace")


@dataclass
class _ChannelQueue:
    uuid: str
    queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue)

    def handler(self) -> Callable[[Any, bytearray], None]:
        def _on(_: Any, data: bytearray) -> None:
            self.queue.put_nowait(bytes(data))
        return _on


class MiAuthError(Exception):
    pass


class MiAuthClient:
    """Run Mi BLE register/login against a connected bleak client."""

    def __init__(
        self,
        client: Any,
        *,
        timeout: float = 10.0,
        bluez_start_notify: bool = False,
    ) -> None:
        self._client = client
        self._timeout = timeout
        self._start_kwargs: dict[str, Any] = (
            {"bluez": {"use_start_notify": True}} if bluez_start_notify else {}
        )
        self._upnp = _ChannelQueue(UPNP_UUID)
        self._avdtp = _ChannelQueue(AVDTP_UUID)
        self._subscribed = False
        self._upnp_sub = False
        self._avdtp_sub = False

    async def __aenter__(self) -> "MiAuthClient":
        await self.subscribe()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.unsubscribe()

    async def subscribe(self, *, upnp: bool = True) -> None:
        """Enable notifications on AVDTP and optionally UPNP.

        Mi Home subscribes to AVDTP first, runs the a4 greeting, then
        subscribes to UPNP before CMD_LOGIN. Passing ``upnp=False`` defers
        the UPNP subscription so the caller can match that order.
        """
        if not self._avdtp_sub:
            await self._client.start_notify(
                AVDTP_UUID, self._avdtp.handler(), **self._start_kwargs
            )
            self._avdtp_sub = True
        if upnp and not self._upnp_sub:
            await self._client.start_notify(
                UPNP_UUID, self._upnp.handler(), **self._start_kwargs
            )
            self._upnp_sub = True
        self._subscribed = self._avdtp_sub

    async def subscribe_upnp(self) -> None:
        """Subscribe to UPNP after greeting, matching Mi Home's order."""
        if self._upnp_sub:
            return
        await self._client.start_notify(
            UPNP_UUID, self._upnp.handler(), **self._start_kwargs
        )
        self._upnp_sub = True

    async def unsubscribe(self) -> None:
        to_stop = []
        if self._upnp_sub:
            to_stop.append(UPNP_UUID)
            self._upnp_sub = False
        if self._avdtp_sub:
            to_stop.append(AVDTP_UUID)
            self._avdtp_sub = False
        self._subscribed = False
        for uuid in to_stop:
            try:
                await self._client.stop_notify(uuid)
            except Exception:  # noqa: BLE001
                LOGGER.debug("stop_notify(%s) failed", uuid, exc_info=True)

    # ------------------------------------------------------------------ IO
    async def _recv(self, channel: _ChannelQueue) -> bytes:
        try:
            data = await asyncio.wait_for(channel.queue.get(), self._timeout)
        except asyncio.TimeoutError as exc:
            raise MiAuthError(f"timeout waiting for {channel.uuid}") from exc
        LOGGER.debug("← %s: %s", channel.uuid, data.hex())
        if data in AUTH_ERRORS:
            raise MiAuthError(f"device auth error: {data.hex()}")
        return data

    async def _recv_until(self, channel: _ChannelQueue, expected: bytes) -> None:
        """Drain until we see a specific short control frame."""
        while True:
            data = await self._recv(channel)
            if data == expected:
                return
            LOGGER.debug("discarding unexpected frame on %s: %s", channel.uuid, data.hex())

    async def _write(self, uuid: str, payload: bytes) -> None:
        LOGGER.debug("→ %s: %s", uuid, payload.hex())
        await self._client.write_gatt_char(uuid, bytearray(payload), response=False)

    async def _send_parcel(self, uuid: str, announcement: bytes, data: bytes) -> None:
        """Send announcement on `uuid`, await RCV_RDY, stream parcels, await RCV_OK.

        Chunk size is picked to fit the negotiated MTU: the phone sends up to
        ~MTU-5 bytes per parcel and this firmware rejects over-chunked uploads
        where the announcement's frame count doesn't match the minimum
        required for the MTU. We recompute the frame count and rewrite the
        announcement's byte[4:6] to match.
        """
        chunk_size = self._parcel_chunk_size()
        frames = _chunk_parcel(data, chunk_size)
        announcement = (
            announcement[:4]
            + len(frames).to_bytes(2, "little")
            + announcement[6:]
        )
        await self._write(uuid, announcement)
        await self._recv_until(self._avdtp, RCV_RDY)
        for idx, chunk in enumerate(frames, start=1):
            frame = bytes([idx & 0xFF, (idx >> 8) & 0xFF]) + chunk
            await self._write(AVDTP_UUID, frame)
        await self._recv_until(self._avdtp, RCV_OK)

    def _parcel_chunk_size(self) -> int:
        """Compute max parcel payload per frame from the GATT MTU.

        Frame = 2-byte LE index + payload; ATT write CMD = MTU-3 bytes; so the
        parcel payload capacity is MTU-5. Bleak exposes `mtu_size` after
        service discovery. Fall back to the protocol-safe 18-byte chunk when
        MTU is unknown.
        """
        mtu = getattr(self._client, "mtu_size", None)
        if isinstance(mtu, int) and mtu > 0:
            return max(PARCEL_CHUNK_SIZE, mtu - 5)
        return PARCEL_CHUNK_SIZE

    async def _recv_parcel(self, announcement: bytes) -> bytes:
        """Given an announcement already received, collect N parcels."""
        expected = int.from_bytes(announcement[4:6], "little")
        if expected == 0:
            raise MiAuthError(f"parcel announcement claims 0 frames: {announcement.hex()}")
        await self._write(AVDTP_UUID, RCV_RDY)
        frames: dict[int, bytes] = {}
        while len(frames) < expected:
            data = await self._recv(self._avdtp)
            if len(data) < 2:
                continue
            idx = int.from_bytes(data[:2], "little")
            if idx == 0 or idx > expected:
                LOGGER.debug("ignoring rogue parcel idx=%d len=%d", idx, len(data))
                continue
            frames[idx] = data[2:]
        await self._write(AVDTP_UUID, RCV_OK)
        return b"".join(frames[i] for i in sorted(frames))

    # --------------------------------------------------------- REGISTER
    async def register(self, did: str | None = None) -> RegisterResult:
        """Run the one-time bind (ECDH-P256 + mible-setup-info HKDF).

        The device must be in pairing mode (factory-reset / unbound).
        """
        # 1. Ask for device info (DID)
        await self._write(UPNP_UUID, CMD_GET_INFO)
        announcement = await self._recv(self._avdtp)
        if announcement[:4] != b"\x00\x00\x00\x00" or announcement[5] != 0x00:
            if did is None:
                raise MiAuthError(
                    f"unexpected announcement on AVDTP: {announcement.hex()}"
                )
            raw = b""
        else:
            raw = await self._recv_parcel(announcement)

        # AD1204U sends 24 bytes: 5-byte prefix `02 00 00 00 00` + 19-byte ASCII DID.
        # The DID blob used for AES-CCM is the 19-byte ASCII string + trailing null
        # (the Mi reference "fallback" format: did.encode() + b"\x00").
        if len(raw) >= 24 and raw[:5] == b"\x02\x00\x00\x00\x00":
            remote_info = raw[5:24] + b"\x00"
        elif len(raw) >= 24:
            # older devices / miauth convention: skip 4-byte header
            remote_info = raw[4:24]
        elif did is not None:
            remote_info = (did.encode() + b"\x00")[:20]
        else:
            raise MiAuthError(
                f"remote_info has unexpected length {len(raw)}: {raw.hex()}"
            )
        if len(remote_info) != 20:
            raise MiAuthError("remote_info must be 20 bytes after header strip")
        LOGGER.debug("remote_info=%s", remote_info.hex())

        # 2. Send our ECDH public key (64 bytes, chunked as 4 frames of 16)
        priv, pub = crypto.generate_keypair()
        pub_bytes = crypto.public_key_to_bytes(pub)

        await self._write(UPNP_UUID, CMD_SET_KEY)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_DATA, pub_bytes)

        # 3. Receive device's public key (announced on AVDTP)
        peer_announcement = await self._recv(self._avdtp)
        if peer_announcement[:4] != b"\x00\x00\x00\x03":
            raise MiAuthError(
                f"expected REMOTE_PUBKEY announcement, got {peer_announcement.hex()}"
            )
        remote_pub_bytes = await self._recv_parcel(peer_announcement)
        peer_pub = crypto.bytes_to_public_key(remote_pub_bytes)

        # 4. ECDH + HKDF, encrypt DID, send it
        shared = crypto.ecdh_shared(priv, peer_pub)
        secrets = crypto.derive_register(shared)
        did_ct = crypto.encrypt_did(secrets.a_key, remote_info)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_DID, did_ct)

        # 5. Trigger auth confirmation
        await self._write(UPNP_UUID, CMD_AUTH)
        conf = await self._recv(self._upnp)
        if conf == CFM_REGISTER_OK:
            LOGGER.info("register OK")
            return RegisterResult(
                token=secrets.token,
                bind_key=secrets.bind_key,
                remote_info=remote_info,
            )
        if conf == CFM_REGISTER_ERR:
            raise MiAuthError("device reported register failure (12 00 00 00)")
        raise MiAuthError(f"unexpected register confirmation: {conf.hex()}")

    # --------------------------------------------------------- GREETING
    async def greet(self) -> None:
        """Run the "official variant" a4 challenge-echo handshake.

        Mi Home performs this before CMD_LOGIN/CMD_GET_INFO. The device
        sends two AVDTP frames starting with ``00 00 04 ..`` and we echo
        each one back with byte[2] flipped from 0x04 to 0x05.
        """
        await self._write(UPNP_UUID, GREETING_TRIGGER)
        for _ in range(2):
            challenge = await self._recv(self._avdtp)
            if len(challenge) < 3 or challenge[:3] != b"\x00\x00\x04":
                raise MiAuthError(
                    f"unexpected greeting challenge: {challenge.hex()}"
                )
            echo = b"\x00\x00\x05" + challenge[3:]
            await self._write(AVDTP_UUID, echo)

    async def _recv_variant(self, expected_code: int) -> bytes:
        """Receive either an official-variant inline message or a dash-app parcel.

        Official:  ``00 00 02 CC <payload>``      (respond with OFFICIAL_ACK)
        Dash-app:  ``00 00 00 CC NN NN`` + parcels (respond with RCV_RDY/OK)
        """
        announcement = await self._recv(self._avdtp)
        if len(announcement) < 4:
            raise MiAuthError(f"short announcement: {announcement.hex()}")
        variant = announcement[2]
        code = announcement[3]
        if code != expected_code:
            raise MiAuthError(
                f"expected code 0x{expected_code:02x}, got {announcement.hex()}"
            )
        if variant == 0x02:
            payload = announcement[4:]
            await self._write(AVDTP_UUID, OFFICIAL_ACK)
            return payload
        if variant == 0x00:
            return await self._recv_parcel(announcement)
        raise MiAuthError(f"unknown variant byte 0x{variant:02x} in {announcement.hex()}")

    # ------------------------------------------------------------ LOGIN
    async def login(self, token: bytes) -> MiSessionKeys:
        if len(token) != 12:
            raise MiAuthError(f"token must be 12 bytes, got {len(token)}")

        import secrets as _secrets

        app_rand = _secrets.token_bytes(16)

        # 1. Announce login and send our random (no delay — Mi Home sends
        # these ~13 ms apart; if we pause, the device fires an e0 reject).
        await self._write(UPNP_UUID, CMD_LOGIN)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_KEY, app_rand)

        # 2. Receive device's random (official-inline or dash-app parcel)
        dev_rand = await self._recv_variant(0x0d)
        if len(dev_rand) != 16:
            raise MiAuthError(f"device random has wrong length: {len(dev_rand)}")

        # 3. Receive device's HMAC
        dev_info = await self._recv_variant(0x0c)

        # 4. Derive session keys and verify device HMAC
        keys = crypto.derive_login(token, app_rand, dev_rand)
        expected_dev_info = crypto.hmac_sha256(keys.dev_key, dev_rand + app_rand)
        if dev_info != expected_dev_info:
            raise MiAuthError(
                "device HMAC mismatch — token is wrong or register required"
            )

        # 5. Send our HMAC (app_key, app_rand + dev_rand)
        app_info = crypto.hmac_sha256(keys.app_key, app_rand + dev_rand)
        await self._send_parcel(AVDTP_UUID, CMD_SEND_INFO, app_info)

        # 6. Await login confirmation
        conf = await self._recv(self._upnp)
        if conf == CFM_LOGIN_OK:
            LOGGER.info("login OK")
            return MiSessionKeys(
                dev_key=keys.dev_key,
                app_key=keys.app_key,
                dev_iv=keys.dev_iv,
                app_iv=keys.app_iv,
            )
        if conf == CFM_LOGIN_ERR:
            raise MiAuthError("device reported login failure (23 00 00 00)")
        raise MiAuthError(f"unexpected login confirmation: {conf.hex()}")


def _chunk_parcel(data: bytes, chunk_size: int = PARCEL_CHUNK_SIZE) -> list[bytes]:
    if not data:
        return [b""]
    return [
        data[i : i + chunk_size]
        for i in range(0, len(data), chunk_size)
    ]
