"""Post-auth encrypted MIOT transport for Mi BLE standard-auth devices.

Wraps an authenticated ``MiAuthClient`` + ``MiSessionKeys`` with AES-CCM
request/response framing. Protocol shape, reverse-engineered from AD1204U
traffic captured in Mi Home's btsnoop log:

- Outbound (host → device), write characteristic ``00000019`` (AVDTP):
    announcement ``00 00 00 00 NN NN`` (NN NN = parcel count LE, normally 01 00)
    → wait ``00 00 01 01`` (RCV_RDY)
    → N parcels ``01 00 CC CC <ct>`` (CC CC = TX counter LE)
    → wait ``00 00 01 00`` (RCV_OK)
- Inbound (device → host), notify characteristic ``0000001c``:
    official-inline ``00 00 02 00 CC CC <ct>`` (ACK with ``00 00 03 00``)
    OR ``00 00 00 00 NN NN`` + RCV_RDY/parcels/RCV_OK

``CC CC`` is an independent 16-bit LE counter in each direction.

AES-CCM parameters (verified against captured AD1204U traffic): nonce =
``IV(4) + b"\\x00\\x00\\x00\\x00" + counter(4 LE)``, no AAD, 4-byte tag.
Key is ``app_key`` for host→device and ``dev_key`` for device→host.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from .auth import MiAuthClient, MiAuthError, MiSessionKeys, _ChannelQueue, _chunk_parcel
from .protocol import (
    AVDTP_UUID,
    OFFICIAL_ACK,
    PARCEL_CHUNK_SIZE,
    RCV_OK,
    RCV_RDY,
)

LOGGER = logging.getLogger(__name__)

# Post-auth MIOT channels. Observed on the AD1204U via Mi Home btsnoop:
#   write + RCV_RDY/RCV_OK (notify): 0x0000001a
#   notify (encrypted responses + telemetry pushes): 0x0000001b
MIOT_WRITE_UUID = "0000001a-0000-1000-8000-00805f9b34fb"
MIOT_NOTIFY_UUID = "0000001b-0000-1000-8000-00805f9b34fb"

# MIOT request/response announcement code (byte[3] of the 6-byte header).
MIOT_ANN_CODE = 0x00


NonceBuilder = Callable[[bytes, int], bytes]


def mible_v1_nonce(iv: bytes, counter: int) -> bytes:
    """AD1204U MIOT nonce scheme: IV(4) + 4 zero bytes + counter(4 LE). 12 bytes."""
    if len(iv) != 4:
        raise ValueError("iv must be 4 bytes")
    return iv + b"\x00\x00\x00\x00" + counter.to_bytes(4, "little")


@dataclass(frozen=True)
class MiotCipherProfile:
    """AES-CCM framing parameters."""

    name: str
    tx_nonce: NonceBuilder
    rx_nonce: NonceBuilder
    aad: bytes = b""
    tag_length: int = 4


DEFAULT_PROFILE = MiotCipherProfile(
    name="mible-v1-noaad",
    tx_nonce=mible_v1_nonce,
    rx_nonce=mible_v1_nonce,
    aad=b"",
    tag_length=4,
)


@dataclass(frozen=True)
class MiotFrame:
    """A single encrypted MIOT frame captured on either direction."""

    counter: int
    ciphertext: bytes
    direction: str  # "tx" or "rx"


class MiSessionError(MiAuthError):
    pass


class MiSession:
    """Encrypted MIOT transport over an authenticated ``MiAuthClient``.

    Callers are expected to have already run ``login()``. The auth client's
    UPNP/AVDTP subscriptions stay put — we additionally subscribe to
    ``0000001c`` for responses and spontaneous telemetry pushes.
    """

    def __init__(
        self,
        auth: MiAuthClient,
        keys: MiSessionKeys,
        *,
        profile: MiotCipherProfile = DEFAULT_PROFILE,
        timeout: float = 10.0,
    ) -> None:
        self._auth = auth
        self._keys = keys
        self._profile = profile
        self._timeout = timeout
        self._response = _ChannelQueue(MIOT_NOTIFY_UUID)
        # RCV_RDY/RCV_OK for MIOT come on UUID 0x001a (same char we write
        # requests to), distinct from AVDTP used during auth.
        self._control = _ChannelQueue(MIOT_WRITE_UUID)
        self._response_sub = False
        self._control_sub = False
        self._tx_counter = 0
        self._rx_counter = 0
        self._app_ccm = AESCCM(keys.app_key, tag_length=profile.tag_length)
        self._dev_ccm = AESCCM(keys.dev_key, tag_length=profile.tag_length)
        self._rx_raw: list[MiotFrame] = []

    @property
    def profile(self) -> MiotCipherProfile:
        return self._profile

    @property
    def captured_frames(self) -> list[MiotFrame]:
        return list(self._rx_raw)

    async def __aenter__(self) -> "MiSession":
        await self.subscribe()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.unsubscribe()

    async def subscribe(self) -> None:
        if not self._response_sub:
            await self._auth._client.start_notify(
                MIOT_NOTIFY_UUID,
                self._response.handler(),
                **self._auth._start_kwargs,
            )
            self._response_sub = True
        if not self._control_sub:
            await self._auth._client.start_notify(
                MIOT_WRITE_UUID,
                self._control.handler(),
                **self._auth._start_kwargs,
            )
            self._control_sub = True

    async def unsubscribe(self) -> None:
        for uuid, flag_attr in (
            (MIOT_NOTIFY_UUID, "_response_sub"),
            (MIOT_WRITE_UUID, "_control_sub"),
        ):
            if getattr(self, flag_attr):
                setattr(self, flag_attr, False)
                try:
                    await self._auth._client.stop_notify(uuid)
                except Exception:  # noqa: BLE001
                    LOGGER.debug("stop_notify(%s) failed", uuid, exc_info=True)

    async def _recv_until(self, channel: _ChannelQueue, expected: bytes) -> None:
        while True:
            try:
                data = await asyncio.wait_for(channel.queue.get(), self._timeout)
            except asyncio.TimeoutError as exc:
                raise MiSessionError(
                    f"timeout waiting for {expected.hex()} on {channel.uuid}"
                ) from exc
            if data == expected:
                return
            LOGGER.debug("ignoring %s on %s", data.hex(), channel.uuid)

    # ---------------------------------------------------------- encode
    def encrypt(self, plaintext: bytes, counter: int | None = None) -> bytes:
        if counter is None:
            counter = self._tx_counter
        nonce = self._profile.tx_nonce(self._keys.app_iv, counter)
        return self._app_ccm.encrypt(nonce, plaintext, self._profile.aad or None)

    def decrypt(self, ciphertext: bytes, counter: int) -> bytes:
        nonce = self._profile.rx_nonce(self._keys.dev_iv, counter)
        return self._dev_ccm.decrypt(nonce, ciphertext, self._profile.aad or None)

    # ---------------------------------------------------------- frame IO
    async def send_request(self, plaintext: bytes) -> bytes:
        """Encrypt, ship on AVDTP, wait for + decrypt the response."""
        counter = self._tx_counter
        ct = self.encrypt(plaintext, counter)
        await self._send_encrypted(ct, counter)
        self._tx_counter = (counter + 1) & 0xFFFF

        # Device interleaves unsolicited telemetry pushes with responses.
        # Skip frames that don't decrypt or that don't look like responses
        # to our request seq, up to a small retry budget.
        req_seq = plaintext[2:4] if len(plaintext) >= 4 else b""
        for _ in range(8):
            frame = await self._recv_encrypted()
            try:
                pt = self.decrypt(frame.ciphertext, frame.counter)
            except Exception as exc:  # noqa: BLE001
                LOGGER.debug(
                    "skip undecryptable frame counter=%d: %s", frame.counter, exc
                )
                continue
            if req_seq and len(pt) >= 4 and pt[2:4] == req_seq:
                self._rx_counter = (frame.counter + 1) & 0xFFFF
                return pt
            LOGGER.debug(
                "skip non-matching pt counter=%d: %s", frame.counter, pt.hex()
            )
        raise MiSessionError("no matching response after 8 frames")

    async def _send_encrypted(self, ct: bytes, counter: int) -> None:
        mtu = getattr(self._auth._client, "mtu_size", None)
        # frame overhead: 2-byte idx + 2-byte counter prefix → MTU-3 (write_cmd) - 4
        payload_cap = (
            max(PARCEL_CHUNK_SIZE - 2, mtu - 7) if isinstance(mtu, int) and mtu > 0
            else PARCEL_CHUNK_SIZE - 2
        )
        counter_prefix = counter.to_bytes(2, "little")
        frames = _chunk_parcel(ct, payload_cap)
        announcement = bytes([0x00, 0x00, 0x00, MIOT_ANN_CODE]) + len(frames).to_bytes(
            2, "little"
        )
        await self._auth._write(MIOT_WRITE_UUID, announcement)
        await self._recv_until(self._control, RCV_RDY)
        for idx, chunk in enumerate(frames, start=1):
            frame = bytes([idx & 0xFF, (idx >> 8) & 0xFF]) + counter_prefix + chunk
            await self._auth._write(MIOT_WRITE_UUID, frame)
        await self._recv_until(self._control, RCV_OK)

    async def _recv_encrypted(self) -> MiotFrame:
        """Receive one encrypted MIOT frame from the data-response channel."""
        while True:
            try:
                data = await asyncio.wait_for(
                    self._response.queue.get(), self._timeout
                )
            except asyncio.TimeoutError as exc:
                raise MiSessionError("timeout waiting for MIOT response") from exc
            LOGGER.debug("← %s: %s", MIOT_NOTIFY_UUID, data.hex())
            if len(data) < 6:
                LOGGER.debug("discarding short frame: %s", data.hex())
                continue
            if data[:4] == b"\x00\x00\x02\x00":
                counter = int.from_bytes(data[4:6], "little")
                ct = bytes(data[6:])
                await self._auth._write(MIOT_NOTIFY_UUID, OFFICIAL_ACK)
                frame = MiotFrame(counter=counter, ciphertext=ct, direction="rx")
                self._rx_raw.append(frame)
                return frame
            if data[:4] == bytes([0x00, 0x00, 0x00, MIOT_ANN_CODE]):
                expected = int.from_bytes(data[4:6], "little")
                await self._auth._write(MIOT_NOTIFY_UUID, RCV_RDY)
                parts: dict[int, bytes] = {}
                counter: int | None = None
                while len(parts) < expected:
                    part = await asyncio.wait_for(
                        self._response.queue.get(), self._timeout
                    )
                    LOGGER.debug("parcel: %s", part.hex())
                    if len(part) < 2:
                        continue
                    idx = int.from_bytes(part[:2], "little")
                    if idx == 1:
                        counter = int.from_bytes(part[2:4], "little")
                        parts[idx] = bytes(part[4:])
                    else:
                        parts[idx] = bytes(part[2:])
                await self._auth._write(MIOT_NOTIFY_UUID, RCV_OK)
                ct = b"".join(parts[i] for i in sorted(parts))
                assert counter is not None
                frame = MiotFrame(counter=counter, ciphertext=ct, direction="rx")
                self._rx_raw.append(frame)
                return frame
            LOGGER.debug("discarding unknown frame: %s", data.hex())

    # ---------------------------------------------------------- passive
    async def collect_pushes(self, duration: float) -> list[MiotFrame]:
        """Passively drain incoming frames for `duration` seconds.

        The device streams telemetry once a client is logged in; we just
        ACK and record. Useful for offline nonce cracking.
        """
        deadline = asyncio.get_event_loop().time() + duration
        collected: list[MiotFrame] = []
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                data = await asyncio.wait_for(self._response.queue.get(), remaining)
            except asyncio.TimeoutError:
                break
            if len(data) < 6 or data[:4] != b"\x00\x00\x02\x00":
                LOGGER.debug("push discard: %s", data.hex())
                continue
            counter = int.from_bytes(data[4:6], "little")
            ct = bytes(data[6:])
            await self._auth._write(MIOT_NOTIFY_UUID, OFFICIAL_ACK)
            frame = MiotFrame(counter=counter, ciphertext=ct, direction="rx")
            self._rx_raw.append(frame)
            collected.append(frame)
        return collected


