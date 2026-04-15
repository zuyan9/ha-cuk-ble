"""Simulate a Mi BLE peer and drive register + login end-to-end."""

from __future__ import annotations

import asyncio
import secrets
from typing import Any, Callable

from cuktech_ble.xiaomi import crypto
from cuktech_ble.xiaomi.auth import MiAuthClient
from cuktech_ble.xiaomi.protocol import (
    AVDTP_UUID,
    CFM_LOGIN_OK,
    CFM_REGISTER_OK,
    CMD_AUTH,
    CMD_GET_INFO,
    CMD_LOGIN,
    CMD_SEND_DATA,
    CMD_SEND_DID,
    CMD_SEND_INFO,
    CMD_SEND_KEY,
    CMD_SET_KEY,
    PARCEL_CHUNK_SIZE,
    RCV_OK,
    RCV_RDY,
    RCV_RESP_DATA,
    RCV_RESP_INFO,
    RCV_RESP_KEY,
    RCV_WR_DID,
    UPNP_UUID,
)


class _PeerSim:
    """Minimal simulated Mi BLE peer that drives the handshake."""

    def __init__(self, did: bytes = b"blt.3.1o6lpef24c8\x00\x00\x00") -> None:
        assert len(did) == 20
        self.did = did
        self.token: bytes | None = None
        self.remote_pub: bytes | None = None
        self.dev_priv, self.dev_pub_obj = crypto.generate_keypair()
        self.dev_pub_bytes = crypto.public_key_to_bytes(self.dev_pub_obj)
        self.dev_rand: bytes | None = None

    async def respond_register(self, client: "FakePeerClient") -> None:
        # Step 1: await CMD_GET_INFO, send CMD_WR_DID parcel with DID
        await client.await_write(UPNP_UUID, CMD_GET_INFO)
        await client.notify(AVDTP_UUID, RCV_WR_DID)
        await client.await_write(AVDTP_UUID, RCV_RDY)
        # real devices prepend a 4-byte header before the 20-byte DID payload
        await _send_parcel(client, b"\x02\x00\x00\x00" + self.did)
        await client.await_write(AVDTP_UUID, RCV_OK)

        # Step 2: await CMD_SET_KEY + CMD_SEND_DATA parcel with our pubkey
        await client.await_write(UPNP_UUID, CMD_SET_KEY)
        await client.await_write(AVDTP_UUID, CMD_SEND_DATA)
        await client.notify(AVDTP_UUID, RCV_RDY)
        self.remote_pub = await _receive_parcel(client, 64)
        await client.notify(AVDTP_UUID, RCV_OK)

        # Step 3: send our public key
        await client.notify(AVDTP_UUID, RCV_RESP_DATA)
        await client.await_write(AVDTP_UUID, RCV_RDY)
        await _send_parcel(client, self.dev_pub_bytes)
        await client.await_write(AVDTP_UUID, RCV_OK)

        # Step 4: receive encrypted DID parcel
        peer_pub_obj = crypto.bytes_to_public_key(self.remote_pub)
        shared = crypto.ecdh_shared(self.dev_priv, peer_pub_obj)
        reg = crypto.derive_register(shared)
        expected_did_ct = crypto.encrypt_did(reg.a_key, self.did)

        await client.await_write(AVDTP_UUID, CMD_SEND_DID)
        await client.notify(AVDTP_UUID, RCV_RDY)
        did_ct = await _receive_parcel(client, len(expected_did_ct))
        assert did_ct == expected_did_ct
        await client.notify(AVDTP_UUID, RCV_OK)

        # Step 5: confirm
        await client.await_write(UPNP_UUID, CMD_AUTH)
        await client.notify(UPNP_UUID, CFM_REGISTER_OK)

        self.token = reg.token

    async def respond_login(self, client: "FakePeerClient") -> None:
        await client.await_write(UPNP_UUID, CMD_LOGIN)

        # app random arrives as a parcel
        await client.await_write(AVDTP_UUID, CMD_SEND_KEY)
        await client.notify(AVDTP_UUID, RCV_RDY)
        app_rand = await _receive_parcel(client, 16)
        await client.notify(AVDTP_UUID, RCV_OK)

        # we send device random
        self.dev_rand = secrets.token_bytes(16)
        await client.notify(AVDTP_UUID, RCV_RESP_KEY)
        await client.await_write(AVDTP_UUID, RCV_RDY)
        await _send_parcel(client, self.dev_rand)
        await client.await_write(AVDTP_UUID, RCV_OK)

        # we send device info (HMAC)
        assert self.token is not None
        keys = crypto.derive_login(self.token, app_rand, self.dev_rand)
        dev_info = crypto.hmac_sha256(keys.dev_key, self.dev_rand + app_rand)
        await client.notify(AVDTP_UUID, RCV_RESP_INFO)
        await client.await_write(AVDTP_UUID, RCV_RDY)
        await _send_parcel(client, dev_info)
        await client.await_write(AVDTP_UUID, RCV_OK)

        # receive our info, verify, confirm login
        await client.await_write(AVDTP_UUID, CMD_SEND_INFO)
        await client.notify(AVDTP_UUID, RCV_RDY)
        app_info = await _receive_parcel(client, 32)
        await client.notify(AVDTP_UUID, RCV_OK)
        expected_app_info = crypto.hmac_sha256(keys.app_key, app_rand + self.dev_rand)
        assert app_info == expected_app_info
        await client.notify(UPNP_UUID, CFM_LOGIN_OK)


async def _send_parcel(client: "FakePeerClient", data: bytes) -> None:
    frames = [
        data[i : i + PARCEL_CHUNK_SIZE]
        for i in range(0, len(data), PARCEL_CHUNK_SIZE)
    ]
    for idx, chunk in enumerate(frames, start=1):
        frame = bytes([idx & 0xFF, (idx >> 8) & 0xFF]) + chunk
        await client.notify(AVDTP_UUID, frame)


async def _receive_parcel(client: "FakePeerClient", expected_len: int) -> bytes:
    collected: dict[int, bytes] = {}
    while sum(len(v) for v in collected.values()) < expected_len:
        frame = await client.pull_write(AVDTP_UUID)
        idx = int.from_bytes(frame[:2], "little")
        collected[idx] = frame[2:]
    return b"".join(collected[i] for i in sorted(collected))


class FakePeerClient:
    """Bleak-compatible fake paired with a _PeerSim coroutine."""

    def __init__(self, sim: _PeerSim) -> None:
        self.sim = sim
        self.handlers: dict[str, Callable[[Any, bytearray], None]] = {}
        self._write_queues: dict[str, asyncio.Queue[bytes]] = {
            UPNP_UUID: asyncio.Queue(),
            AVDTP_UUID: asyncio.Queue(),
        }

    async def start_notify(
        self, uuid: str, handler: Callable[[Any, bytearray], None], **_: object
    ) -> None:
        self.handlers[uuid] = handler

    async def stop_notify(self, uuid: str) -> None:
        self.handlers.pop(uuid, None)

    async def write_gatt_char(
        self, uuid: str, data: bytearray, response: bool = False
    ) -> None:
        await self._write_queues[uuid].put(bytes(data))

    # helpers used by the simulated peer
    async def notify(self, uuid: str, data: bytes) -> None:
        handler = self.handlers[uuid]
        handler(uuid, bytearray(data))
        await asyncio.sleep(0)

    async def pull_write(self, uuid: str) -> bytes:
        return await asyncio.wait_for(self._write_queues[uuid].get(), timeout=2)

    async def await_write(self, uuid: str, expected: bytes) -> None:
        data = await self.pull_write(uuid)
        assert data == expected, f"on {uuid}: got {data.hex()}, expected {expected.hex()}"


async def _round_trip() -> None:
    sim = _PeerSim()
    client = FakePeerClient(sim)
    auth = MiAuthClient(client, timeout=2)
    await auth.subscribe()

    peer_task = asyncio.create_task(sim.respond_register(client))
    result = await auth.register()
    await peer_task

    assert result.token == sim.token
    assert result.remote_info == sim.did
    assert len(result.token) == 12
    assert len(result.bind_key) == 16

    peer_task = asyncio.create_task(sim.respond_login(client))
    keys = await auth.login(result.token)
    await peer_task

    assert len(keys.dev_key) == 16
    assert len(keys.app_key) == 16
    assert len(keys.dev_iv) == 4
    assert len(keys.app_iv) == 4


def test_register_and_login_round_trip() -> None:
    asyncio.run(_round_trip())
