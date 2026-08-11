from __future__ import annotations

import asyncio
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cuktech_ble.xiaomi.auth import MiSessionKeys, _ChannelQueue
from cuktech_ble.xiaomi.protocol import OFFICIAL_ACK
from cuktech_ble.xiaomi.session import (
    MAX_CAPTURED_FRAMES,
    MAX_MIOT_PARCELS,
    MIOT_NOTIFY_UUID,
    MIOT_WRITE_UUID,
    MiSession,
    MiSessionError,
    mible_v1_nonce,
)


KEYS = MiSessionKeys(
    dev_key=bytes.fromhex("00112233445566778899aabbccddeeff"),
    app_key=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    dev_iv=bytes.fromhex("10203040"),
    app_iv=bytes.fromhex("50607080"),
)


class FakeClient:
    def __init__(self) -> None:
        self.handlers: dict[str, Callable[[Any, bytearray], None]] = {}
        self.stopped: list[str] = []

    async def start_notify(
        self, uuid: str, callback: Callable[[Any, bytearray], None], **_: object
    ) -> None:
        self.handlers[uuid] = callback

    async def stop_notify(self, uuid: str) -> None:
        self.stopped.append(uuid)
        self.handlers.pop(uuid, None)

    def emit(self, uuid: str, data: bytes) -> None:
        self.handlers[uuid](uuid, bytearray(data))


class FakeAuth:
    def __init__(self) -> None:
        self._client = FakeClient()
        self._start_kwargs: dict[str, object] = {}
        self.writes: list[tuple[str, bytes]] = []

    async def _write(self, uuid: str, data: bytes) -> None:
        self.writes.append((uuid, bytes(data)))


def _inline(plaintext: bytes, counter: int) -> bytes:
    ciphertext = AESCCM(KEYS.dev_key, tag_length=4).encrypt(
        mible_v1_nonce(KEYS.dev_iv, counter), plaintext, None
    )
    return b"\x00\x00\x02\x00" + counter.to_bytes(2, "little") + ciphertext


async def _session(
    callback: Callable[[bytes], None] | None = None,
) -> tuple[MiSession, FakeAuth]:
    auth = FakeAuth()
    session = MiSession(
        auth, KEYS, timeout=0.25, notification_callback=callback  # type: ignore[arg-type]
    )
    await session.subscribe()
    return session, auth


def test_pending_response_is_installed_before_wire_send() -> None:
    async def run() -> None:
        session, auth = await _session()
        response = bytes.fromhex("1c 20 34 12 03 00")

        async def fake_send(_ciphertext: bytes, _counter: int) -> None:
            auth._client.emit(MIOT_NOTIFY_UUID, _inline(response, 7))
            await asyncio.sleep(0)

        session._send_encrypted = fake_send  # type: ignore[method-assign]
        try:
            result = await session.send_request(bytes.fromhex("33 20 34 12 02 00"))
            assert result == response
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_inline_frame_is_acked_before_notification_callback() -> None:
    async def run() -> None:
        callback_payloads: list[bytes] = []
        auth_ref: list[FakeAuth] = []

        def callback(plaintext: bytes) -> None:
            assert auth_ref[0].writes[-1] == (MIOT_NOTIFY_UUID, OFFICIAL_ACK)
            callback_payloads.append(plaintext)

        session, auth = await _session(callback)
        auth_ref.append(auth)
        notification = bytes.fromhex(
            "0f 20 01 00 04 01 02 02 00 04 50 01 0a 29 c9"
        )
        try:
            # Even a frame that fails authentication is acknowledged first.
            auth._client.emit(
                MIOT_NOTIFY_UUID, b"\x00\x00\x02\x00\x01\x00bad-tag"
            )
            auth._client.emit(MIOT_NOTIFY_UUID, _inline(notification, 2))
            await asyncio.sleep(0)
            await asyncio.sleep(0)

            assert callback_payloads == [notification]
            assert [write for write in auth.writes if write[1] == OFFICIAL_ACK] == [
                (MIOT_NOTIFY_UUID, OFFICIAL_ACK),
                (MIOT_NOTIFY_UUID, OFFICIAL_ACK),
            ]
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_push_burst_does_not_consume_response_budget() -> None:
    async def run() -> None:
        pushes: list[bytes] = []
        session, auth = await _session(pushes.append)

        async def fake_send(_ciphertext: bytes, _counter: int) -> None:
            return None

        session._send_encrypted = fake_send  # type: ignore[method-assign]
        request_task = asyncio.create_task(
            session.send_request(bytes.fromhex("33 20 44 00 02 00"))
        )
        await asyncio.sleep(0)
        try:
            for counter in range(1, 13):
                push = bytes.fromhex(
                    f"0f 20 {counter:02x} 00 04 01 02 02 00 04 50 01 0a 29 c9"
                )
                auth._client.emit(MIOT_NOTIFY_UUID, _inline(push, counter))
            auth._client.emit(
                MIOT_NOTIFY_UUID,
                _inline(bytes.fromhex("1c 20 45 00 03 00"), 13),
            )
            matching = bytes.fromhex("1c 20 44 00 03 00")
            auth._client.emit(MIOT_NOTIFY_UUID, _inline(matching, 14))

            assert await request_task == matching
            assert len(pushes) == 12
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_property_echo_with_matching_sequence_is_not_set_response() -> None:
    async def run() -> None:
        pushes: list[bytes] = []
        session, auth = await _session(pushes.append)

        async def fake_send(_ciphertext: bytes, _counter: int) -> None:
            return None

        session._send_encrypted = fake_send  # type: ignore[method-assign]
        request_task = asyncio.create_task(
            session.send_request(
                bytes.fromhex("0c 20 21 00 00 01 02 06 00 01 10 04")
            )
        )
        await asyncio.sleep(0)
        event = bytes.fromhex("0c 20 21 00 04 01 02 06 00 01 10 04")
        auth._client.emit(MIOT_NOTIFY_UUID, _inline(event, 1))
        await asyncio.sleep(0)
        assert not request_task.done()
        assert pushes == [event]

        response = bytes.fromhex("0b 20 21 00 01 01 02 06 00 00 00")
        auth._client.emit(MIOT_NOTIFY_UUID, _inline(response, 2))
        try:
            assert await request_task == response
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_unsubscribe_fails_pending_request_and_stops_reader() -> None:
    async def run() -> None:
        session, auth = await _session()

        send_entered = asyncio.Event()

        async def fake_send(_ciphertext: bytes, _counter: int) -> None:
            send_entered.set()
            await asyncio.Event().wait()

        session._send_encrypted = fake_send  # type: ignore[method-assign]
        request_task = asyncio.create_task(
            session.send_request(bytes.fromhex("33 20 12 00 02 00"))
        )
        await send_entered.wait()
        reader = session._reader_task
        assert reader is not None and not reader.done()

        await asyncio.wait_for(session.unsubscribe(), timeout=1)
        with pytest.raises(MiSessionError, match="unsubscribed"):
            await request_task
        assert reader.done()
        assert session._reader_task is None
        assert auth._client.stopped == [MIOT_NOTIFY_UUID, MIOT_WRITE_UUID]

        await session.unsubscribe()
        assert auth._client.stopped == [MIOT_NOTIFY_UUID, MIOT_WRITE_UUID]

    asyncio.run(run())


def test_inline_notification_interleaved_with_parcels_is_acked_and_deferred() -> None:
    async def run() -> None:
        auth = FakeAuth()
        session = MiSession(auth, KEYS, timeout=0.25)  # type: ignore[arg-type]
        response = bytes.fromhex("1c 20 34 12 03 00")
        response_ct = AESCCM(KEYS.dev_key, tag_length=4).encrypt(
            mible_v1_nonce(KEYS.dev_iv, 8), response, None
        )
        notification = bytes.fromhex(
            "0f 20 35 12 04 01 02 02 00 04 50 01 0a 29 c9"
        )

        session._response.queue.put_nowait(b"\x00\x00\x00\x00\x02\x00")
        session._response.queue.put_nowait(_inline(notification, 9))
        session._response.queue.put_nowait(
            b"\x01\x00\x08\x00" + response_ct[:5]
        )
        session._response.queue.put_nowait(b"\x02\x00" + response_ct[5:])

        parcel_frame = await session._recv_encrypted()
        deferred_frame = await session._recv_encrypted()

        assert session.decrypt(parcel_frame.ciphertext, parcel_frame.counter) == response
        assert session.decrypt(
            deferred_frame.ciphertext, deferred_frame.counter
        ) == notification
        assert auth.writes == [
            (MIOT_NOTIFY_UUID, b"\x00\x00\x01\x01"),
            (MIOT_NOTIFY_UUID, OFFICIAL_ACK),
            (MIOT_NOTIFY_UUID, b"\x00\x00\x01\x00"),
        ]

    asyncio.run(run())


def test_channel_queue_and_frame_history_are_bounded() -> None:
    queue = _ChannelQueue("test", maxsize=3)
    handler = queue.handler()
    for value in range(5):
        handler(None, bytearray((value,)))

    assert queue.queue.maxsize == 3
    assert queue.queue.qsize() == 3
    assert queue.dropped == 2
    assert [queue.queue.get_nowait() for _ in range(3)] == [b"\x02", b"\x03", b"\x04"]

    async def run() -> None:
        session, auth = await _session(lambda _plaintext: None)
        try:
            for counter in range(MAX_CAPTURED_FRAMES + 5):
                notification = bytes.fromhex(
                    "0f 20 01 00 04 01 02 02 00 04 50 01 0a 29 c9"
                )
                auth._client.emit(MIOT_NOTIFY_UUID, _inline(notification, counter))
                await asyncio.sleep(0)
            assert len(session.captured_frames) == MAX_CAPTURED_FRAMES
            assert session.captured_frames[0].counter == 5
            assert session.captured_frames[-1].counter == MAX_CAPTURED_FRAMES + 4
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_invalid_parcel_count_is_rejected_without_allocating_parts() -> None:
    async def run() -> None:
        auth = FakeAuth()
        session = MiSession(auth, KEYS, timeout=0.1)  # type: ignore[arg-type]
        for count in (0, MAX_MIOT_PARCELS + 1, 0xFFFF):
            session._response.queue.put_nowait(
                b"\x00\x00\x00\x00" + count.to_bytes(2, "little")
            )
            with pytest.raises(MiSessionError, match="invalid MIOT parcel count"):
                await session._recv_encrypted()
        assert auth.writes == []

    asyncio.run(run())
