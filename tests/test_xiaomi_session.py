from __future__ import annotations

import asyncio
import secrets
from typing import Any, Callable
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cuktech_ble.xiaomi import crypto
from cuktech_ble.xiaomi.auth import (
    MAX_AUTH_PARCELS,
    MiAuthClient,
    MiAuthError,
    MiAuthInvalidTokenError,
    MiSessionKeys,
    _ChannelQueue,
)
from cuktech_ble.xiaomi.protocol import CFM_LOGIN_ERR, OFFICIAL_ACK
from cuktech_ble.xiaomi.session import (
    MAX_CAPTURED_FRAMES,
    MAX_MIOT_COUNTER,
    MAX_MIOT_PARCELS,
    MIOT_NOTIFY_UUID,
    MIOT_WRITE_UUID,
    MiSession,
    MiSessionError,
    MiSessionReauthenticationRequired,
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
        self.writes: list[tuple[str, bytes]] = []

    async def start_notify(
        self, uuid: str, callback: Callable[[Any, bytearray], None], **_: object
    ) -> None:
        self.handlers[uuid] = callback

    async def stop_notify(self, uuid: str) -> None:
        self.stopped.append(uuid)
        self.handlers.pop(uuid, None)

    async def write_gatt_char(
        self, uuid: str, data: bytearray, *, response: bool
    ) -> None:
        assert response is False
        self.writes.append((uuid, bytes(data)))

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
    fatal_callback: Callable[[Exception], None] | None = None,
) -> tuple[MiSession, FakeAuth]:
    auth = FakeAuth()
    session = MiSession(
        auth,
        KEYS,
        timeout=0.25,
        notification_callback=callback,
        fatal_error_callback=fatal_callback,
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
        assert session._tx_counter == 1
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


def test_tx_counter_is_spent_before_uncertain_io_and_never_wraps() -> None:
    async def run() -> None:
        fatal_errors: list[Exception] = []
        session, _auth = await _session(fatal_callback=fatal_errors.append)
        session._tx_counter = MAX_MIOT_COUNTER
        send_calls: list[int] = []

        async def failed_send(_ciphertext: bytes, counter: int) -> None:
            send_calls.append(counter)
            assert session._tx_counter == MAX_MIOT_COUNTER + 1
            raise OSError("uncertain BLE write")

        session._send_encrypted = failed_send  # type: ignore[method-assign]
        try:
            with pytest.raises(OSError, match="uncertain BLE write"):
                await session.send_request(bytes.fromhex("33 20 34 12 02 00"))
            assert session.requires_reauthentication is True

            with pytest.raises(
                MiSessionReauthenticationRequired,
                match="TX counter exhausted",
            ):
                await session.send_request(bytes.fromhex("33 20 35 12 02 00"))
            assert send_calls == [MAX_MIOT_COUNTER]
            assert len(fatal_errors) == 1
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_rx_counter_boundary_delivers_last_frame_then_requires_reauth() -> None:
    async def run() -> None:
        pushes: list[bytes] = []
        fatal_errors: list[Exception] = []
        session, auth = await _session(pushes.append, fatal_errors.append)
        notification = bytes.fromhex(
            "0f 20 01 00 04 01 02 02 00 04 50 01 0a 29 c9"
        )
        try:
            auth._client.emit(
                MIOT_NOTIFY_UUID,
                _inline(notification, MAX_MIOT_COUNTER),
            )
            reader = session._reader_task
            assert reader is not None
            await asyncio.wait_for(reader, timeout=1)

            assert pushes == [notification]
            assert session.requires_reauthentication is True
            assert len(fatal_errors) == 1
            assert isinstance(
                fatal_errors[0], MiSessionReauthenticationRequired
            )
            assert auth.writes[-1] == (MIOT_NOTIFY_UUID, OFFICIAL_ACK)
        finally:
            await session.unsubscribe()

    asyncio.run(run())


def test_repeated_rx_counter_stops_before_second_decrypt() -> None:
    async def run() -> None:
        pushes: list[bytes] = []
        fatal_errors: list[Exception] = []
        session, auth = await _session(pushes.append, fatal_errors.append)
        notification = bytes.fromhex(
            "0f 20 01 00 04 01 02 02 00 04 50 01 0a 29 c9"
        )
        try:
            frame = _inline(notification, 7)
            auth._client.emit(MIOT_NOTIFY_UUID, frame)
            auth._client.emit(MIOT_NOTIFY_UUID, frame)
            reader = session._reader_task
            assert reader is not None
            await asyncio.wait_for(reader, timeout=1)

            assert pushes == [notification]
            assert len(fatal_errors) == 1
            assert isinstance(
                fatal_errors[0], MiSessionReauthenticationRequired
            )
        finally:
            await session.unsubscribe()

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

        assert (
            session.decrypt(parcel_frame.ciphertext, parcel_frame.counter)
            == response
        )
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


def test_outbound_miot_parcel_count_is_capped() -> None:
    async def run() -> None:
        auth = FakeAuth()
        session = MiSession(auth, KEYS, timeout=0.1)  # type: ignore[arg-type]
        oversized = b"x" * (MAX_MIOT_PARCELS * 16 + 1)

        with pytest.raises(MiSessionError, match="request needs 65 parcels"):
            await session._send_encrypted(oversized, 0)
        assert auth.writes == []

    asyncio.run(run())


def test_auth_parcel_announcements_and_outbound_count_are_capped() -> None:
    async def run() -> None:
        client = FakeClient()
        auth = MiAuthClient(client, timeout=0.1)

        for announcement in (
            b"\x00\x00\x00\x00\x01",
            b"\x00\x00\x00\x00\x00\x00",
            b"\x00\x00\x00\x00"
            + (MAX_AUTH_PARCELS + 1).to_bytes(2, "little"),
        ):
            with pytest.raises(MiAuthError):
                await auth._recv_parcel(announcement)

        oversized = b"x" * (MAX_AUTH_PARCELS * 18 + 1)
        with pytest.raises(MiAuthError, match="needs 65 parcels"):
            await auth._send_parcel(
                MIOT_NOTIFY_UUID,
                b"\x00\x00\x00\x00\x01\x00",
                oversized,
            )
        assert client.writes == []

    asyncio.run(run())


def test_login_hmac_mismatch_has_dedicated_invalid_token_error() -> None:
    async def run() -> None:
        auth = MiAuthClient(FakeClient(), timeout=0.1)
        auth._write = AsyncMock()  # type: ignore[method-assign]
        auth._send_parcel = AsyncMock()  # type: ignore[method-assign]
        auth._recv_variant = AsyncMock(  # type: ignore[method-assign]
            side_effect=(b"d" * 16, b"not-a-valid-hmac")
        )

        with pytest.raises(MiAuthInvalidTokenError, match="HMAC mismatch"):
            await auth.login(b"t" * 12)

    asyncio.run(run())


def test_device_login_rejection_has_dedicated_invalid_token_error(
    monkeypatch,
) -> None:
    async def run() -> None:
        token = b"t" * 12
        app_random = b"a" * 16
        device_random = b"d" * 16
        keys = crypto.derive_login(token, app_random, device_random)
        device_info = crypto.hmac_sha256(
            keys.dev_key, device_random + app_random
        )
        monkeypatch.setattr(secrets, "token_bytes", lambda _size: app_random)
        auth = MiAuthClient(FakeClient(), timeout=0.1)
        auth._write = AsyncMock()  # type: ignore[method-assign]
        auth._send_parcel = AsyncMock()  # type: ignore[method-assign]
        auth._recv_variant = AsyncMock(  # type: ignore[method-assign]
            side_effect=(device_random, device_info)
        )
        auth._recv = AsyncMock(  # type: ignore[method-assign]
            return_value=CFM_LOGIN_ERR
        )

        with pytest.raises(MiAuthInvalidTokenError, match="login failure"):
            await auth.login(token)

    asyncio.run(run())
