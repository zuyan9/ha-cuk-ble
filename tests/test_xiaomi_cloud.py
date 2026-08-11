import asyncio
import base64
import json

import aiohttp
import pytest
from yarl import URL

from cuktech_ble import xiaomi_cloud
from cuktech_ble.xiaomi_cloud import (
    CloudAuth,
    CloudError,
    QRLogin,
    QRLoginPending,
    find_token_by_mac,
    poll_qr_login,
    start_qr_login,
    wait_for_qr_scan,
)

TEST_TOKEN_HEX = "ab" * 12
TEST_EXTENDED_TOKEN_HEX = TEST_TOKEN_HEX + "cd" * 4


class _FailingRequest:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    async def __aenter__(self):
        raise self._error

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


class _FailingSession:
    def __init__(self, error: BaseException) -> None:
        self._error = error

    def get(self, *args, **kwargs) -> _FailingRequest:
        return _FailingRequest(self._error)

    def post(self, *args, **kwargs) -> _FailingRequest:
        return _FailingRequest(self._error)


class _Response:
    def __init__(self, text: str, url: str) -> None:
        self._text = text
        self.url = URL(url)
        self.status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def text(self) -> str:
        return self._text

    async def read(self) -> bytes:
        return self._text.encode()


class _QueuedSession:
    def __init__(self, responses: list[_Response], cookie_jar) -> None:
        self._responses = iter(responses)
        self.cookie_jar = cookie_jar

    def get(self, *args, **kwargs) -> _Response:
        return next(self._responses)


def _qr_login() -> QRLogin:
    return QRLogin(
        qr_image_url="https://example.test/qr",
        login_url="https://example.test/login",
        lp_url="https://example.test/poll",
        timeout_seconds=300,
        device_id="device-id",
    )


def _cloud_auth() -> CloudAuth:
    return CloudAuth(
        user_id="user",
        cuser_id="cuser",
        ssecurity=base64.b64encode(b"s" * 16).decode(),
        pass_token="pass",
        service_token="service",
        device_id="device-id",
    )


@pytest.mark.parametrize(
    "error",
    [aiohttp.ClientConnectionError("offline"), asyncio.TimeoutError()],
)
def test_start_qr_login_wraps_network_errors(error: BaseException) -> None:
    with pytest.raises(CloudError, match="QR login request failed"):
        asyncio.run(start_qr_login(_FailingSession(error)))  # type: ignore[arg-type]


def test_start_qr_login_rejects_non_object_json() -> None:
    session = _QueuedSession(
        [_Response("&&&START&&&[]", "https://account.xiaomi.com/login")],
        cookie_jar=None,
    )

    with pytest.raises(CloudError, match="not JSON"):
        asyncio.run(start_qr_login(session))  # type: ignore[arg-type]


def test_poll_qr_login_wraps_network_errors() -> None:
    session = _FailingSession(aiohttp.ClientConnectionError("offline"))

    with pytest.raises(CloudError, match="QR poll request failed"):
        asyncio.run(poll_qr_login(session, _qr_login()))  # type: ignore[arg-type]


def test_poll_qr_login_uses_cookie_for_redirect_domain() -> None:
    async def run() -> None:
        jar = aiohttp.CookieJar()
        redirect_url = "https://sts.api.io.mi.com/sts"
        jar.update_cookies(
            {"serviceToken": "correct-token"},
            response_url=URL(redirect_url),
        )
        jar.update_cookies(
            {"serviceToken": "unrelated-token"},
            response_url=URL("https://unrelated.example/login"),
        )
        poll_result = {
            "code": 0,
            "ssecurity": base64.b64encode(b"s" * 16).decode(),
            "location": redirect_url,
            "userId": "user",
            "cUserId": "cuser",
            "passToken": "pass",
        }
        session = _QueuedSession(
            [
                _Response(
                    "&&&START&&&" + json.dumps(poll_result),
                    "https://account.xiaomi.com/poll",
                ),
                _Response("", redirect_url),
            ],
            jar,
        )

        auth = await poll_qr_login(session, _qr_login())  # type: ignore[arg-type]

        assert auth.service_token == "correct-token"

    asyncio.run(run())


def test_encrypted_post_wraps_network_errors() -> None:
    session = _FailingSession(asyncio.TimeoutError())

    with pytest.raises(CloudError, match="request failed"):
        asyncio.run(
            xiaomi_cloud._encrypted_post(  # noqa: SLF001
                session,  # type: ignore[arg-type]
                _cloud_auth(),
                "cn",
                "/home/device_list",
                "{}",
            )
        )


def test_encrypted_post_wraps_invalid_cloud_auth() -> None:
    auth = _cloud_auth()
    auth = CloudAuth(
        user_id=auth.user_id,
        cuser_id=auth.cuser_id,
        ssecurity="not-base64!",
        pass_token=auth.pass_token,
        service_token=auth.service_token,
        device_id=auth.device_id,
    )

    with pytest.raises(CloudError, match="request signing failed"):
        asyncio.run(
            xiaomi_cloud._encrypted_post(  # noqa: SLF001
                _FailingSession(AssertionError("network must not be used")),
                auth,
                "cn",
                "/home/device_list",
                "{}",
            )
        )


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"result": []},
        {"result": {"list": {}}},
        {"result": {"list": ["not-a-device"]}},
    ],
)
def test_list_devices_rejects_malformed_shapes(monkeypatch, response) -> None:
    async def _response(*args, **kwargs):
        return response

    monkeypatch.setattr(xiaomi_cloud, "_encrypted_post", _response)

    with pytest.raises(CloudError, match="invalid"):
        asyncio.run(
            xiaomi_cloud.list_devices(
                object(),  # type: ignore[arg-type]
                _cloud_auth(),
                "cn",
            )
        )


def test_cloud_requests_preserve_cancellation() -> None:
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            start_qr_login(  # type: ignore[arg-type]
                _FailingSession(asyncio.CancelledError())
            )
        )


def test_wait_for_qr_scan_stops_at_deadline(monkeypatch) -> None:
    calls = 0

    async def _pending(session, qr):
        nonlocal calls
        calls += 1
        raise QRLoginPending

    monkeypatch.setattr(xiaomi_cloud, "poll_qr_login", _pending)

    with pytest.raises(CloudError, match="timed out"):
        asyncio.run(
            wait_for_qr_scan(  # type: ignore[arg-type]
                object(),
                _qr_login(),
                max_wait=0,
            )
        )
    assert calls == 1


def test_find_token_by_mac_accepts_valid_12_or_16_byte_hex() -> None:
    mac = "AA:BB:CC:DD:EE:FF"

    assert find_token_by_mac(
        [{"mac": "aa-bb-cc-dd-ee-ff", "token": TEST_TOKEN_HEX.upper()}],
        mac,
    ) == TEST_TOKEN_HEX
    assert find_token_by_mac(
        [{"mac": mac, "token": TEST_EXTENDED_TOKEN_HEX}],
        mac,
    ) == TEST_TOKEN_HEX


def test_find_token_by_mac_uses_valid_duplicate_record() -> None:
    mac = "AA:BB:CC:DD:EE:FF"

    assert find_token_by_mac(
        [
            {"mac": mac, "token": "not-a-token"},
            {"mac": mac, "token": TEST_TOKEN_HEX},
        ],
        mac,
    ) == TEST_TOKEN_HEX


@pytest.mark.parametrize(
    "token",
    ["001122", "00112233445566778899aabz", "00112233445566778899aabbccddeezz"],
)
def test_find_token_by_mac_rejects_invalid_cloud_token(token: str) -> None:
    with pytest.raises(CloudError, match="invalid|non-hex"):
        find_token_by_mac(
            [{"mac": "AA:BB:CC:DD:EE:FF", "token": token}],
            "AA:BB:CC:DD:EE:FF",
        )
