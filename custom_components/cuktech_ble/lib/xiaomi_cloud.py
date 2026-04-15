"""Async Xiaomi cloud client (QR-code login, device list).

Adapted from https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor.
QR-login only — no password/2FA paths.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import string
import time
from dataclasses import dataclass, field
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

SERVERS: tuple[str, ...] = ("cn", "de", "us", "ru", "tw", "sg", "in", "i2")

_USER_AGENT = (
    "Android-7.1.1-1.0.0-ONEPLUS A3010-136-"
    "%s APP/xiaomi.smarthome APPV/62830"
)


def _fresh_user_agent() -> str:
    return _USER_AGENT % "".join(random.choices(string.ascii_uppercase, k=13))


def _rc4_keystream(key: bytes):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    while True:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) & 0xFF]


def _rc4_xor(key: bytes, data: bytes) -> bytes:
    ks = _rc4_keystream(key)
    for _ in range(1024):
        next(ks)
    return bytes(b ^ next(ks) for b in data)


def _rc4_encrypt_b64(key_b64: str, payload: str) -> str:
    return base64.b64encode(
        _rc4_xor(base64.b64decode(key_b64), payload.encode())
    ).decode()


def _rc4_decrypt_b64(key_b64: str, payload_b64: str) -> bytes:
    return _rc4_xor(base64.b64decode(key_b64), base64.b64decode(payload_b64))


def _strip_jsonp(text: str) -> dict[str, Any]:
    return json.loads(text.replace("&&&START&&&", "").strip())


class CloudError(Exception):
    """Raised for any Xiaomi cloud error."""


class QRLoginPending(Exception):
    """QR scan still pending — caller should retry."""


@dataclass
class QRLogin:
    """State carried between starting the QR login and polling for approval."""

    qr_image_url: str
    login_url: str
    lp_url: str
    timeout_seconds: int
    device_id: str
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class CloudAuth:
    """Resolved Xiaomi cloud credentials after successful QR scan."""

    user_id: str
    cuser_id: str
    ssecurity: str
    pass_token: str
    service_token: str
    device_id: str


def _cookies_for(device_id: str) -> dict[str, str]:
    return {
        "sdkVersion": "accountsdk-18.8.15",
        "deviceId": device_id,
    }


async def start_qr_login(session: aiohttp.ClientSession) -> QRLogin:
    """Request a QR-code login URL. Show ``qr_image_url`` to the user."""
    device_id = "".join(random.choices(string.ascii_letters, k=16))
    cookies = _cookies_for(device_id)
    url = "https://account.xiaomi.com/longPolling/loginUrl"
    params = {
        "_qrsize": "480",
        "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
        "bizDeviceType": "",
        "callback": "https://sts.api.io.mi.com/sts",
        "_hasLogo": "false",
        "theme": "",
        "needTheme": "false",
        "showActiveX": "false",
        "serviceParam": '{"checkSafePhone":false,"checkSafeAddress":false,"lsrp_score":0.0}',
        "sid": "xiaomiio",
        "_locale": "en_GB",
        "_dc": str(int(time.time() * 1000)),
    }
    headers = {"User-Agent": _fresh_user_agent()}
    async with session.get(url, params=params, headers=headers, cookies=cookies) as r:
        text = await r.text()
        if r.status != 200:
            raise CloudError(f"QR login request failed: HTTP {r.status}")
    try:
        data = _strip_jsonp(text)
    except ValueError as exc:
        raise CloudError(f"QR login response not JSON: {exc}") from exc
    try:
        return QRLogin(
            qr_image_url=data["qr"],
            login_url=data.get("loginUrl", ""),
            lp_url=data["lp"],
            timeout_seconds=int(data.get("timeout", 300)),
            device_id=device_id,
            cookies=cookies,
        )
    except KeyError as exc:
        raise CloudError(f"QR login response missing {exc}") from exc


async def poll_qr_login(session: aiohttp.ClientSession, qr: QRLogin) -> CloudAuth:
    """Poll the long-polling URL once; returns CloudAuth on success.

    Raises ``QRLoginPending`` if the user has not scanned/approved yet.
    Raises ``CloudError`` if the login endpoint returns a terminal error.
    """
    headers = {"User-Agent": _fresh_user_agent()}
    try:
        async with session.get(
            qr.lp_url,
            headers=headers,
            cookies=qr.cookies,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as r:
            text = await r.text()
            status = r.status
    except asyncio.TimeoutError as exc:
        raise QRLoginPending() from exc

    try:
        data = _strip_jsonp(text)
    except ValueError as exc:
        raise CloudError(f"QR poll response not JSON: {exc}") from exc

    code = data.get("code")
    if code in (401, 700, 70016):
        raise QRLoginPending()
    if code not in (0, None):
        raise CloudError(f"QR login failed: code={code} desc={data.get('desc')}")
    if "ssecurity" not in data:
        raise QRLoginPending()

    location = data.get("location")
    if not location:
        raise CloudError("QR login missing location")

    async with session.get(
        location,
        headers=headers,
        cookies=qr.cookies,
        allow_redirects=True,
    ) as r2:
        service_token = None
        for cookie in session.cookie_jar:
            if cookie.key == "serviceToken":
                service_token = cookie.value
                break
    if not service_token:
        raise CloudError("serviceToken cookie not set after location fetch")

    return CloudAuth(
        user_id=str(data.get("userId", "")),
        cuser_id=str(data.get("cUserId", "")),
        ssecurity=str(data["ssecurity"]),
        pass_token=str(data.get("passToken", "")),
        service_token=str(service_token),
        device_id=qr.device_id,
    )


async def wait_for_qr_scan(
    session: aiohttp.ClientSession,
    qr: QRLogin,
    *,
    max_wait: float | None = None,
) -> CloudAuth:
    """Long-poll until the user scans and approves, or ``max_wait`` elapses."""
    deadline = time.monotonic() + (max_wait if max_wait is not None else qr.timeout_seconds)
    while True:
        try:
            return await poll_qr_login(session, qr)
        except QRLoginPending:
            if time.monotonic() >= deadline:
                raise CloudError("QR login timed out") from None
            await asyncio.sleep(1.0)


def _api_base(region: str) -> str:
    return "https://" + ("" if region == "cn" else region + ".") + "api.io.mi.com/app"


def _signed_nonce(ssecurity: str, nonce_b64: str) -> str:
    digest = hashlib.sha256(
        base64.b64decode(ssecurity) + base64.b64decode(nonce_b64)
    ).digest()
    return base64.b64encode(digest).decode()


def _enc_signature(
    url: str, method: str, signed_nonce: str, params: dict[str, str]
) -> str:
    parts = [method.upper(), url.split("com")[1].replace("/app/", "/")]
    parts.extend(f"{k}={v}" for k, v in params.items())
    parts.append(signed_nonce)
    return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()


async def _encrypted_post(
    session: aiohttp.ClientSession,
    auth: CloudAuth,
    region: str,
    path: str,
    data: str,
) -> dict[str, Any]:
    url = _api_base(region) + path
    params = {"data": data}
    millis = int(time.time() * 1000)
    nonce_bytes = os.urandom(8) + (millis // 60000).to_bytes(4, "big")
    nonce = base64.b64encode(nonce_bytes).decode()
    signed_nonce = _signed_nonce(auth.ssecurity, nonce)

    params["rc4_hash__"] = _enc_signature(url, "POST", signed_nonce, params)
    for k, v in params.items():
        params[k] = _rc4_encrypt_b64(signed_nonce, v)
    params["signature"] = _enc_signature(url, "POST", signed_nonce, params)
    params["ssecurity"] = auth.ssecurity
    params["_nonce"] = nonce

    headers = {
        "Accept-Encoding": "identity",
        "User-Agent": _fresh_user_agent(),
        "Content-Type": "application/x-www-form-urlencoded",
        "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
        "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
    }
    cookies = {
        "userId": auth.user_id,
        "serviceToken": auth.service_token,
        "yetAnotherServiceToken": auth.service_token,
        "locale": "en_GB",
        "timezone": "GMT+00:00",
        "is_daylight": "0",
        "dst_offset": "0",
        "channel": "MI_APP_STORE",
    }
    async with session.post(url, headers=headers, cookies=cookies, params=params) as r:
        text = await r.text()
        if r.status != 200:
            raise CloudError(f"{path}: HTTP {r.status}")
    try:
        decoded = _rc4_decrypt_b64(_signed_nonce(auth.ssecurity, nonce), text)
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError) as exc:
        raise CloudError(f"{path}: decrypt/parse failed: {exc}") from exc


async def list_devices(
    session: aiohttp.ClientSession,
    auth: CloudAuth,
    region: str,
) -> list[dict[str, Any]]:
    """Return raw device records for the given region."""
    resp = await _encrypted_post(
        session,
        auth,
        region,
        "/home/device_list",
        '{"getVirtualModel":true,"getHuamiDevices":1}',
    )
    return ((resp or {}).get("result") or {}).get("list") or []


def normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


def find_token_by_mac(devices: list[dict[str, Any]], mac: str) -> str | None:
    """Find a device by MAC and return the 24-hex-char (12-byte) BLE bindkey."""
    target = normalize_mac(mac)
    for dev in devices:
        if normalize_mac(str(dev.get("mac", ""))) != target:
            continue
        token = str(dev.get("token", "")).strip().lower()
        if len(token) in (24, 32):
            return token[:24]
    return None
