"""Fetch the AD1204U BLE token from the Xiaomi cloud.

Standalone re-implementation of the Mi Home cloud login + device-list flow
(adapted from https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor).
No ``micloud`` dependency — only ``requests`` is required at runtime.

Supports password login with email-based 2FA fallback (the flow Mi Home uses
when the account has two-factor verification enabled, which is the norm for
accounts that pair BLE devices).

Usage:
    .venv/bin/python tools/ad1204u_fetch_token.py \\
        --username you@example.com --address AA:BB:CC:DD:EE:FF [--server cn]

Password is read from ``XIAOMI_PASSWORD`` or prompted. If the account has
2FA, you will be prompted for the email code interactively.

Writes ``~/.cuktech_ble.token`` as JSON ``{"address": ..., "token_hex": ...}``.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import random
import string
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    print("This tool needs 'requests'. Install with: pip install requests", file=sys.stderr)
    sys.exit(2)


SERVERS = ("cn", "de", "us", "ru", "tw", "sg", "in", "i2")
USER_AGENT = (
    "Android-7.1.1-1.0.0-ONEPLUS A3010-136-"
    "%s APP/xiaomi.smarthome APPV/62830"
) % "".join(random.choices(string.ascii_uppercase, k=13))


def _normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").lower()


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
    # Xiaomi drops the first 1024 bytes of keystream.
    for _ in range(1024):
        next(ks)
    return bytes(b ^ next(ks) for b in data)


def _rc4_encrypt_b64(password_b64: str, payload: str) -> str:
    key = base64.b64decode(password_b64)
    return base64.b64encode(_rc4_xor(key, payload.encode())).decode()


def _rc4_decrypt_b64(password_b64: str, payload_b64: str) -> bytes:
    key = base64.b64decode(password_b64)
    return _rc4_xor(key, base64.b64decode(payload_b64))


def _to_json(text: str) -> dict[str, Any]:
    return json.loads(text.replace("&&&START&&&", ""))


class CloudError(Exception):
    pass


class Cloud:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.device_id = "".join(random.choices(string.ascii_letters, k=16))
        self.agent = USER_AGENT
        for domain in ("mi.com", "xiaomi.com"):
            self.session.cookies.set("sdkVersion", "accountsdk-18.8.15", domain=domain)
            self.session.cookies.set("deviceId", self.device_id, domain=domain)
        self._sign: str | None = None
        self._ssecurity: str | None = None
        self._service_token: str | None = None
        self._user_id: str | None = None
        self._cuser_id: str | None = None
        self._pass_token: str | None = None
        self._location: str | None = None

    def login(self, username: str, password: str) -> None:
        if not self._step1(username):
            raise CloudError("invalid username (step 1 failed)")
        if not self._step2(username, password):
            raise CloudError("invalid password or 2FA failed (step 2)")
        if self._location and not self._service_token and not self._step3():
            raise CloudError("unable to fetch serviceToken (step 3)")

    def _step1(self, username: str) -> bool:
        url = "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
        r = self.session.get(
            url,
            headers={"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"},
            cookies={"userId": username},
        )
        if r.status_code != 200:
            return False
        j = _to_json(r.text)
        if "_sign" in j:
            self._sign = j["_sign"]
            return True
        if "ssecurity" in j:
            self._load_success(j)
            return True
        return False

    def _load_success(self, j: dict[str, Any]) -> None:
        self._ssecurity = j["ssecurity"]
        self._user_id = j.get("userId")
        self._cuser_id = j.get("cUserId")
        self._pass_token = j.get("passToken")
        self._location = j.get("location")

    def _step2(self, username: str, password: str) -> bool:
        url = "https://account.xiaomi.com/pass/serviceLoginAuth2"
        fields = {
            "sid": "xiaomiio",
            "hash": hashlib.md5(password.encode()).hexdigest().upper(),
            "callback": "https://sts.api.io.mi.com/sts",
            "qs": "%3Fsid%3Dxiaomiio%26_json%3Dtrue",
            "user": username,
            "_sign": self._sign or "",
            "_json": "true",
        }
        r = self.session.post(
            url,
            headers={"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"},
            params=fields,
            allow_redirects=False,
        )
        if r.status_code != 200:
            return False
        j = _to_json(r.text)
        if "ssecurity" in j and len(str(j["ssecurity"])) > 4:
            self._load_success(j)
            return True
        if "notificationUrl" in j:
            return self._do_2fa(j["notificationUrl"])
        return False

    def _step3(self) -> bool:
        r = self.session.get(
            self._location,
            headers={"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code != 200:
            return False
        self._service_token = r.cookies.get("serviceToken")
        return bool(self._service_token)

    def _do_2fa(self, notification_url: str) -> bool:
        headers = {"User-Agent": self.agent, "Content-Type": "application/x-www-form-urlencoded"}
        self.session.get(notification_url, headers=headers)
        context = parse_qs(urlparse(notification_url).query)["context"][0]
        self.session.get(
            "https://account.xiaomi.com/identity/list",
            params={"sid": "xiaomiio", "context": context, "_locale": "en_US"},
            headers=headers,
        )
        self.session.post(
            "https://account.xiaomi.com/identity/auth/sendEmailTicket",
            params={
                "_dc": str(int(time.time() * 1000)),
                "sid": "xiaomiio",
                "context": context,
                "mask": "0",
                "_locale": "en_US",
            },
            data={
                "retry": "0",
                "icode": "",
                "_json": "true",
                "ick": self.session.cookies.get("ick", ""),
            },
            headers=headers,
        )

        print("2FA required — enter the code sent to your Xiaomi account email:", file=sys.stderr)
        code = input("code: ").strip()

        r = self.session.post(
            "https://account.xiaomi.com/identity/auth/verifyEmail",
            params={
                "_flag": "8",
                "_json": "true",
                "sid": "xiaomiio",
                "context": context,
                "mask": "0",
                "_locale": "en_US",
            },
            data={
                "_flag": "8",
                "ticket": code,
                "trust": "false",
                "_json": "true",
                "ick": self.session.cookies.get("ick", ""),
            },
            headers=headers,
        )
        if r.status_code != 200:
            return False
        try:
            finish_loc = r.json().get("location")
        except ValueError:
            finish_loc = None
        if not finish_loc:
            r0 = self.session.get(
                "https://account.xiaomi.com/identity/result/check",
                params={"sid": "xiaomiio", "context": context, "_locale": "en_US"},
                headers=headers,
                allow_redirects=False,
            )
            if r0.status_code in (301, 302):
                finish_loc = r0.headers.get("Location") or r0.url
        if not finish_loc:
            return False

        if "identity/result/check" in finish_loc:
            r = self.session.get(finish_loc, headers=headers, allow_redirects=False)
            end_url = r.headers.get("Location")
        else:
            end_url = finish_loc
        if not end_url:
            return False

        r = self.session.get(end_url, headers=headers, allow_redirects=False)
        if r.status_code == 200 and "Xiaomi Account - Tips" in r.text:
            r = self.session.get(end_url, headers=headers, allow_redirects=False)
        ext = r.headers.get("extension-pragma")
        if ext:
            try:
                self._ssecurity = json.loads(ext).get("ssecurity") or self._ssecurity
            except ValueError:
                pass
        if not self._ssecurity:
            return False

        sts_url = r.headers.get("Location")
        if not sts_url and r.text:
            idx = r.text.find("https://sts.api.io.mi.com/sts")
            if idx != -1:
                end = r.text.find('"', idx)
                sts_url = r.text[idx:end if end != -1 else idx + 300]
        if not sts_url:
            return False
        r = self.session.get(sts_url, headers=headers, allow_redirects=True)
        if r.status_code != 200:
            return False
        self._service_token = self.session.cookies.get("serviceToken", domain=".sts.api.io.mi.com")
        if not self._service_token:
            return False
        for domain in (".api.io.mi.com", ".io.mi.com", ".mi.com"):
            self.session.cookies.set("serviceToken", self._service_token, domain=domain)
            self.session.cookies.set("yetAnotherServiceToken", self._service_token, domain=domain)
        self._user_id = self._user_id or self.session.cookies.get("userId", domain=".xiaomi.com")
        self._cuser_id = self._cuser_id or self.session.cookies.get("cUserId", domain=".xiaomi.com")
        return True

    def _api_base(self, country: str) -> str:
        return "https://" + ("" if country == "cn" else country + ".") + "api.io.mi.com/app"

    def _signed_nonce(self, nonce_b64: str) -> str:
        digest = hashlib.sha256(
            base64.b64decode(self._ssecurity) + base64.b64decode(nonce_b64)
        ).digest()
        return base64.b64encode(digest).decode()

    def _enc_signature(self, url: str, method: str, signed_nonce: str, params: dict[str, str]) -> str:
        parts = [method.upper(), url.split("com")[1].replace("/app/", "/")]
        parts.extend(f"{k}={v}" for k, v in params.items())
        parts.append(signed_nonce)
        return base64.b64encode(hashlib.sha1("&".join(parts).encode()).digest()).decode()

    def _encrypted_post(self, country: str, path: str, data: str) -> dict[str, Any]:
        url = self._api_base(country) + path
        params = {"data": data}
        millis = int(time.time() * 1000)
        nonce_bytes = os.urandom(8) + (millis // 60000).to_bytes(4, "big")
        nonce = base64.b64encode(nonce_bytes).decode()
        signed_nonce = self._signed_nonce(nonce)

        params["rc4_hash__"] = self._enc_signature(url, "POST", signed_nonce, params)
        for k, v in params.items():
            params[k] = _rc4_encrypt_b64(signed_nonce, v)
        params["signature"] = self._enc_signature(url, "POST", signed_nonce, params)
        params["ssecurity"] = self._ssecurity
        params["_nonce"] = nonce

        r = self.session.post(
            url,
            headers={
                "Accept-Encoding": "identity",
                "User-Agent": self.agent,
                "Content-Type": "application/x-www-form-urlencoded",
                "x-xiaomi-protocal-flag-cli": "PROTOCAL-HTTP2",
                "MIOT-ENCRYPT-ALGORITHM": "ENCRYPT-RC4",
            },
            cookies={
                "userId": str(self._user_id),
                "serviceToken": str(self._service_token),
                "yetAnotherServiceToken": str(self._service_token),
                "locale": "en_GB",
                "timezone": "GMT+00:00",
                "is_daylight": "0",
                "dst_offset": "0",
                "channel": "MI_APP_STORE",
            },
            params=params,
        )
        if r.status_code != 200:
            raise CloudError(f"{path}: HTTP {r.status_code}")
        decoded = _rc4_decrypt_b64(self._signed_nonce(nonce), r.text)
        return json.loads(decoded)

    def list_devices(self, country: str) -> list[dict[str, Any]]:
        resp = self._encrypted_post(
            country,
            "/home/device_list",
            '{"getVirtualModel":true,"getHuamiDevices":1}',
        )
        result = (resp or {}).get("result") or {}
        return result.get("list") or []


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--username", required=True)
    parser.add_argument("--address", required=True, help="BLE MAC of the AD1204U")
    parser.add_argument("--server", default="cn", choices=SERVERS)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path.home() / ".cuktech_ble.token",
    )
    args = parser.parse_args()

    password = os.environ.get("XIAOMI_PASSWORD") or getpass.getpass(
        f"Xiaomi password for {args.username}: "
    )

    cloud = Cloud()
    try:
        cloud.login(args.username, password)
    except CloudError as exc:
        print(f"login failed: {exc}", file=sys.stderr)
        return 1

    try:
        devices = cloud.list_devices(args.server)
    except CloudError as exc:
        print(f"device list failed: {exc}", file=sys.stderr)
        return 1

    target = _normalize_mac(args.address)
    for dev in devices:
        if _normalize_mac(str(dev.get("mac", ""))) != target:
            continue
        token = str(dev.get("token", "")).strip().lower()
        if len(token) not in (24, 32):
            print(f"unexpected token length {len(token)}: {token}", file=sys.stderr)
            return 1
        token_hex = token[:24]
        args.output.write_text(
            json.dumps({"address": args.address, "token_hex": token_hex}) + "\n"
        )
        args.output.chmod(0o600)
        print(f"wrote {args.output} (token: {token_hex})")
        return 0

    print(
        f"no device matching {args.address} in {args.server} cloud; "
        f"listed MACs: " + ", ".join(str(d.get("mac", "?")) for d in devices),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
