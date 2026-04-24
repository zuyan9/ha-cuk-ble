# tools/

CLI utilities for working with the AD1204U. Most scripts need the BLE pairing
token at `~/.cuktech_ble.token` (JSON `{"address": ..., "token_hex": ...}`).

All scripts run from the repo's `.venv`:

```bash
.venv/bin/python tools/<script>.py --help
```

## Scripts

| Script | Purpose |
|---|---|
| [`ad1204u_fetch_token.py`](ad1204u_fetch_token.py) | Fetch BLE pairing token from Xiaomi Cloud (password + email 2FA). No `micloud` dep — requires `pip install -e ".[cloud-token]"`. Writes `~/.cuktech_ble.token`. |
| [`ad1204u_read_props.py`](ad1204u_read_props.py) | One-shot: log in, send `get_properties`, print decoded per-port power + voltage + current + protocol. |
| [`sweep_logger.py`](sweep_logger.py) | Persistent BLE session with background KM003C reader. Samples both sources every N seconds, parses KM003C PD events for live contract labels, writes a jsonl log. |
| [`ad1204u_probe.py`](ad1204u_probe.py) | Log in and log every GATT notification for a fixed duration. Used for reverse-engineering new properties. |
| [`decrypt_btsnoop_miot.py`](decrypt_btsnoop_miot.py) | Android btsnoop + BLE token to decrypted MIOT CSV rows (`ts, opcode, siid, piid, value, status`). Used to turn Mi Home captures into property evidence. |
| [`tablet_unlock.sh`](tablet_unlock.sh) | Helper for the rooted capture tablet. Wakes the device and sends the known L-pattern via `sendevent`; accepts `-s DEVICE_ID`. |
| [`ad1204u_register.py`](ad1204u_register.py) | **Write path.** One-time binding for a factory-reset (unpaired) charger. Writes the 12-byte token + 16-byte bind_key + DID back to the token file. |
| [`ad1204u_register_probe.py`](ad1204u_register_probe.py) | Variant of `ad1204u_register.py` that only probes the pairing-mode handshake without actually binding. |
| [`ad1204u_adv_sniff.py`](ad1204u_adv_sniff.py) | Passive advertisement logger — dumps FE95 service data frames. No connection. |
| [`ad1204u_unauth_scan.py`](ad1204u_unauth_scan.py) | Scan + connect + enumerate GATT without logging in. Useful for firmware comparison. |
| [`btsnoop_att.py`](btsnoop_att.py) | Android btsnoop HCI log → filtered ATT stream for a given MAC. Source of every protocol decision in [`docs/protocol.md`](../docs/protocol.md). |
| [`mible_decrypt.py`](mible_decrypt.py) | Offline AES-CCM decrypt of captured Mi BLE session traffic, given the session keys reconstructed from btsnoop. |

## Offline MIOT capture decode

For a Mi Home capture pulled from the rooted Android tablet:

```bash
.venv/bin/python tools/decrypt_btsnoop_miot.py /tmp/btsnoop.log \
    --mac AA:BB:CC:DD:EE:FF \
    --token 00112233445566778899aabb
```

The script writes CSV to stdout. It assumes the AD1204U handles currently
documented in [`docs/protocol.md`](../docs/protocol.md): auth on `0x0010`,
MIOT write on `0x0019`, and MIOT notify on `0x001c`. If a firmware changes
handles, pass `--auth-handle`, `--miot-write-handle`, or
`--miot-notify-handle`.

`tablet_unlock.sh` defaults to the local bench tablet id (`HA1R80YR`). Use
`tools/tablet_unlock.sh -s <adb-device-id>` for another attached device. If
Android moves the lock-pattern view, override the raw touch path with
`PATTERN_POINTS="x,y x,y x,y x,y"`.

## Safety

- Only `ad1204u_register.py` performs control-plane BLE writes that touch
  the charger's pairing state. Every other tool here reads only; the
  HA integration itself can issue `set_properties` writes (switches +
  scene-mode select).
- Mi Home can't be connected at the same time as these tools. Force-close
  it on the phone before running.
- `tablet_unlock.sh` sends touch input to the Android tablet only. It does
  not talk to the charger.
