# Usage

## Getting the BLE token

Easiest: use the **Mi Cloud (QR)** option in the config flow. It's a one-shot
fetch — no password, no stored credentials, and the integration never talks
to Mi Cloud again after setup.

If you'd rather grab the token outside Home Assistant:

```bash
python -m venv .venv
.venv/bin/pip install -e ".[cloud-token]"
.venv/bin/python tools/ad1204u_fetch_token.py \
    --username you@example.com \
    --address AA:BB:CC:DD:EE:FF \
    --server cn
```

The script handles 2FA interactively and writes `~/.cuktech_ble.token`.
[Xiaomi-cloud-tokens-extractor](https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor)
works as well — paste the 24-character hex into the manual path of the
config flow.

## Entities

One parent device per charger, with a sub-device per port (C1, C2, C3, A).
All sub-devices inherit the parent's area.

Per port: **power** (W), **voltage** (V), **current** (A), **protocol**
(diagnostic), **PDO cap** (W, diagnostic). There's also a charger-level
**total power** sensor.

Charger-level controls (on the parent device):

- **Scene mode** (select): AI Mode / Hybrid / Single / Dual.
- **USB-A always on** (switch): keeps the USB-A rail energized.
- **Screen off when idle** (switch): charger display auto-sleeps.
- **Lock screen orientation** (switch): disables display auto-rotate.

## Options

**Settings → Devices & services → CUKTECH BLE → Configure**:

| Option | Default | Range | Meaning |
|---|---|---|---|
| Polling interval | 30 s | 5–3600 | BLE read cadence |
| Idle release | 300 s | 0–3600 | Disconnect after this long with no poll (`0` = stay connected) |
| Connection timeout | 15 s | 5–120 | How long to wait for a BLE connect |
| BlueZ `start-notify` hint | off | — | Linux-only workaround for CCCD flakiness |

## Notes and limits

- **Writable controls:** USB-A always on, screen-off when idle, lock screen
  orientation, scene mode. More will be added as we reverse additional
  settings (per-port protocol masks are still pending).
- **One BLE peer at a time.** If Mi Home is connected on your phone, HA can't
  talk to the charger. Force-close Mi Home if you see connect timeouts.
- **Diagnostics** (Device page → ⋮ → Download diagnostics) redacts the token
  and MAC.

## Supported device

| | |
|---|---|
| Model | CUKTECH AD1204U "10 GaN Charger Ultra" |
| Mijia name | `njcuk.fitting.ad1204` |
| Mijia product id | `0x660E` |
| Service UUID | `0000fe95-0000-1000-8000-00805f9b34fb` |
