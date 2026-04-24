# CUKTECH BLE for Home Assistant

Local Home Assistant integration for the **CUKTECH AD1204U "10 GaN Charger
Ultra"**. Reads per-port power, voltage, current, and protocol over BLE, and
exposes a small set of charger settings (scene mode, USB-A always on,
screen toggles) as HA controls — no cloud polling, no outbound traffic.

[![Open in HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=zuyan9&repository=ha-cuk-ble&category=integration)
[![Add integration](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=cuktech_ble)

## Install

1. Click **Open in HACS** above (or add this repo as an Integration custom
   repository in HACS), install, and restart Home Assistant.
2. Click **Add integration** above, pick **CUKTECH BLE**, and either:
   - log in with the Mi Cloud QR flow to fetch the BLE pairing token, or
   - paste an existing 24-character hex token.

That's it — HA creates one device per charger with sensors for each port.

## More

- [Usage, options, and getting the token manually](docs/usage.md)
- [Protocol notes and reverse-engineering](docs/reverse-engineering.md)
- [Issues / PRs](https://github.com/zuyan9/ha-cuk-ble/issues)

Unofficial; not affiliated with CUKTECH or Xiaomi.
