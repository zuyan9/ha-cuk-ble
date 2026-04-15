# CUKTECH BLE — integration folder

This is the Home Assistant integration itself. User-facing docs (installation,
setup, options, screenshots) live in the
[repo-root README](../../README.md).

Files here:

| File | Purpose |
|---|---|
| `manifest.json` | HA integration metadata (domain, version, requirements) |
| `__init__.py` | Entry setup, device-registry seeding, platform forwarding |
| `config_flow.py` | Setup flow (Mi-Cloud QR login + manual token path) |
| `coordinator.py` | BLE session manager + polling + idle-release |
| `sensor.py` / `binary_sensor.py` | Entity descriptions |
| `diagnostics.py` | Redacted diagnostics dump |
| `translations/` | UI strings |
| `brand/` | Icon + logo served via the HA brands proxy API |
| `lib/` | Pure-Python library code (BLE transport, MIOT encode/decode, port-word decode). Reusable outside HA. |

See [`../../docs/`](../../docs/) for protocol notes and
[`../../tools/`](../../tools/) for CLI helpers.
