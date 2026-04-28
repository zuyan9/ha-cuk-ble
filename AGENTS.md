# OpenCode Agent Instructions

This repository contains a Home Assistant integration for the CUKTECH AD1204U BLE charger, alongside reverse-engineering tools and testing scripts.

## Repository Structure

- `custom_components/cuktech_ble/`: The Home Assistant integration codebase.
- `custom_components/cuktech_ble/lib/`: Core BLE protocol implementation. This is deliberately vendored inside the integration so Home Assistant doesn't require an external PyPI dependency.
- `tools/`: Standalone scripts for direct BLE testing, decrypting btsnoop logs, and controlling the testing environment.
- `tests/`: Pytest suite covering the protocol library and integration logic.
- `.claude/TestInstructions.md`: Detailed environment configuration, device IPs, tokens, and reversing notes. Read this for deep-dives into protocol reversing.

## Development & Testing

- **Testing:** You MUST run tests with the current directory in the Python path to correctly resolve imports between `tests/`, `tools/`, and the integration:
  ```bash
  PYTHONPATH=. pytest
  ```

## Hardware Constraints & Connection Handoff

The CUKTECH AD1204U charger only supports **one active BLE connection at a time**. There are three potential clients in this environment:
1. The remote Home Assistant instance (polls periodically)
2. The local Raspberry Pi (running `tools/`)
3. The rooted Android tablet (running the Mi Home app)

If a script hangs or fails to connect, another client is likely holding the connection. Use these handoff procedures:

**To free the charger for Pi tools (`tools/*.py`):**
```bash
.venv/bin/python tools/disable_ha_proper.py
adb -s HA1R80YR shell 'su -c "am force-stop com.xiaomi.smarthome"'
pkill -f python || true
bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth
sleep 1 && bluetoothctl -- power on && sleep 2
```

**To free the charger for Tablet capture (Mi Home):**
```bash
.venv/bin/python tools/disable_ha_proper.py
pkill -f python || true
bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth
sleep 1 && bluetoothctl -- power on && sleep 2
```

**To return control to Home Assistant:**
```bash
adb -s HA1R80YR shell 'su -c "am force-stop com.xiaomi.smarthome"'
pkill -f python || true
bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
.venv/bin/python tools/enable_ha_proper.py
```

## Troubleshooting BLE

- **"not advertising" / "Device not found" on Pi:** BlueZ is holding a phantom session or is stuck in a passive scanning loop. Flush it:
  ```bash
  bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 && bluetoothctl -- remove 3C:CD:73:2B:1B:88
  ```
- **"org.bluez.Error.Busy" / "org.bluez.Error.InProgress":** The Bluetooth adapter is crashed or multiple scripts are trying to scan/connect simultaneously. Perform a hard reset of the adapter:
  ```bash
  pkill -f python
  sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth && sleep 1 && bluetoothctl -- power on
  ```
