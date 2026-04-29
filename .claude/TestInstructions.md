# Test instructions and debugging plan

_Keep this file current — update it as environment details change or tasks
close. Claude should refresh it whenever a task state changes or a new
constraint is discovered._

Never commit as Calude, only commit as Zuyang.

## Environments

- **HA instance:** 192.168.1.199:8123, username `Zuyang`, password
  `vier11man8`. Integration is currently loaded on HA; disable/unload it
  before Pi-side BLE tests, then reload afterward. Long-lived access token: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiI2MzdlNjUyYzkzOTU0M2RkODY4NTI1ZGExZjA3Y2JlOCIsImlhdCI6MTc3NzAwNTY0MywiZXhwIjoyMDkyMzY1NjQzfQ.GwBVDGRBDqLX9hj3WnQnSWEyS3cbxUAJorwD4V37YOY`.
- **Raspberry Pi (this host):** runs the integration source, the Python
  tools, tshark, and adb. Scripts live under `tools/`.
- **Rooted Android tablet (BT capture + UI automation):** Lenovo TB132FU
  (Legion Tab) running Android 14, Magisk with Shell granted root.
  - ADB device id: `HA1R80YR`.
  - androiddump extcap: `android-bluetooth-btsnoop-net-HA1R80YR`.
  - Mi Home (`com.xiaomi.smarthome`) installed; user is logged in.
  - Unlock pattern: **L shape starting from top-middle** (dots 1→4→7→8
    on the 3×3 grid). `tools/` has no unlock script yet; the `sendevent`
    sequence we used lives in this file's history under git log
    `4ed0c1c` if we need to re-run it.
  - Enable full snoop (post-reboot, settings survive BT cycles):
    ```
    adb shell 'su -c "setprop persist.bluetooth.btsnooplogmode full; \
                      setprop persist.bluetooth.btsnoopdefaultmode full; \
                      device_config put bluetooth com.android.bluetooth.flags.snoop_logger_filtering false; \
                      cmd bluetooth_manager disable"'
    # wait ~3s
    adb shell 'su -c "cmd bluetooth_manager enable"'
    ```
  - btsnoop log file: `/data/misc/bluetooth/logs/btsnoop_hci.log`
    (`su -c cat` to dump).
  - Mi Home sets FLAG_SECURE on some activities; `screencap` returns
    black for those. Root-level `su -c screencap` works for lockscreen
    but not always for in-app content. Use `uiautomator dump` to read
    text/bounds when pixels are unavailable.
- **Power-Z KM003C:** USB-C meter on USB (VID/PID `5fc9:0063`). Reads via
  pyusb on vendor bulk (IF0, EP1 OUT / 0x81 IN). 52-byte ADC response;
  payload starts at offset +8, layout: `<i i i i ...` → vbus_uV, ibus_uA,
  vbus_avg_uV, ibus_avg_uA, then temperatures and CC voltages.
  - Udev rule: `/etc/udev/rules.d/53-km003c.rules`.
  - CDC ACM driver claims IF1/IF2 — only claim interface 0 in pyusb and
    **don't call `set_configuration`** (returns "Resource busy").
- **Power-Z SINK240:** PD trigger board, **manual button control** — user
  drives contracts, Pi reads after each preset.
- **CUKTECH AD1204U charger:** BLE MAC `3C:CD:73:2B:1B:88`. **One peer at a
  time.** Three potential clients on this LAN:
    1. **HA instance** (`192.168.1.199`) — polls every ~30 s via the integration.
    2. **Raspberry Pi** (this host) — runs the CLI tools, sweep_logger,
       direct-Pi tests.
    3. **Tablet Mi Home** (Lenovo TB132FU) — used for capture / manual UI.

  Only one holds the BLE link at any moment; the other two see "Offline"
  or "not advertising". Ownership-handoff cheatsheet below.

  ### Hand off → Tablet (for Mi Home capture)

  ```bash
  # Free HA: disable the config entry so polling stops via WebSocket script.
  .venv/bin/python tools/disable_ha_proper.py

  # Free Pi: disconnect, remove cache, and completely reset the adapter 
  # to prevent org.bluez.Error.InProgress and org.bluez.Error.Busy errors.
  bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
  bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
  sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth
  sleep 1 && bluetoothctl -- power on && sleep 2
  
  # Tablet now wins the next reconnect.
  # (Optional: If tablet still refuses to connect, force restart its BT stack):
  # adb -s HA1R80YR shell 'su -c "cmd bluetooth_manager disable && sleep 2 && cmd bluetooth_manager enable"'
  ```

  ### Hand off → Pi (for sweep_logger / direct tests)

  ```bash
  # Free HA: same disable step as above.
  .venv/bin/python tools/disable_ha_proper.py

  # Free tablet: completely kill Mi Home so background services release the link.
  adb -s HA1R80YR shell 'su -c "am force-stop com.xiaomi.smarthome"'

  # Free Pi: make sure Bluetooth radio is clean and not stuck.
  pkill -f python || true
  bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
  bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
  sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth
  sleep 1 && bluetoothctl -- power on && sleep 2
  
  # Run tools normally; they scan + connect.
  ```

  ### Hand off → HA (return to normal)

  ```bash
  # Free Pi: disconnect any open Bleak session.
  pkill -f python || true
  bluetoothctl -- disconnect 3C:CD:73:2B:1B:88 || true
  bluetoothctl -- remove 3C:CD:73:2B:1B:88 || true
  
  # Free tablet: kill Mi Home so it doesn't auto-grab.
  adb -s HA1R80YR shell 'su -c "am force-stop com.xiaomi.smarthome"'
  
  # Re-enable HA entry; HA reconnects on next poll via WebSocket.
  .venv/bin/python tools/enable_ha_proper.py
  ```

  ### Failure modes

  - **"not advertising" / "Device not found" from Pi**: BlueZ holds a phantom session
    or is stuck in passive scanning. `bluetoothctl -- disconnect <MAC>` then `remove <MAC>`
    flushes its cache.
  - **Pi `rfkill` left soft-blocked / `org.bluez.Error.Busy`**: The adapter has crashed
    or been soft-blocked during aggressive testing. Run `sudo rfkill block bluetooth && sleep 1 && sudo rfkill unblock bluetooth && sleep 1 && bluetoothctl -- power on` to reset the entire stack.
  - **`BleakDBusError: org.bluez.Error.InProgress`**: Multiple scanners or connection attempts are fighting for the radio. Run `pkill -f python` and the rfkill reset sequence above.
  - **Stuck after disconnect**: a few firmware revisions hold the
    advertising-stop state until a power cycle. Unplug charger ~10 s
    and replug — last-resort reset.

## Live captures

```bash
# Tablet (rooted, full ACL/ATT — this is the live capture path for MIOT traffic)
tshark -i android-bluetooth-btsnoop-net-HA1R80YR -w /tmp/bt.pcap

# Then pull the unfiltered btsnoop file for offline decrypt (usually cleaner
# than the live-stream pcap because tshark's pcapng needs conversion before
# tools/btsnoop_att.py can read it):
adb -s HA1R80YR shell 'su -c "cat /data/misc/bluetooth/logs/btsnoop_hci.log"' \
    > /tmp/btsnoop.log
.venv/bin/python tools/btsnoop_att.py /tmp/btsnoop.log --mac 3C:CD:73:2B:1B:88
```

On Android 14, `btsnoop_hci.log` may be all zeroes after manual truncation. If
that happens, pull the latest `BT_HCI_*.cfa.curf` file instead; it can still be
plain btsnoop format despite the `.cfa.curf` suffix:

```bash
adb -s HA1R80YR shell 'su -c "ls -lt /data/misc/bluetooth/logs/BT_HCI_*"'
adb -s HA1R80YR shell 'su -c "cat /data/misc/bluetooth/logs/BT_HCI_YYYY_MMDD_HHMMSS.cfa.curf"' \
    > /tmp/btsnoop.log
```

Related udev rule: `/etc/udev/rules.d/53-km003c.rules` for the KM003C
(VID/PID `5fc9:0063`).

## Open tasks

### 1. C1/C2 PDO decode table — Track A, SINK240 sweep (closed 2026-04-23)

Done via `tools/sweep_logger.py` with SINK240 stepping PD Fixed
5/9/12/15/20 V and two PPS bands on C1 while KM003C gave ground truth.

Findings:
- `cap_byte = watts` (decimal). Old hardcoded dict replaced in
  `lib/ports.py`; new formula handles any wattage.
- `high_byte` encodes the PDO kind: `0x07` = Fixed, `0x08` = PPS.
- `b1 = 0x0a` for every PD contract under the SINK240's near-zero load;
  `b1` alone can't distinguish Fixed from PPS.

Still open: `b1` under real current (SINK240 draws nothing). Need a phone
or laptop drawing amps to see whether `b1` shifts to 0x01/0x03/0x08 etc.
The integration's protocol-name sensor uses both `b1` and (soon) the
PDO high byte for accuracy.

### 2. `b0` upper nibble — Track A, cable-flip and port-swap

Observed: `b0=0x01` on C1/C2, `b0=0x11` on C3 at 5 V. Theory: CC polarity
or port role.
- Flip cable on C3 with same sink, same contract. Read `b0`. Upper nibble
  toggle → polarity.
- Move same sink C3 → C1 under same contract. Port-by-port change →
  port index.

KM003C `cc1_tenth_mV` / `cc2_tenth_mV` give independent polarity truth.

### 3. MIOT wire format (reversed end-to-end 2026-04-23/24)

| Direction | Opcode | Body |
|---|---|---|
| get request | `33 20` | `<seq_le2> 02 <count> <(siid, piid_le2)>*` |
| get response (bulk, btsnoop) | `93 20` | `<seq_le2> 03 <count> <results>*` |
| get response (multi, live) | `1c 20` | same body as 0x93 |
| get response (single, live) | `0e 20` | same body as 0x93 |
| set request | `0c 20` | `<seq_le2> 00 <count> <(siid, piid_le2, type, marker, value)>*` |
| set response | `0b 20` | `<seq_le2> 01 <count> <(siid, piid_le2, status_le2)>*` |
| spontaneous notify | `0f 20` | `<seq_le2> 04 01 <(siid, piid_le2, 04, 50, value_le4)>` |

Value encoding used in both get-response and set-request tuples:
- bool: `type=0x01, marker=0x00, value=1B`
- u8:   `type=0x01, marker=0x10, value=1B`
- u32:  `type=0x04, marker=0x50, value=4B LE`

Direct Pi-side verification on piid 0x13/0x14: the charger accepts either
bool or u8 encoding and updates state identically. The read-back always
returns `marker=0x00` (bool) for those piids, so the integration surfaces
them as Python bool even though Mi Home writes u8.

### Writable properties confirmed on this firmware (siid=2)

| piid | Name | Write enc | Values | How confirmed |
|---|---|---|---|---|
| 0x05 | scene_mode | u8 | 1=AI, 2=Hybrid, 3=Single, 4=Dual | tablet capture 2026-04-23 |
| 0x0e | unknown — Mi Home writes val=2 on every reconnect | u8 | unknown | tablet capture 2026-04-23 |
| 0x0f | usb_a_always_on | bool | 0/1 | reversed earlier; HA switch verified |
| 0x13 | screenoff_while_idle | u8 (Mi Home) / bool (accepted) | 0/1 | tablet capture + Pi-direct read-back |
| 0x14 | screen_dir_lock | u8 / bool | 0/1 | tablet capture + Pi-direct read-back |

### Not yet exercised

- piid 0x06 `screen_save_time` (u8)
- piid 0x07 `protocol_ctl` (u8)
- piid 0x0d `device_language` (u8)
- piid 0x10 `port_ctl` (u8 port-enable bitmap)
- piid 0x11 / 0x12 `c1c2_protocol` / `c3a_protocol` (u32, per-port UFCS/PD/PPS masks)
- piid 0x15 `protocol_ctl_extend` (u32)

Port-submenu taps on the rooted tablet didn't produce observable writes
— probably my taps missed the actual clickable bounds. Another capture
with fixed tap coordinates, or actually using the Xiaomi app manually,
would close this out.

### 4. Temperature exposure check (closed 2026-04-29)

The charger hardware has NTC temperature monitoring, but no readable BLE
temperature value has been found.

Evidence:
- Public MIOT spec for `njcuk.fitting.ad1204` exposes charger properties only
  through `2.21`; no temp property.
- Mi Home RN plugin `1028581` / `1896060` subscribes to the same
  `prop.2.1`..`prop.2.21` list and has no temperature string/property map.
- Existing decrypted captures show only port-info/protocol/settings updates.
- Fresh rooted-tablet capture with HA disabled and Mi Home on the connected
  charger page decoded to 191 MIOT rows. Mi Home queried only
  `2.1`, `2.2`, `2.3`, `2.4`, `2.5`, `2.6`, `2.7`, `2.13`, `2.15`, `2.16`,
  `2.17`, `2.18`, `2.19`, `2.20`, and `2.21`, then received `2.1`/`2.2`
  port-info notifications; no temp path appeared.
- Direct authenticated Pi-side sweep of `siid=2` `piid=0x16..0x40` returned
  not-found status `0xf05f` for unknown properties.

Conclusion: don't add a HA temperature entity until a new firmware/plugin
exposes a real value or we reverse a private/non-MIOT command path.

## Next steps

Ordered by "finishable as a single unit" and by what each one unlocks.

### Quick wins

1. **Cut a real release tag** (`v0.3.0` or similar). HACS currently shows
   commit SHAs to users; tagged releases give them version numbers plus
   rendered changelog. Implemented locally for v0.3.0 pending push.
2. **Formalize the decrypt-set_properties flow into
   `tools/decrypt_btsnoop_miot.py`.** Done: the script takes a btsnoop log
   plus token and emits CSV rows per decrypted MIOT tuple.
3. **Tablet-unlock helper** for future sessions. Done:
   `tools/tablet_unlock.sh` wakes the tablet and sends the L-pattern via
   `sendevent`; override coordinates with `PATTERN_POINTS` if the lock UI
   moves.

### Research that needs live hardware

4. **`b1` under real load.** Plug a real phone/laptop into C1 drawing
   ≥1 A and watch whether `b1` shifts from `0x0a` to `0x01/0x03/0x08`
   (as earlier captures hinted). Closes the protocol-name sensor's
   accuracy gap.
5. **`b0` upper nibble.** Cable flip + port swap with the same sink
   under the same contract. Upper nibble toggle with orientation → CC
   polarity; upper nibble changes across ports → port index.

### More-property reversing (each needs another tablet capture)

6. **Per-port protocol masks** (c1c2_protocol / c3a_protocol u32 writes,
   piid `0x11` / `0x12`). Our first attempt missed the Port submenu
   toggles — retry either with tap coordinates resolved via uiautomator
   after entering the submenu, or by manual touch on the tablet while
   we capture.
7. **`port_ctl`** (u8 bitmap, piid `0x10`). Mi Home exposes a per-port
   power button — capture one toggle.
8. **piid `0x0e`** — Mi Home writes `val=2` on every reconnect. Read
   its current value, try writing different values, see what moves in
   the device state.
9. **Temperature private path** — only if new evidence appears. Current
   MIOT/property/plugin paths do not expose temperature despite the hardware
   sensor.

### Integration polish (after 6/7 land)

10. Switches for per-port UFCS/PD/PPS enable.
11. Switches (or a combined number) for `port_ctl` port-enable bitmap.
12. Number entity for `screen_save_time` if it's a minutes value.

### Housekeeping

13. Screenshots for the root README (still a TODO in the HACS landing
    flow).
14. `.mailmap` if GitHub's Contributors list still shows `@claude` past
    ~2026-04-25.

## Tools that exist

- `tools/ad1204u_read_props.py --address <MAC>` — one-shot MIOT property
  read against a live charger.
- `tools/sweep_logger.py --address <MAC> --port c1 --interval 2 --out x.jsonl` —
  persistent BLE session, samples both the charger and KM003C every N
  seconds, parses KM003C PD events for contract labels.
- `tools/btsnoop_att.py <btsnoop.log> --mac <MAC>` — extract ATT traffic
  from an Android btsnoop v1 file.
- `tools/mible_decrypt.py --mac <MAC> --beaconkey <hex>` — legacy
  beacon-level decrypt for FE95 advertisements.

The decrypt-set_properties flow we used on 2026-04-23/24 is currently
inlined into Bash heredocs. If we rerun it often, wrap into a
`tools/decrypt_btsnoop_miot.py` that takes a btsnoop log + token and
dumps the (ts, opcode, siid, piid, value) table.
