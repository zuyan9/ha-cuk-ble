# MIOT property map (siid = 2)

All telemetry is on service id `0x02`. The AD1204U does not expose a full MIOT
spec discovery endpoint; the list below was reconstructed from Mi Home's
`get_properties` requests.

## Wire encoding

Request:

```
33 20 <seq LE2> 02 <count> <siid(1) piid_le2>*N
```

Response:

```
93 20 <seq LE2> 03 <count>
  then per entry: <siid(1)> <piid_le2> <status_le2> <type(1)> <marker(1)> <value>
    type=0x04 marker=0x50 → 4-byte LE uint32
    type=0x01 marker=0x10 → 1-byte uint8
    type=0x01 marker=0x00 → 1-byte bool
```

## Known properties

| piid | Name | Type | Notes |
|------|------|------|-------|
| 0x01 | port C1 info | u32 | per-port power word (see below) |
| 0x02 | port C2 info | u32 | per-port power word |
| 0x03 | port C3 info | u32 | per-port power word |
| 0x04 | port A info  | u32 | per-port power word |
| 0x05 | scene_mode | u8 | |
| 0x06 | screen_save_time | u8 | |
| 0x07 | protocol_ctl | u8 | |
| 0x0d | device_language | u8 | |
| 0x0f | usb_a_always_on | bool | |
| 0x10 | port_ctl | u8 | bitmap — `0x0f` = all four ports enabled |
| 0x11 | c1c2_protocol | u32 | low16 = C2, high16 = C1 |
| 0x12 | c3a_protocol | u32 | low16 = A,  high16 = C3 |
| 0x13 | screenoff_while_idle | bool | |
| 0x14 | screen_dir_lock | bool | |
| 0x15 | protocol_ctl_extend | u32 | |

## Temperature

The AD1204U hardware has internal NTC temperature monitoring and the charger
screen can show temperature, but no BLE-readable temperature property has been
found yet.

Checks done on 2026-04-29:

- The public MIOT spec for `njcuk.fitting.ad1204` defines only charger
  properties `2.1` through `2.21`; none are temperature-related.
- The Mi Home RN plugin bundle for plugin `1028581` / version `1896060`
  subscribes to the same `prop.2.1` through `prop.2.21` list and contains no
  temperature UI/string/property mapping.
- Existing decrypted Mi Home captures only show port-info/protocol/settings
  notifications.
- A fresh rooted-tablet Mi Home capture with HA disabled and the charger device
  page connected produced 191 decrypted MIOT rows. Mi Home requested only
  `2.1`, `2.2`, `2.3`, `2.4`, `2.5`, `2.6`, `2.7`, `2.13`, `2.15`, `2.16`,
  `2.17`, `2.18`, `2.19`, `2.20`, and `2.21`; no extra temperature property
  or non-MIOT temperature read appeared.
- A live authenticated read sweep of `siid=2` `piid=0x16..0x40` returned the
  firmware not-found status `0xf05f` for unknown properties.

Conclusion: temperature is not exposed over the currently reversed BLE MIOT
path. Adding a Home Assistant temperature sensor needs a new reverse-engineering
lead, such as a future plugin/firmware property, a private action, or a
non-MIOT GATT characteristic.

## Per-port power word decode

The u32 port-info value, taken little-endian as bytes `b0 b1 b2 b3`:

- `b0` — in-use bitfield. `0` always means idle; non-zero means active.
  Observed values include `0x01` and `0x11` on the same port at different
  times (the upper nibble likely encodes PD role/state but isn't decoded yet).
  Treat `bool(b0)` as the authoritative idle/active signal.
- `b1` — protocol code (see below)
- `b2` — **current, in 0.1 A units** (deciamps)
- `b3` — **voltage, in 0.1 V units** (decivolts)
- watts = `b2 × b3 / 100 = V × A`

Verified across 15+ datapoints, 0.5 W–100 W, 5 V–20 V, all four ports.

### b1 protocol codes

**Authoritative idle indicator is `b0` (in_use), not `b1`.** Early captures
led us to assume several `b1` values meant "idle" because they coincided with
unloaded ports. Follow-up live probes under active load contradicted that:
e.g. a C1 port drawing 48 W on a PD 3.0 45 W contract reports `b1=0x03`, and a
C2 port drawing 9 W at 5 V reports `b1=0x01`. Treat `b1` as a PD
protocol/subtype hint that is only meaningful when `b0=1`.

| b1 | Meaning | Where seen |
|----|---------|------------|
| `0x01` | PD (5 V contracts, loaded) | C1/C2 |
| `0x03` | PD (20 V contracts, loaded — e.g. PD3.0 45 W) | C1/C2 |
| `0x05` / `0x06` / `0x30` | PD (observed unloaded only; subtype unconfirmed) | any port |
| `0x08` | PD PPS SPR | C1/C2 (15V/0.8A=12W, 20V/4A=80W) |
| `0x0a` | PD fixed-PDO SPR | C1/C2 (5V/0.4A, 9V/0.7A, 10V/4.2A, 20V/3–5A) |
| `0x60` | USB-A (generic): seen on DCP at 5 V **and on QC 2.0 / SCP at 9 V** (KM003C confirmed QC2.0\|SCP while charger still reported `0x60`) | A, **and C3 when the C3+A shared rail is in USB-A compat mode** (reported on C3 even while PD-charging a USB-C sink at 5 V) |
| `0x70` | USB-A QC — from one btsnoop capture, but not reliably distinct from `0x60` in later tests. Don't trust as a QC indicator. | A |
| `0x80` | C3 high-voltage bucket (15 V PD fixed/PPS; C3 is spec-capped at 15 V) | C3 only |

On the **C3/A shared rail**, `b1` is voltage-band-driven rather than
protocol-driven: `0x60` covers everything 5–9 V on both A and C3 (USB-A
DCP/QC **and** USB-C PD all report the same code), and `0x80` covers 15 V
PD on C3. Meter-verified by plugging the same phone on C3 at PD 9 V (b1=0x60)
and PD 15 V (b1=0x80).

The `0x08` vs `0x0a` PPS/fixed split is fuzzy — the KM003C once reported "PPS"
on a contract the charger labeled `0x0a`, so the mapping isn't strictly 1:1
with the PD spec.

Idle ports (`b0=0`) always report `b2 = b3 = 0`.

## PDO-cap halves (piid 0x11 / 0x12)

Each u32 is two LE16 halves: low16 = C2/A, high16 = C1/C3. The low byte of
each half encodes the **negotiated PDO watt cap**:

**The low byte is the watt cap in decimal** — the original "observed values"
table (0x0a/0x0f/0x1e/…) was coincidence. A SINK240 sweep across PD Fixed
5/9/12/15/20 V and two PPS bands on C1 produced a linear progression:

| contract | low byte | dec | watts |
|---|---|---|---|
| Fixed 5V | `0x0f` | 15 | 15 |
| Fixed 9V | `0x1b` | 27 | 27 |
| Fixed 12V | `0x24` | 36 | 36 |
| Fixed 15V | `0x2d` | 45 | 45 |
| Fixed 20V | `0x64` | 100 | 100 (charger SPR ceiling) |
| PPS 3.3–11V / 5A | `0x37` | 55 | 55 |
| PPS 3.3–21V / 4A | `0x50` | 80 | 80 |

`cap_w = low_byte_decimal`. A zero low byte means "no contract / idle port".

### High byte (PDO kind)

Observed on C1/C2:
- `0x07` — PD Fixed PDO (every Fixed contract tested)
- `0x08` — PD PPS (APDO) (both PPS bands tested)

Observed on the C3/A shared rail (voltage-band driven, see earlier notes):
- `0x01` at 5 V USB-A DCP
- `0x02` at USB-A QC
- `0x04` at USB-A 9 V (QC 2.0 / SCP phone charging)


## Open questions

- **`b1` under real current.** Every SINK240 sweep row came back with
  `b1=0x0a` because the trigger board draws ~0 A. `b1` under a real load
  (phone/laptop pulling amps) still needs a pass; earlier captures hint
  that `b1` can shift to `0x01`, `0x03`, `0x08`, etc. under load.
- **`b0` upper nibble** (seen `0x01` and `0x11` on same port at different
  times) — CC polarity vs port role unresolved. Needs cable-flip / port-
  swap with the same sink under the same contract.
- **No EPR**: the charger tops out at PD 3.0 SPR 100 W (KM003C confirms);
  the "100 W" SINK240 case landed on plain 20 V/5 A SPR rather than PD 3.1.
- **`protocol_ctl_extend`** (u32 `0x03030f0f` constant so far) and
  **`port_ctl`** bitmap (`0x0f` constant) — not varied by Mi Home during
  our captures. Their writable semantics are still unknown.
- **piid `0x0e`** — Mi Home writes val=2 on every reconnect. Purpose
  unknown; the integration doesn't touch it.
- **Temperature telemetry** — the charger has internal NTC monitoring, but no
  BLE MIOT property or Mi Home plugin field currently exposes it.
