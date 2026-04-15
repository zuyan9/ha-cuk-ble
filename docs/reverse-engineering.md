# How this was figured out

1. **Android bug report btsnoop logs** from a live Mi Home session (paired +
   charging) captured under
   `bugreport-*/FS/data/misc/bluetooth/logs/btsnoop_hci.log*`.

2. [`tools/btsnoop_att.py`](../tools/btsnoop_att.py) extracts ATT traffic
   filtered by device MAC — this exposed the full handshake, the post-login
   MIOT framing, and that requests are written to UUID `0x001a` (not AVDTP).

3. **Session keys were reconstructable** from the logged `app_rand` /
   `dev_rand` because the binding token was already known (obtained via
   `Xiaomi-cloud-tokens-extractor`). That let us offline-decrypt Mi Home's
   own request/response traffic, which is where the `33 20 … / 93 20 …` MIOT
   get-properties wire format came from.

4. **Per-port word decode** was pinned down by stepping through loads of
   known wattages on each port and looking for a cross-port-consistent
   formula — `b2·b3/100 = V·A` fits **all** datapoints collected (15+
   across all four ports, spanning 0.5W–100W and 5V–20V).

## Verified datapoints

| Port | Reported load | raw LE | Amps (b2/10) | Volts (b3/10) | Watts | Profile |
|------|---------------|--------|--------------|----------------|-------|---------|
| C3 | ~1.5 W | `01 80 03 33` | 0.3 A | 5.1 V | 1.53 | PD 5V default |
| A  | ~5 W   | `01 70 0a 33` | 1.0 A | 5.1 V | 5.10 | QC 5V/1A |
| A  | ~9 W   | `01 70 09 5b` | 0.9 A | 9.1 V | 8.19 | QC 2.0 9V |
| C3 | ~30 W  | `01 80 14 97` | 2.0 A | 15.1 V | 30.2 | PD 15V |
| C1 | ~60 W  | `01 0a 1e c8` | 3.0 A | 20.0 V | 60.00 | PD fixed 20V/3A |
| C2 | ~62 W  | `01 0a 1f c9` | 3.1 A | 20.1 V | 62.31 | PD fixed 20V/3A (PPS-boosted draw) |
| C1 | ~80 W  | `01 08 28 c8` | 4.0 A | 20.0 V | 80.00 | PD **PPS** 20V/4A |
| C1 | ~100 W | `01 0a 32 c8` | 5.0 A | 20.0 V | 100.00 | PD fixed 20V/5A (SPR) |
| C2 | ~12 W  | `01 08 08 96` | 0.8 A | 15.0 V | 12.00 | PD **PPS** 15V (iPad, 45W cap) |
| C1 | ~42 W  | `01 0a 2a 64` | 4.2 A | 10.0 V | 42.00 | PD fixed 10V (disproves 0x0a=20V-only) |
| C1 | ~6 W   | `01 0a 07 5a` | 0.7 A | 9.0 V  | 6.30  | PD 9V, same 55W-cap contract as 10V/42W |
| A  | ~0.5 W | `01 60 01 33` | 0.1 A | 5.1 V  | 0.51  | USB-A DCP/BC1.2 (non-QC, `b1=0x60`) |
| C1 | ~2 W   | `01 0a 04 32` | 0.4 A | 5.0 V  | 2.00  | PD fixed 5V (15W cap; 0x0a at 5V) |
| C3 | ~30 W  | `01 80 20 5f` | 3.2 A | 9.5 V  | 30.40 | PD **PPS 9.5V** on C3 (breaks 0x80=5V/15V-only) |
| C3 | ~29 W  | `01 80 18 78` | 2.4 A | 12.0 V | 28.80 | PD PPS 12V on C3, same 30W cap |
| C2 | ~42 W  | `01 0a 15 c9` | 2.1 A | 20.1 V | 42.21 | PD 20V low draw, 100W contract |
| C1 | ~33 W  | `01 0a 21 63` | 3.3 A | 9.9 V  | 32.67 | PD ~10V, 55W cap |
| C1 | ~98 W  | `01 0a 31 c8` | 4.9 A | 20.0 V | 98.00 | PD fixed 20V/4.9A (near 100W cap) |

The 100W case is worth noting: the sink requested PD 3.1 EPR, but the charger
landed on plain 20V/5A SPR — EPR's 28/36/48V profiles are only required above
100W. `b1=0x0a` covers the entire 20V SPR range.

## Follow-up live probes (C1+C2+C3 simultaneously loaded)

Captured on the Pi via `tools/ad1204u_read_props.py`:

| Port | raw LE | b1 | V | A | W | PDO cap byte → W | Notes |
|------|--------|----|---|---|---|-----------------|-------|
| C1 | `01 03 18 c8` | `0x03` | 20.0 | 2.4 | 48.0 | `0x2d` → 45 | PD 3.0 45 W contract — **`0x03` under load, not idle** |
| C2 | `01 03 16 c9` | `0x03` | 20.1 | 2.2 | 44.2 | `0x2d` → 45 | PD 3.0 45 W contract |
| C2 | `01 01 ?? 34` | `0x01` | 5.2 | 1.8 | 9.36 | `0x0f` → 15 | PD 5 V — **`0x01` under load, not idle** |
| C3 | `01 60 13 33` | `0x60` | 5.1 | 1.9 | 9.69 | `0x0a` → 10 | USB-C PD sink at 5 V but C3+A rail in USB-A compat mode, so C3 reports `0x60` (USB-A DCP). New cap byte `0x0a` = 10 W. |
| C3 | `11 30 14 33` | `0x30` | 5.1 | 2.0 | 10.20 | `0x0a` → 10 | Same sink moments later now reports `b1=0x30` and `b0=0x11` (not 0x01). Confirms `b0` is a bitfield (non-zero = active) and `0x30` appears under load too. |
| A  | `00 30 00 00` | `0x30` | 0.0 | 0.0 | 0.00 | — | Idle A port also reports `0x30` — this code straddles idle and active. |
| A  | `01 60 03 33` | `0x60` | 5.1 | 0.3 | 1.53 | `0x0a` → 10 W | USB-A DCP/low-voltage default with C3 idle — A finally credited its own current when the shared rail isn't attributed to C3. |
| A  | `01 60 01 5b` | `0x60` | 9.1 | 0.1 | 0.91 | `0x0f` → 15 W | Phone on QC 2.0 at 9 V (KM003C confirmed QC2.0\|SCP) — charger still reports `b1=0x60`, not `0x70`. c3a_protocol high byte = `0x04` (new voltage bucket). Conclusion: `b1` on USB-A does not cleanly separate DCP vs QC. |
| C3 | `01 60 01 5b` | `0x60` | 9.1 | 0.1 | 0.91 | `0x1e` → 30 W | Phone on C3 doing PD 3.0 9V (meter-confirmed). Despite being USB-C PD, `b1=0x60` — same code as USB-A at 9 V. |
| C3 | `01 80 14 97` | `0x80` | 15.1 | 2.0 | 30.2 | `0x1e` → 30 W | Same phone on C3, now PD 3.0 15V/30W (meter-confirmed). `b1=0x80`. |

**Conclusion about C3/A b1:** on the shared rail, `b1` is voltage-band-driven, not protocol-driven. `0x60` covers everything 5–9 V (USB-A DCP/QC, USB-C PD alike); `0x80` covers ≥15 V PD. The old btsnoop inference that `0x80` meant "PD port-family" and `0x60` meant "USB-A DCP" was a correlation, not a definition.

**Idle-code observation:** when a port goes idle after being loaded, the charger cycles through different `b1` values (seen: `0x01`, `0x03`, `0x06`, `0x30`, `0x60`, `0x80` on idle ports). This is why the decoder treats `b0` as the authoritative idle flag and ignores `b1` when idle.

These contradict the earlier assumption that `0x01`/`0x03` meant "idle" — they
are PD codes that happen to appear at rest (because the port is on a PD
handshake idle/advertising frame) and under load (because the PD contract
stayed at the same subtype). The authoritative idle signal is always `b0`.
