# AD1204U BLE protocol

Wire-level notes for the Mi BLE standard-auth v1 + AES-CCM MIOT transport as
spoken by the CUKTECH AD1204U. Everything here was reconstructed from btsnoop
HCI logs of a live Mi Home session; see [reverse-engineering.md](reverse-engineering.md)
for methodology.

## Device identity

- Advertised name: `njcuk.fitting.ad1204`
- Mijia product id: `0x660E`
- Service UUID (advertising): `0000fe95-0000-1000-8000-00805f9b34fb`

## GATT map

Resolve by UUID — ATT handles change across firmware.

| UUID (short) | Role | ATT handle (this device) |
|---|---|---|
| `0x0010` UPNP  | Auth command channel | 0x000d |
| `0x0019` AVDTP | Auth parcel channel (RCV_RDY/OK, handshake frames) | 0x0010 |
| `0x001a` MIOT write | Encrypted MIOT requests + flow-control | 0x0019 |
| `0x001b` MIOT notify | Encrypted MIOT responses + spontaneous telemetry pushes | 0x001c |

The key (previously-wrong) observation: post-auth MIOT requests do **not** go
on AVDTP. Write + flow-control for MIOT lives on UUID `0x001a`; encrypted
response payloads land on `0x001b`.

## Login

Standard Xiaomi Mi BLE v1: ECDH-P256 → HKDF-SHA256 → 16-byte `app_key` /
`dev_key` + 4-byte `app_iv` / `dev_iv`. Implementation in
[`cuktech_ble/xiaomi/auth.py`](../cuktech_ble/xiaomi/auth.py).

**Device-specific wrinkle**: a greeting byte `a4` must be written to UPNP and
echoed on AVDTP before the login handshake — Mi Home does this, the vanilla
`dnandha/miauth` flow does not.

## MIOT transport framing

AES-CCM with:

- **key** = `dev_key` (device → host); `app_key` (host → device)
- **nonce** = `iv(4) ‖ 0x00000000 ‖ counter.to_bytes(4, "little")` (12 bytes)
- **AAD** = empty
- **tag** = 4 bytes
- **counter** = independent 16-bit LE per direction, embedded in the transport frame

### Outbound (host → device on UUID `0x001a`)

```
announcement: 00 00 00 00 NN NN              (NN NN = parcel count LE, normally 01 00)
← RCV_RDY:    00 00 01 01                    (on UUID 0x001a)
parcels:      01 00 CC CC <ct-fragment>      (parcel 1: idx + counter + ct)
              02 00 <ct-fragment>            (parcel 2+: idx + ct, no counter)
              ...
← RCV_OK:     00 00 01 00                    (on UUID 0x001a)
```

### Inbound (device → host on UUID `0x001b`)

Two forms — both observed in the same session from the same request.

**Inline** (short responses):

```
00 00 02 00 CC CC <ct>
→ ACK: 00 00 03 00
```

**Parcel** (long responses):

```
00 00 00 00 NN NN        announcement
→ RCV_RDY: 00 00 01 01
N × parcels               same 4-byte-strip-on-parcel-1 rule
→ RCV_OK: 00 00 01 00
```

### Parcel reassembly gotcha

Mi Home's bundled parcel 1 carries the LE16 counter immediately after the
index; parcels 2+ do **not** repeat it. Early versions of the client stripped
4 bytes from every parcel — this corrupts ciphertext from parcel 2 onward and
manifests as an `InvalidTag` with no other hint. Fix in
[`session.py`](../cuktech_ble/xiaomi/session.py): parcel 1 strips 4 bytes,
parcels 2+ strip 2.

### Interleaved telemetry

After login the device may spontaneously push a counter=0/1 telemetry frame
*before* the response you asked for. `MiSession.send_request` reads up to
8 frames, skips anything that doesn't decrypt or doesn't match the request seq
in `pt[2:4]`, and returns the matching response.

### Offline btsnoop decode

Mi Home captures can be decoded without connecting to the charger again:

```bash
.venv/bin/python tools/decrypt_btsnoop_miot.py /tmp/btsnoop.log \
    --mac AA:BB:CC:DD:EE:FF \
    --token 00112233445566778899aabb
```

The script extracts the login randoms from the auth channel, derives the
same `app_key` / `dev_key` and IVs used by the live client, decrypts MIOT
frames on handles `0x0019` / `0x001c`, and emits one CSV row per decoded
property request, response, set, or notify tuple. It is the preferred path
for turning tablet captures into evidence for new writable properties.

### BlueZ MTU quirk

BlueZ defaults to ATT MTU 23. The 32-byte `CMD_SEND_INFO` HMAC during login
splits into two parcels and the AD1204U intermittently rejects multi-parcel
auth uploads. Workaround: call `client._backend._acquire_mtu()` (the method
lives on `BleakClientBlueZDBus`, not the `BleakClient` facade) right after
connect — MTU jumps to 247 and login works first try. The client keeps a
4-attempt retry loop around login as belt-and-braces.
