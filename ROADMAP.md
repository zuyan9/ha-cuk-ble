# Roadmap

Ordered by "finishable as a single unit" and by what each one unlocks.
Agent-local details live in `.claude/TestInstructions.md` (gitignored); this
file is the shareable summary.

## Quick wins

- [ ] **Cut a real release tag** (`v0.3.0` or similar). HACS currently shows
  commit SHAs to users; tagged releases give them version numbers and a
  rendered changelog.
- [ ] **Formalize the decrypt-set_properties flow into
  `tools/decrypt_btsnoop_miot.py`.** The inline Python heredoc we've used
  should become a script that takes a btsnoop log plus token and emits one
  row per decrypted frame (`ts, opcode, siid, piid, value`).
- [ ] **Tablet-unlock helper.** The sendevent `L` pattern we scripted during
  the 2026-04-23 Mi Home capture belongs in `tools/tablet_unlock.sh` so
  future captures don't re-derive touchscreen coordinates.

## Research that needs live hardware

- [ ] **`b1` under real load.** Plug a phone/laptop into C1 drawing ≥1 A and
  check whether `b1` shifts from `0x0a` to `0x01/0x03/0x08` as earlier
  captures hinted. Closes the protocol-name sensor's accuracy gap.
- [ ] **`b0` upper nibble.** Cable-flip and port-swap with the same sink
  under the same contract; upper-nibble toggle vs orientation resolves
  CC polarity vs port-index.

## More-property reversing (each wants another tablet capture)

- [ ] **Per-port protocol masks** (`c1c2_protocol` / `c3a_protocol` u32
  writes, piid `0x11` / `0x12`). First capture missed the Port submenu
  toggles — retry with tap coordinates resolved via `uiautomator` after
  entering the submenu, or by manual touch while capturing.
- [ ] **`port_ctl`** (u8 bitmap, piid `0x10`). Mi Home exposes a per-port
  power button; capture one toggle.
- [ ] **piid `0x0e`** — Mi Home writes `val=2` on every reconnect. Read
  its current value, try writing different values, see what moves in the
  device state.

## Integration polish (after protocol masks land)

- [ ] Switches for per-port UFCS/PD/PPS enable.
- [ ] Switches (or a combined Number) for the `port_ctl` port-enable bitmap.
- [ ] Number entity for `screen_save_time` (u8, piid `0x06`) if it turns
  out to be a minutes value.

## Housekeeping

- [ ] Add screenshots to the root [README](README.md) (HACS landing page
  reads the root README).
- [ ] Drop a `.mailmap` only if GitHub's Contributors widget still shows
  `@claude` past 2026-04-25 — otherwise let it clear on its own.
