# TS0505A (Lidl Livarno Lux) OTA investigation

A Tuya EFR32MG21 light bulb rejects unsigned custom firmware. This repository documents why, down to the bytes, and why the light always turns back ON after a power cut, down to the NVM3 key map.

This repository records a complete, reproducible attempt to replace the stock firmware of Lidl "Livarno Lux" TS0505A lights (E27 HG06106C, E14 HG06106B, GU10 HG06106A, strip HG06104A; Silicon Labs EFR32MG21, module ZS3L) with custom firmware built from the public Tuya Zigbee SDK, and to change the always-on-after-blackout behavior. Seven verified OTA images were served to a sacrificial bulb. All were fully downloaded (about 21 minutes each) and all were rejected with `upgradeEndRequest` status 150 (`0x96 INVALID_IMAGE`). The bulb survived every attempt unharmed on stock firmware.

The investigation progressed from the initial five rejections (Nov 4) through root-cause analysis of both the OTA wall and the power-on behavior (Nov 17-20), arriving at a complete static map of the firmware's boot, configuration, and persistence architecture, verified end-to-end in the disassembly of both the application and the bootloader.

## TL;DR: what we now know

1. **Why custom firmware is rejected**: the bootloader Gecko verifies the ECDSA P-256 signature of the GBL container using the Secure Element, and the only production private key is not publicly available. The AES-128 fleet key that encrypts the containers IS publicly available (it is a constant in the official SDK on GitHub).
2. **Why the light always turns ON after a power cut**: the OnOff attribute is never persisted anywhere. At every boot it resets to its default value (ON). There is no setting, flag, or attribute that can change this on stock firmware. The `pmemory:1` option in the factory configuration is already enabled but is ignored for on/off state.
3. **The TS0505B variant has the same problem**: upgrading to the B variant would not fix the power-on behavior (see [zigbee2mqtt#28129](https://github.com/Koenkk/zigbee2mqtt/issues/28129)).
4. **Every Zigbee-reachable path to change the behavior is closed**: all standard and Tuya-specific clusters have been tested or statically ruled out.

## Background: the always-on problem

These lights always power back ON after a mains cut, and the firmware rejects every documented way to change that behavior:

- `genOnOff.startUpOnOff` write: `UNSUPPORTED_ATTRIBUTE`
- `manuSpecificTuya3.powerOnBehavior` write: `UNSUPPORTED_ATTRIBUTE`
- `lightingColorCtrl.tuyaOnStartUp` (0xF9) and `tuyaDoNotDisturb` (0xFA): default response `UNSUPPORTED_CLUSTER`, while Z2M reports success (fixed upstream in the error handling, see the thread below)

The behavioral matrix and the swallowed-error analysis are public in [Koenkk/zigbee-herdsman-converters#13643](https://github.com/Koenkk/zigbee-herdsman-converters/issues/13643). The same thread tracks the architecture fix in zigbee-herdsman ([PR#1927](https://github.com/Koenkk/zigbee-herdsman/pull/1927)) that makes cluster-specific rejections visible.

## Root cause of always-on: no OnOff persistence (proven)

We statically mapped the complete persistence architecture of the stock v84 firmware using Ghidra (REA). The result closes the question:

The device uses **Simplicity NVM3** for persistent storage (pages at flash `0xB6000`-`0xBC000`, magic `0xB29A`). On top of NVM3 sits a 4 KB logical array (`tuya_flash_read`/`tuya_flash_write` at addresses `0x1494c`/`0x148b2` in the v84 binary), stored across 17 NVM3 objects of 250 bytes each. A complete NVM3 key map was extracted from the firmware's migration table (100 entries at flash `0x47410`).

The only application-level data ever written to the logical array is a **20-slot reset-reason ring** (`{u32 timestamp, u8 reason}` per slot), used by the power-cycle factory-reset counter (`rstnum`). The Zigbee stack stores its own tables (bindings, scenes, network keys) in separate NVM3 objects.

**The OnOff attribute has no persistent storage anywhere.** No NVM3 key, no ZCL token, no flash array offset ever stores it. At every boot, OnOff resets to its compiled default: ON. This is not a "forced on" routine; it is the absence of a "remember off" mechanism. The `pmemory:1` factory setting, which sounds like it should enable power-off memory, is parsed at boot but only affects brightness and color restoration, never on/off state.

The full analysis with every address is in [analysis/ota-client-map-protocol-gap_2026-11-17.md](analysis/ota-client-map-protocol-gap_2026-11-17.md) (addenda 3-8, nights 1-8).

## The factory configuration decoded

The firmware's factory configuration is a compressed JSON blob inside the application flash. We reconstructed the LZ decompression algorithm from the disassembly (function at `0x464b0` in v84, using the string template block at `0x46528` as dictionary) and decoded it completely for both stock versions:

v84 (TS0505A, the fleet):
```json
{"Jsonver":1.1.0,"category":"0505","module":"ZS3L","cmod":"rgbcw","dmod":0,
 "onoffmode":1,"pmemory":1,"defcolor":"c","defbright":100,"deftemp":100,
 "cwmaxp":100,"brightmin":1,"brightmax":100,"wfcfg":"spcl","rstmode":0,
 "rstnum":3,"r_pin":8,"g_pin":4,"b_pin":1,"c_pin":9,"w_pin":5,"pwmhz":1000,...}
```

Key findings from the configuration:
- `onoffmode` does NOT control power-on behavior; it is the on/off fade/gradient setting
- `pmemory:1` is already enabled; it governs brightness/color restoration, not on/off
- `rstnum:3` is the power-cycle count for factory reset (3 on/off cycles to unpair)
- The pinout (r8/g4/b1/c9/w5, PWM at 1 kHz) identifies the hardware unambiguously
- The v80 stock firmware is a different product (TS0502A, 2-channel CW, category 0502); the only configuration differences from v84 are `category`, `cmod`, `brightmin`, and `colormin`

The decompressor is reproducible: literal tokens copy `raw-1` bytes, back-references copy `ctrl>>4 + 2` bytes at offset `off_lo + (mode<<8)` into the output-relative dictionary seeded with the template block.

## The OTA wall: complete architecture

### Seven candidates, seven rejections

All images were served via Zigbee2MQTT OTA with per-device isolation. The bulb downloaded each completely (~21 min, 4909 blocks) and rejected each with status 150.

| Candidate | Container | Signature | Result |
|---|---|---|---|
| v96 | plaintext GBL | unsigned | INVALID_IMAGE |
| v97 | plaintext GBL, versions aligned | unsigned | INVALID_IMAGE |
| v98 | plaintext GBL | ECDSA (Silabs example key) | INVALID_IMAGE |
| V-A | plaintext, production headerString | unsigned | INVALID_IMAGE |
| V-B | plaintext, outer version 81 | unsigned | INVALID_IMAGE |
| v99 | encrypted (AES-128 fleet key) + signed | ECDSA (Silabs example key) | INVALID_IMAGE after 24s |
| E1 repeat | same as v98 | same | INVALID_IMAGE |

### Where the rejection actually comes from (timing proof)

Timing analysis of the download logs discriminates the rejection source:

- Plaintext candidates (v97, v98, E1): `upgradeEndRequest(INVALID_IMAGE)` arrives **within 1 second** of download completion. The bootloader rejects at the GBL header type-bits check (missing encryption bit) before doing any cryptographic work.
- Encrypted candidate (v99, type 0x101 with the correct fleet AES key): the endRequest arrives **24 seconds** after completion. Those 24 seconds are the bootloader streaming-decrypting the entire ~286 KB, walking the decrypted tag stream, computing SHA-256, and submitting the ECDSA verification to the Secure Element, which then **rejects the signature** (the example key does not match the production key).

This proves:
1. The application delegates verification to the bootloader correctly (it is not an app-level stub that blocks everything)
2. The AES-128 fleet key is correct for this device (the decrypt succeeded; a wrong key would produce garbage tags and instant rejection)
3. **ECDSA signature enforcement is real and active on-device**

### The ECDSA production key

The bootloader (disassembled from the TS0222 sensor's flash dump, a cousin product on the same SDK; the TS0505A's own bootloader was not dumped) extracts its verification keys from flash tokens at `0xBE34C`/`0xBE36C` (X and Y coordinates of a P-256 public key). The same key signs:
- The bootloader GBL containers
- The application-level ECDSA signature (over the flash image bytes `[0x4000, 0x3A4F0)`)

We harvested 31 production-signed firmware images from the public Tuya CDN (28 from the catalog plus v80, v84, and the TS0222 sensor dump) and verified all against this key. Cryptanalysis closed:
- No nonce reuse (zero collisions in r or (r,s) across 31 signatures)
- No truncated nonces (BSGS negative at 32 bits; lattice HNP attack, validated with known-answer tests, negative at 64/96/128/160 bits)
- No low-s normalization (19/31 signatures have s > n/2)
- Conclusion: the signing pipeline uses full-size CSPRNG nonces. There is no mathematical path to the private key from the available signatures.

### The AES fleet key is public

The AES-128 key `03d29876bcd7f03e64c375734975ebdc` (used to encrypt GBL containers for the entire Tuya Silabs lighting line, verified across at least 3 products) is not a manufacturing secret: it is a **constant hardcoded in `zigbee_sdk_core.o` inside `libtuya_sdk.a`** in the official `TuyaInc/tuya_zigbee_sdk` repository on GitHub (target `EFR32MG21A020F768`). It was never a secret. The security of the Tuya Silabs OTA chain rests entirely on the ECDSA signature gate.

### The signature digest span (verified in bootloader disassembly and build scripts)

We disassembled the GBL parser of the Tuya Silabs bootloader (from the TS0222 full flash dump; note that the TS0505A's own bootloader was not dumped, so the parser behavior is a family-level inference, not a device-level measurement). The SHA-256 digest for ECDSA verification covers the **outer GBL container bytes** from the first tag through the last tag before SIGNATURE:

- For **encrypted** containers (type 0x101): the hash covers HEADER_V3 + ENC_INIT + ENC_DATA (the AES-CTR **ciphertext**, not the decrypted plaintext). This is confirmed by our own build: `build_v99_enc_signed.py` signs `sha256(HEADER_V3 + ENC_INIT + ENC_DATA)` and the committed v99 signature verifies against this outer span.
- For **plaintext** containers: tag headers and payloads are hashed through the same callback.
- The SIGNATURE tag itself is never hashed. The END tag is never hashed.
- The Zigbee OTA wrapper (56-byte ZCL header, outside the GBL entirely) is never hashed.

**Consequence**: the OTA header (manufacturerCode, imageType, fileVersion) is completely outside the signature. The GBL content is fully committed to by the signature (including the encrypted payload), but the OTA wrapper identity is not. In theory, a production-signed GBL for one product could be re-wrapped in an OTA header claiming another product's identity. However, we found no hardware-compatible candidate among the 70 CDN firmware images we analyzed (see below), and the TS0505B variant does not fix the power-on behavior.

### The identity-wrapping dead end

We analyzed all 70 firmware files harvested from the public Tuya CDN (`images.tuyaeu.com`, catalog from [divadiow/Misc](https://github.com/divadiow/Misc)). Among the 28 production-signed images, one (`oem_light_mg21_linea`) contains the exact identity of our fleet (`TS0505A / _TZ3000_riwp3k79`). However:

1. The `_TZ3000_riwp3k79` identity is also used by Livarno Lux **LED strips** (HG06104A), not just bulbs. The linea firmware may target the strip hardware.
2. The newer firmware generation (mg21_zg_light_bulb series, briloner, linea) does not contain the compressed JSON config blob. The pinout cannot be verified from the file. Without pinout verification, serving the firmware is an unacceptable brick risk.
3. The TS0505B variant (referenced in the firmware's model tables) has the same power-on problem as TS0505A ([zigbee2mqtt#28129](https://github.com/Koenkk/zigbee2mqtt/issues/28129)), so even a successful swap would not fix the behavior.

## The fleet and its OTA identity

Eight units across two IEEE OUIs (84:2e:14 and 58:8e:81, likely two module generations): seven in the original behavior-test fleet plus one sacrificial unit kept for flashing experiments. All report the same OTA identity:

| Field | Value |
|---|---|
| manufacturerCode | 4098 (0x1002) |
| imageType | 5634 (0x1602) |
| fileVersion | 80 |
| modelId | TS0505A |

Manufacturer names seen in the wild on this family: `_TZ3000_odygigth`, `_TZ3000_dbou1ap4`, `_TZ3000_riwp3k79`, `_TZ3000_kdpxju99`.

Note: imageType 0x1602 is shared by other Tuya products. The identity alone does not identify a product; serving the wrong image to these lights is a real hazard.

## What was verified byte by byte

The verification battery (`evidence/verify_v99_build.py`, baseline-pinned) reconstructs the flash image from the GBL and verifies:

- Flash chunks: exact address and size match to the v98 baseline
- Flash-level diff v98 to v99: exactly three version bytes, all accounted for
- GBL body CRC32 residue: `0x2144DF1C` (streaming zlib)
- AES-CTR roundtrip: the fleet key decrypts the ENC_DATA payload to a valid inner tag stream
- ECDSA: the signature verifies against the Silabs example public key (proving the signing was done correctly) and fails against the production key (proving the production key is different)
- Strict tag-sequence check: [HEADER_V3, ENC_INIT, ENC_DATA+, SIGNATURE, END], no unknown tags, no overlaps

## The bench: stock behavior measured

With every firmware route closed, we measured the actual power-on behavior on an automated bench: the sacrificial bulb powered through a smart plug, six mains cuts total, MQTT reads correlated to the cut ordering. Every cut with a verified pre-cut OFF state still came back ON at restore. Full write-up: [analysis/bench-power-on-behavior_2026-11-06.md](analysis/bench-power-on-behavior_2026-11-06.md).

The static analysis (NVM3 map, no OnOff persistence) now explains the bench result: there is no mechanism in the firmware that could remember the OFF state across a power cut.

## Format findings worth reusing

1. **Tuya GBL files are not 4-byte padded between tags.** Walk tags as `offset + 8 + length` exactly.
2. **GBL `ERASEPROG` payload is `u32 flashAddress` followed by data.**
3. **The OTA subelement header is 2-byte tag + 4-byte length (6 bytes), not 8.**
4. **AAT layout verified against Tuya sources** (`cstartup-common.c`).
5. **The 16 bytes at the start of `appProperties` are the standard Silicon Labs `APPLICATION_PROPERTIES_MAGIC`.**
6. **Production Tuya images carry `EBL ` prefix in the headerString.**
7. **The Tuya config JSON is compressed with a custom LZ algorithm** (literal tokens + back-references into a template dictionary). The decompressor is trivially reproducible: control byte gives literal length (bits 0-1, extended if zero) and copy length (bits 4-7, extended if 0xF); back-reference offset is `off_lo + (bits 2-3 << 8)` with a third byte if mode==3; copy length is `raw + 2`.
8. **The Tuya Silabs SDK stores global variables via r9-relative addressing** (static base), so literal pools never contain addresses of globals or peripherals. This is why naive constant searches in the binary fail.
9. **NVM3 is the persistence layer** (not a proprietary Tuya store). Keys are 20-bit; the application uses a migration table at a fixed flash address to declare ~100 key ranges with defaults.

## The lead we killed with disassembly

The prebuilt `libtuya_sdk.a` contains `ota-bootload-soc.o` with `emberSendBootloadMessage` and `TOKEN_MFG_BOOTLOAD_AES_KEY` symbols. Disassembly proved it is a ten-byte stub calling `halAppBootloaderInstallNewImage` with no protocol, no AES challenge, no XMODEM. The incoming bootload handler that IS linked is `bx lr`. No legacy door exists.

We also statically audited:
- **Every path that emits ZCL status 150 (INVALID_IMAGE)**: the status is a catch-all. The application's "slot-verify" function (`FUN_000393de` in v84) is a compiled stub `return 1`, but it never executes in the observed OTA flows. The real rejections come from the bootloader: instant rejection at the GBL type-bits check (plaintext candidates) and post-verification rejection (encrypted candidates with wrong signature).
- **Every NVM3 key the firmware reads at boot**: none stores an on/off state.
- **Every function in the OTA client's finalize path**: manufacturerCode and imageType are not checked at finalize; the identity match happens only at queryNextImage.

## What remains open

- **Official firmware with startUpOnOff**: no Tuya Silabs lighting firmware currently implements it (confirmed for both TS0505A and TS0505B). Monitor [zigbee-OTA index](https://github.com/Koenkk/zigbee-OTA) and [#13643](https://github.com/Koenkk/zigbee-herdsman-converters/issues/13643).
- **The production ECDSA private key**: not in the official SDK (337 MB scanned), not recoverable from available signatures (31 samples, full-size nonces), not leaked in any public artifact we found. The signing infrastructure is server-side at Tuya; ODM-side tools almost certainly never contain it.
- **Physical flashing (SWD)**: would bypass everything (replace the bootloader with a custom one from the Gecko SDK). We excluded opening devices from this project.

## Related work

- [analienx/tuya-ts0505b-router-firmware](https://github.com/analienx/tuya-ts0505b-router-firmware): custom firmware for TS0505B, a newer generation with a different OTA identity (0x100B / 0x020C).
- [romasku/tuya-zigbee-switch](https://github.com/romasku/tuya-zigbee-switch): custom firmware for Tuya Telink and some Silabs devices.
- [dzerik/zs3l-ncp-flash-over-network](https://github.com/dzerik/zs3l-ncp-flash-over-network): flashed the same EFR32MG21/ZS3L chip via GPIO boot strap + UART XMODEM.
- [pvvx/ZigbeeTLc](https://github.com/pvvx/ZigbeeTLc): the Telink ecosystem shows what open Tuya hardware looks like.
- [paoloantinori/osram-lightify-fw-re](https://github.com/paoloantinori/osram-lightify-fw-re): OSRAM LIGHTIFY bulbs share the always-on-after-power-cycle behavior.
- [openshwprojects/OpenBK7231T_App](https://github.com/openshwprojects/OpenBK7231T_App): OpenBeken firmware for Tuya WiFi devices (BK7231), a different chipset family. We used its source extensively for cross-referencing.
- [Koenkk/zigbee2mqtt#28129](https://github.com/Koenkk/zigbee2mqtt/issues/28129): TS0505B power outage behavior (same problem).

## Repository contents

- `evidence/` verification batteries, build scripts, run logs, decrypted firmware images, the 31-signature production dataset, the production ECDSA public key.
- `analysis/` investigation write-ups (Italian; this README carries the essential findings in English). The two primary documents:
  - `ota-client-map-protocol-gap_2026-11-17.md` (with 12 addenda through Nov 20): the complete OTA architecture, NVM3 map, config decode, persistence analysis, cryptanalysis
  - `bootloader-signature-policy-ts0222-dump_2026-11-17.md` (rev 4): bootloader signature verification mechanism

## Credits and conduct

All experiments ran on our own devices, on our own network, with the risk formally accepted before each flash. The sacrificial bulb survived every step and is back on stock duty. Questions and additions: please open an issue.
