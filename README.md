# TS0505A (Lidl Livarno Lux) OTA investigation

A Tuya EFR32MG21 light bulb rejects unsigned custom firmware. This repository documents why, down to the bytes.

This repository records a complete, reproducible attempt to replace the stock
firmware of Lidl "Livarno Lux" TS0505A lights (E27 HG06106C, E14 HG06106B, GU10
HG06106A, strip HG06104A; Silicon Labs EFR32MG21, module ZS3L) with custom
firmware built from the public Tuya Zigbee SDK. Three verified OTA images were
served to a sacrificial bulb. All three were fully downloaded (about 21 minutes
each) and all three were rejected by the bootloader with `upgradeEndRequest`
status 150 (`0x96 INVALID_IMAGE`): unsigned with internal version 1, unsigned
with version 97 aligned everywhere, and ECDSA-signed with the Silicon Labs
example key. The bulb survived all attempts unharmed on stock firmware.

We publish everything: the build, the byte-level verification of what was
served, the run logs, the format findings we extracted on the way, the leads we
followed, and the leads we killed with disassembly. If you own one of these
lights and want custom firmware, this is the current state of the art as far as
we can push it without opening the device.

## Background

These lights always power back ON after a mains cut, and the firmware rejects
every documented way to change that behavior:

- `genOnOff.startUpOnOff` write: `UNSUPPORTED_ATTRIBUTE`
- `manuSpecificTuya3.powerOnBehavior` write: `UNSUPPORTED_ATTRIBUTE`
- `lightingColorCtrl.tuyaOnStartUp` (0xF9) and `tuyaDoNotDisturb` (0xFA):
  default response `UNSUPPORTED_CLUSTER`, while Z2M reports success (fixed
  upstream in the error handling, see the thread below)

The behavioral matrix and the swallowed-error analysis are public in
[Koenkk/zigbee-herdsman-converters#13643](https://github.com/Koenkk/zigbee-herdsman-converters/issues/13643).
The same thread tracks the architecture fix in zigbee-herdsman
([PR#1927](https://github.com/Koenkk/zigbee-herdsman/pull/1927)) that makes
cluster-specific rejections visible.

## The fleet and its OTA identity

Eight units across two IEEE OUIs (84:2e:14 and 58:8e:81, likely two module
generations): seven in the original behavior-test fleet plus one sacrificial
unit kept for flashing experiments. All report the same OTA identity, read via
image notify plus the device's own `queryNextImageRequest`:

| Field | Value |
|---|---|
| manufacturerCode | 4098 (0x1002) |
| imageType | 5634 (0x1602) |
| fileVersion | 80 |
| modelId | TS0505A |

Manufacturer names seen in the wild on this family: `_TZ3000_odygigth`,
`_TZ3000_dbou1ap4`, `_TZ3000_riwp3k79`, `_TZ3000_kdpxju99`.

Note: imageType 0x1602 is shared by other Tuya products (a ZS5 UART module
image and an MG21 window-cover relay exist in the public zigbee-OTA index
under the same code). The identity alone does not identify a product; serving
the wrong image to these lights is a real hazard, which is why our serving
setup pins one URL to one device.

## What we built and served

Custom firmware from the Tuya Zigbee SDK (`tuya_zigbee_sdk`, commit 7bedace),
configured for the EFR32MG21A020F768 target, with a power-on memory rewrite
for the light controller. Two candidates:

- **v96** (`ts0505a_fw_OTA_1.2.0.bin`, SHA-256 `b57b959d...`): external version
  96, internal application version left at the SDK default of 1.
- **v97** (`ts0505a_fw_OTA_1.2.1.bin`, SHA-256 `08f8560b...`): external 97 and
  internal 97 everywhere a bootloader can read it: AAT
  `customerApplicationVersion`, `ApplicationProperties.app.version`, the GBL
  `APP_INFO` tag, and the in-image `g_firmware_ver`. Inner and outer aligned,
  like production Tuya images we compared against (ZB21S3 dimmer: inner 10 =
  outer 10).
- **v98** (`ts0505a_fw_OTA_1.2.2.bin`, SHA-256 `eadeb8a1...`, 245450 bytes):
  v97 plus an ECDSA-P256 GBL signature, signed with the public Silabs example
  key from `gecko_sdk/platform/common/example_signing_key.pem`. The Gecko
  bootloader makes signature enforcement a per-build flag; if Tuya provisioned
  the stock bootloader against the example key instead of their own, this
  image would have passed. It did not.

Serving went through Zigbee2MQTT with a local OTA index pinned to one device
by `manufacturerName`, plus a blocker entry that answers the other seven units
with v80 `NO_IMAGE_AVAILABLE`. Before each run we re-verified isolation for
all eight devices over MQTT. No other unit ever started a download.

## The outcome, three times

All three candidates were downloaded completely and rejected at the end:

- v96: full download (4908 blocks), `upgradeEndRequest` fileVersion 96,
  status 150.
- v97: 99.91% progress in 20m39s, `upgradeEndRequest` fileVersion 97,
  status 150 (0x96 INVALID_IMAGE), 2026-11-04 06:08. The device echoed the
  fileVersion of our image, so it received ours, and returned to a healthy
  stock v80 state.
- v98: same rejection, 2026-11-04 11:20, after 99.91% progress in 20m48s.
  The device echoed fileVersion 98: it received and parsed our signed image,
  and the example-key signature did not change the verdict.

What the three rejections establish, stated carefully: aligning every
version field at 97 was not sufficient, and signing with a key we possess was
not sufficient either. The status 0x96 aggregates several distinct parser and
policy errors, so three identical statuses are three identical observations,
not three identical mechanisms. We do not claim a diagnosed root cause. The
readings that remain consistent with all three data points: the stock
bootloader requires signatures from a burned-in non-public Tuya key, requires
encryption plus signature together (the wincover pattern), or the rejection
has nothing to do with signatures at all (a vendor callback or an internal
version register deciding first).

## What was verified byte by byte

The interesting part is what was proven about the artifacts, because it
removes whole families of explanation. The battery
(`evidence/verify_v97_build.py`, baseline-pinned) reconstructs the flash image
from the GBL and compares v96 to v97:

- Flash chunks identical in address and size: `0x4000` (AAT, 172 B), `0x4200`
  (app body, 242098 B), `0x3f3b4` (tail, 2946 B).
- Flash-level diff v96 to v97: exactly three bytes, all accounted for:
  `0x4058` AAT version 1 to 97, `0x3c88c` appProperties version 1 to 97,
  `0x3f598` `g_firmware_ver` 96 to 97.
- GBL-level diff: eight bytes (the three above, the APP_INFO version, and the
  internal CRC in the END tag).
- GBL body CRC32 residue exactly `0x2144DF1C` (verified with streaming zlib
  over the whole body, the same method the bootloader parser uses).
- ELF diff: three bytes total. Linker map byte-identical to v96, so the
  layout is unchanged by construction.
- The OTA wrapper (56-byte ZCL header plus a u16 tag / u32 length subelement)
  was repaired early in the investigation after a real packaging bug, and
  byte-serving was reconstructed from coordinator logs with matching SHA.

## Format findings worth reusing

These came out of parsing real Tuya MG21 images (wincover relay, ZS5 UART,
ZB21S3 dimmer) and our own builds. They may save you the week they cost us:

1. **Tuya GBL files are not 4-byte padded between tags.** Walk tags as
   `offset + 8 + length` exactly. A padding-aware walker desynchronizes on
   the big ERASEPROG tag and produces garbage.
2. **GBL `ERASEPROG` payload is `u32 flashAddress` followed by data.** The
   three chunks above reconstruct the entire programmed flash image.
3. **The OTA subelement header is 2-byte tag + 4-byte length (6 bytes), not 8.**
4. **AAT layout verified against Tuya sources** (`cstartup-common.c`):
   VECTOR_TABLE at +0x14 (0x4200), sizeof at +0x1b (0xac), appProperties
   pointer at +0x34, `customerApplicationVersion` at +0x58.
5. **The 16 bytes at the start of `appProperties` are the standard Silicon
   Labs `APPLICATION_PROPERTIES_MAGIC`.** We briefly believed they were a
   proprietary Tuya marker. They are not; the GSDK magic is what you should
   expect. (This correction was forced by adversarial review and is the kind
   of error worth publishing.)
6. Production Tuya MG21 images exist in both classes in the public index:
   the wincover relay is encrypted and ECDSA-signed (ENC_INIT, ENC_DATA,
   SIGNATURE tags), while ZS5 and ZB21S3 are plaintext. Per-product choice is
   real at the distribution level. The Gecko Bootloader makes signature and
   encryption enforcement a per-build bootloader configuration (documented,
   default off).

## The lead we killed with disassembly

We found what looked like a door: the prebuilt `libtuya_sdk.a` contains an
`ota-bootload-soc.o` object, the map shows `emberSendBootloadMessage` and
`TOKEN_MFG_BOOTLOAD_AES_KEY` symbols, and the classic Ember over-air
bootloader launch (AN760) would be exactly the kind of mesh-local command
worth trying. We disassembled the object instead of probing the device:

```text
00000000 <emberAfOtaBootloadCallback>:
  0: push {r3, lr}
  2: bl   halAppBootloaderInstallNewImage
  6: movs r0, #1
  8: pop  {r3, pc}
```

Ten bytes that call the standard OTA image installer. No protocol, no AES
challenge, no XMODEM, no flash read. And the map symbols we had relied on sit
in the "Discarded input sections" region: never linked. The incoming bootload
handler that IS linked in our image is `bx lr`, an empty function. No legacy
door exists in this build. We are publishing the refutation because a
plausible-sounding door that turns out empty is exactly what someone else
will rediscover.

## Hypotheses that remain

None of these is a diagnosis. Each is compatible with both rejections:

1. Per-build signature/encryption enforcement in the stock bootloader
   (configurable in Gecko Bootloader, default off in stock Silabs builds;
   unknown for this product). Two unsigned images failing is consistent with
   it, and so is a demo-key-signed image failing: the enforcement would check
   against a burned-in Tuya key, not the public example key.
2. A vendor `parser_applicationUpgradeValidCallback` rejecting on productId,
   type, or any product-specific field (the extension point exists; the stock
   implementation is not available to us).
3. Anti-rollback against an internal highest-version register we never
   measured (the OTA fileVersion 80 does not reveal it).
4. Parser/storage context mismatch of a kind we have not enumerated.

What we have excluded: container structure, GBL CRC, served-byte corruption,
address overlap with the bootloader, and version alignment as a sufficient
condition.

## What would settle it

- A genuine stock OTA image for this lineage (class disclosure: signed,
  encrypted, or plaintext). We requested it publicly in
  [Koenkk/zigbee-OTA#1372](https://github.com/Koenkk/zigbee-OTA/issues/1372);
  nothing exists in public indexes. The remaining capture path is a rooted
  Tuya gateway relaying the cloud update URL.
- A physical dump of any Tuya Silabs light (SWD or bootloader UART). We
  excluded opening devices from this project, so we did not qualify this
  path. Note that a debug unlock on a locked EFR32 can mass-erase, which
  destroys the very stock image you want.
- Anyone with knowledge of Tuya's Silabs bootloader provisioning policy for
  lighting products. Issues welcome.

## Related work

- [analienx/tuya-ts0505b-router-firmware](https://github.com/analienx/tuya-ts0505b-router-firmware):
  custom firmware for TS0505B, a newer generation with a different OTA identity
  (0x100B / 0x020C). Different product line; its success does not transfer to
  TS0505A.
- [romasku/tuya-zigbee-switch](https://github.com/romasku/tuya-zigbee-switch):
  custom firmware for Tuya Telink and some Silabs devices. Their OTA migration
  images are Telink-only (`board.mk` excludes Silabs); Silabs targets are
  flashed by wire, bootloader plus app.
- [pvvx/ZigbeeTLc](https://github.com/pvvx/ZigbeeTLc): the Telink ecosystem
  shows what open Tuya hardware looks like (BLE first flash, debug pin without
  readout protection). None of those properties hold for this bulb.

## Repository contents

- `evidence/` the verification battery (`verify_v97_build.py`), the post-link
  version patcher (`patch_v97_inner_version.py`), and the filtered run logs
  of both rejected updates.
- `analysis/` the investigation write-ups, including the adversarial review
  that corrected our own claims (kept verbatim on purpose). The write-ups are
  in Italian; this README carries their essential findings in English.

Reproduction: the battery is baseline-pinned to the published v96 hashes and
fails loudly if fed the wrong baseline or an unpatched ELF (there is a
negative test described in the header). It needs only Python 3 and the two
binaries referenced inside it.

## Credits and conduct

All experiments ran on our own devices, on our own network, with the risk
formally accepted before each flash. The sacrificial bulb survived every step
and is back on stock duty. Questions and additions: please open an issue.
