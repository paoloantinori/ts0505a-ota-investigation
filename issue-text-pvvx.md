Question about Tuya firmware on Silabs EFR32 (not Telink): has anyone ever dumped one?

Your ZigbeeTLc work shows what open Tuya hardware looks like on TLSR825x: BLE
first flash, SWS without readout protection, full dumps traded openly. We are
stuck on the other chip family and wonder if this community has ever seen the
Silabs side.

We built custom firmware from the public Tuya Zigbee SDK for Lidl Livarno Lux
TS0505A lights (EFR32MG21 / ZS3L, OTA identity 0x1002 / 0x1602 / stock
fileVersion 80). Two verified images (internal version 1 and internal version
97 aligned everywhere) were fully downloaded by the bulb and both rejected by
the bootloader with upgradeEndRequest status 150 (0x96 INVALID_IMAGE). The
device survives unharmed on stock.

We documented the whole thing, byte level:
https://github.com/paoloantinori/ts0505a-ota-investigation (format findings
for Tuya GBL, the exact three-byte diffs between our candidates, and a lead we
killed by disassembling ota-bootload-soc.o).

Questions for anyone who has touched Tuya Silabs firmware:

1. Has anyone obtained a dump (any path: gateway, debug, provider tooling) of
   a Tuya EFR32 lighting product, even a different model?
2. Is anything known about how Tuya provisions the Gecko Bootloader for
   lighting products (signature/encryption enforcement flags, secure boot)
   beyond the stock Silabs defaults?
3. The TS0505B generation accepts custom OTA (analienx project, different OTA
   identity). Has anyone explained why the TS0505A generation does not?

We are not looking for a bypass. We want one stock image or one dump to
compare against.
