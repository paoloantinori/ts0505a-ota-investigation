#!/usr/bin/env python3
"""TASK-13.1 verification battery for the v97 candidate.

Runs on bird against build/ts0505a_fw_OTA_1.2.1.bin + build/dev.out,
with the approved v96 baseline (SHA-pinned below) at /tmp/v96_ota.bin and
/tmp/v96_dev.out.

  V0  input sanity: argv present and readable, baselines match the pinned
      SHA-256 hashes from MANIFEST (a bad baseline fails distinctly from a
      bad candidate)
  V1  GBL APPLICATION tag: type==1 (zigbee), version==97 (from patched appProperties)
  V2  OTA wrapper header: magic, header length 56, fileVersion==97, manuf 0x1002,
      imageType 0x1602, total size identical to v96
  V3  GBL CRC32 (zlib over whole GBL body) residue 0x2144DF1C
  V4  flash reconstruction from ERASEPROG tags (Tuya GBL: tags are NOT padded,
      each payload = u32 flash address + data): diff v96 vs v97 must be exactly
      3 bytes at 0x4058 (.aat customerApplicationVersion), 0x3C88C
      (appProperties.app.version) and 0x3F598 (g_firmware_ver in .data);
      chunk map must be identical
  V5  GBL byte diff over the FULL body (equal lengths required): only the
      APPLICATION version window, the 3 V4 flash bytes, and the END-tag CRC
  V6  ELF diff v96 vs v97 (equal lengths required): exactly 2 bytes in the
      patch windows plus the g_firmware_ver bump byte at file offset 0x545dc
      (.data LMA), each bump byte 0x60 -> 0x61

Every check prints one PASS/FAIL line and the battery exits non-zero on any
failure. Usage: verify_v97_build.py V97_OTA V97_ELF
"""
import hashlib
import struct
import sys
import zlib

OTA_HDR_LEN = 56
OTA_MAGIC = 0x0BEEF11E
MANUF_CODE = 0x1002
IMAGE_TYPE = 0x1602
APP_TYPE_ZIGBEE = 1
V96_OTA = "/tmp/v96_ota.bin"
V96_OTA_SHA = "b57b959d4343b1b9094a1be839eab81077386e6e759693422daba6bd36e35d80"
V96_ELF = "/tmp/v96_dev.out"
V96_ELF_SHA = "6007206ce6fea630898efcd3241cf14fdea3097776ef76a7884a3bd44caed80a"

GBL_APPLICATION = 0xF40A0AF4
GBL_ERASEPROG = 0xFD0303FD
GBL_END = 0xFC0404FC
CRC_RESIDUE = 0x2144DF1C
APPPROPS_VER_FLASH = 0x3C88C
AAT_VER_FLASH = 0x4058
G_FW_VER_FLASH = 0x3F598  # g_firmware_ver (.data LMA), external version byte 0x60->0x61
G_FW_VER_ELF_OFF = 0x545DC
EXPECTED_FLASH_DIFF = {
    AAT_VER_FLASH: (0x01, 0x61),
    APPPROPS_VER_FLASH: (0x01, 0x61),
    G_FW_VER_FLASH: (0x60, 0x61),
}
ELF_PATCH_WINDOWS = set(range(0x04C88C, 0x04C890)) | set(range(0x014058, 0x01405C))

failures = []


def report(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not ok:
        failures.append(name)


def die(msg):
    raise SystemExit(f"ERROR: {msg} (usage: verify_v97_build.py V97_OTA V97_ELF)")


def read_or_die(path, label):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        die(f"cannot read {label} at {path}: {e}")


def ota_to_gbl(ota):
    tag_id, tag_len = struct.unpack("<HI", ota[OTA_HDR_LEN : OTA_HDR_LEN + 6])
    if tag_id != 0 or tag_len != len(ota) - OTA_HDR_LEN - 6:
        die(f"unexpected OTA wrapper in input (tag {tag_id}, len {tag_len})")
    return ota[OTA_HDR_LEN + 6 :]


def walk_tags(gbl):
    off = 0
    while off + 8 <= len(gbl):
        tag, ln = struct.unpack("<II", gbl[off : off + 8])
        yield off, tag, ln
        off += 8 + ln
        if tag == GBL_END:
            break


def find_app_tags(gbl):
    return [(o, l) for o, t, l in walk_tags(gbl) if t == GBL_APPLICATION]


def eraseprog_addr_map(gbl):
    """File offset inside an ERASEPROG data payload -> flash address."""
    m = {}
    for off, tag, ln in walk_tags(gbl):
        if tag == GBL_ERASEPROG:
            if ln < 4:
                die(f"ERASEPROG tag at {off:#x} shorter than its address field")
            addr = struct.unpack("<I", gbl[off + 8 : off + 12])[0]
            for i in range(off + 12, off + 8 + ln):
                m[i] = addr + (i - off - 12)
    return m


def reconstruct_flash(gbl):
    chunks = []
    mem = {}
    for off, tag, ln in walk_tags(gbl):
        if tag == GBL_ERASEPROG:
            payload = gbl[off + 8 : off + 8 + ln]
            if ln < 4:
                die(f"ERASEPROG tag at {off:#x} shorter than its address field")
            addr = struct.unpack("<I", payload[:4])[0]
            chunks.append((addr, ln - 4))
            for i, b in enumerate(payload[4:]):
                mem[addr + i] = b
    return mem, chunks


def diff_indices(a, b):
    return [i for i in range(len(a)) if a[i] != b[i]]


def main():
    if len(sys.argv) != 3:
        die("exactly two paths required")
    v97_ota = read_or_die(sys.argv[1], "v97 OTA")
    v97_elf = read_or_die(sys.argv[2], "v97 ELF")

    # V0: baseline sanity, distinct from candidate failures
    v96_ota = read_or_die(V96_OTA, "v96 OTA baseline")
    v96_elf = read_or_die(V96_ELF, "v96 ELF baseline")
    ota_sha = hashlib.sha256(v96_ota).hexdigest()
    elf_sha = hashlib.sha256(v96_elf).hexdigest()
    report("V0 baselines pinned", ota_sha == V96_OTA_SHA and elf_sha == V96_ELF_SHA,
           f"v96_ota={ota_sha[:16]}... (want b57b959d...) "
           f"v96_elf={elf_sha[:16]}... (want 6007206c...)")
    if failures:
        print()
        print("RESULT:", "FAILURES:", failures, "(fix baselines before judging the candidate)")
        sys.exit(1)

    v97_gbl = ota_to_gbl(v97_ota)
    v96_gbl = ota_to_gbl(v96_ota)

    # V1
    app_entries = find_app_tags(v97_gbl)
    if len(app_entries) != 1:
        report("V1 APPLICATION tag", False, f"found {len(app_entries)} tags")
    else:
        o, l = app_entries[0]
        app_tag = v97_gbl[o + 8 : o + 8 + l]
        atype = app_tag[0]
        aver = int.from_bytes(app_tag[4:8], "little")
        report("V1 GBL APPLICATION", atype == APP_TYPE_ZIGBEE and aver == 97,
               f"type={atype} version={aver} payload={app_tag.hex(' ')}")

    # V2
    magic, _, hlen, _, manuf, itype, fwver = struct.unpack("<IHHHHHI", v97_ota[:18])
    report("V2 OTA header",
           magic == OTA_MAGIC and hlen == OTA_HDR_LEN and fwver == 97
           and manuf == MANUF_CODE and itype == IMAGE_TYPE
           and len(v97_ota) == len(v96_ota),
           f"magic={magic:#x} hlen={hlen} fileVersion={fwver} manuf={manuf:#x} "
           f"imageType={itype:#x} size={len(v97_ota)} (v96 {len(v96_ota)})")

    # V3
    crc = zlib.crc32(v97_gbl)
    report("V3 GBL CRC residue", crc == CRC_RESIDUE,
           f"crc32(body)={crc:#010x} expected {CRC_RESIDUE:#010x}")

    # V4
    mem96, chunks96 = reconstruct_flash(v96_gbl)
    mem97, chunks97 = reconstruct_flash(v97_gbl)
    common = set(mem96) & set(mem97)
    flash_diff = sorted(a for a in common if mem96[a] != mem97[a])
    ok4 = chunks96 == chunks97 and set(mem96) == set(mem97)
    for a in flash_diff:
        want = EXPECTED_FLASH_DIFF.get(a)
        if want is None or (mem96[a], mem97[a]) != want:
            ok4 = False
    for a in EXPECTED_FLASH_DIFF:
        if a not in flash_diff:
            ok4 = False
    report("V4 flash reconstruction", ok4,
           f"chunks v96={[(hex(a), l) for a, l in chunks96]} "
           f"v97={[(hex(a), l) for a, l in chunks97]}; "
           f"flash diff={[hex(a) for a in flash_diff]} "
           f"(v96byte->v97byte: "
           f"{[(hex(a), hex(mem96[a]), hex(mem97[a])) for a in flash_diff]})")

    # V5 (full-body diff; equal lengths required)
    if len(v96_gbl) != len(v97_gbl):
        report("V5 GBL byte diff", False,
               f"GBL lengths differ: v96={len(v96_gbl)} v97={len(v97_gbl)}")
    else:
        gbl_diff = diff_indices(v96_gbl, v97_gbl)
        v96_app = find_app_tags(v96_gbl)
        if len(v96_app) != 1:
            report("V5 GBL byte diff", False, "v96 APPLICATION tag not unique")
        else:
            app_off = v96_app[0][0]
            app_ver_win = set(range(app_off + 12, app_off + 16))
            crc_win = set(range(len(v96_gbl) - 4, len(v96_gbl)))
            addr_map = eraseprog_addr_map(v96_gbl)
            mapped = []
            unmapped = []
            for i in gbl_diff:
                if i in app_ver_win or i in crc_win:
                    continue
                fa = addr_map.get(i)
                (mapped if fa is not None else unmapped).append(fa if fa is not None else i)
            ok5 = (not unmapped) and all(fa in EXPECTED_FLASH_DIFF for fa in mapped)
            report("V5 GBL byte diff", ok5,
                   f"diff bytes={len(gbl_diff)}, APP_INFO version window="
                   f"{len([i for i in gbl_diff if i in app_ver_win])}, "
                   f"ERASEPROG-mapped={[hex(f) for f in mapped]}, "
                   f"GBL-CRC(END)={len([i for i in gbl_diff if i in crc_win])}"
                   f"{', unmapped=' + str([hex(i) for i in unmapped]) if unmapped else ''}")

    # V6
    if len(v96_elf) != len(v97_elf):
        report("V6 ELF diff", False,
               f"ELF lengths differ: v96={len(v96_elf)} v97={len(v97_elf)}")
    else:
        ediffs = diff_indices(v96_elf, v97_elf)
        in_patch = sorted(i for i in ediffs if i in ELF_PATCH_WINDOWS)
        bumps = sorted(i for i in ediffs if i not in ELF_PATCH_WINDOWS)
        ok6 = (set(in_patch) == {0x04C88C, 0x014058}
               and bumps == [G_FW_VER_ELF_OFF]
               and all(v96_elf[i] == 0x60 and v97_elf[i] == 0x61 for i in bumps))
        report("V6 ELF diff", ok6,
               f"total={len(ediffs)} patch_bytes={[hex(i) for i in in_patch]} "
               f"external_bump={[hex(i) for i in bumps]} at .data "
               f"(g_firmware_ver, each 0x60->0x61)")

    print()
    print("RESULT:", "ALL PASS" if not failures else f"FAILURES: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
