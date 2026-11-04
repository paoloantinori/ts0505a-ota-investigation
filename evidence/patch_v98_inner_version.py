#!/usr/bin/env python3
"""TASK-13 round11: patch inner application version to 98 on the linked ELF.

Structural metadata patch per astra review par. 8 (ota-invalid-image-review-astra-2026-11-03.md):
  1. appProperties (0x3c86c, inside .rodata, ELF file offset 0x04c86c):
     app.version at +0x20: 1 -> 98
  2. .aat (0x4000, ELF file offset 0x014000):
     customerApplicationVersion at +0x58: 1 -> 98

Every anchor field is asserted before patching; the script refuses to run on
anything but the expected v98 pre-patch ELF. Post-conditions: the diff against
the pre-patch content is non-empty, falls entirely inside the two 4-byte
version windows (only the changed bytes differ; 01 00 00 00 -> 62 00 00 00
touches one byte per field), and both fields read NEW_VERSION.

Usage: patch_v98_inner_version.py ELF_PATH
"""
import sys

APPPROPS_OFF = 0x04C86C
AAT_OFF = 0x014000
NEW_VERSION = 98

EXPECTED_APPPROPS = {
    0x00: bytes.fromhex("13b779fac925ddb7adf3cfe0f1b614b8"),
    0x10: bytes.fromhex("0101"),
    0x18: bytes.fromhex("ffffffff"),
    0x1C: bytes.fromhex("01000000"),
    0x20: bytes.fromhex("01000000"),
}
EXPECTED_AAT = {
    0x14: bytes.fromhex("00420000"),
    0x1B: bytes.fromhex("ac"),
    0x34: bytes.fromhex("6cc80300"),
    0x58: bytes.fromhex("01000000"),
}
WINDOWS = set(range(APPPROPS_OFF + 0x20, APPPROPS_OFF + 0x24)) | set(
    range(AAT_OFF + 0x58, AAT_OFF + 0x5C)
)


def die(msg):
    raise SystemExit(f"ERROR: {msg} (usage: patch_v98_inner_version.py ELF_PATH)")


def check(data, base, field_map, label):
    for off, want in field_map.items():
        got = data[base + off : base + off + len(want)]
        if got != want:
            die(f"{label}+{off:#x}: expected {want.hex()} got {got.hex()} (wrong ELF?)")


def main():
    if len(sys.argv) != 2:
        die("exactly one ELF path required")
    path = sys.argv[1]
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())
    except OSError as e:
        die(f"cannot read {path}: {e}")

    check(data, APPPROPS_OFF, EXPECTED_APPPROPS, "appProperties")
    check(data, AAT_OFF, EXPECTED_AAT, ".aat")
    print("pre-patch asserts: PASS (all anchor fields match expected pre-patch layout)")

    before = bytes(data)
    with open(path + ".prepatch", "wb") as f:
        f.write(before)

    data[APPPROPS_OFF + 0x20 : APPPROPS_OFF + 0x24] = NEW_VERSION.to_bytes(4, "little")
    data[AAT_OFF + 0x58 : AAT_OFF + 0x5C] = NEW_VERSION.to_bytes(4, "little")

    with open(path, "wb") as f:
        f.write(data)

    diff = [i for i in range(len(before)) if before[i] != data[i]]
    if not diff or not all(i in WINDOWS for i in diff):
        with open(path, "wb") as f:  # restore: leave the ELF unpatched on failure
            f.write(before)
        die(f"diff outside the two version windows (ELF restored from backup): {[hex(i) for i in diff]}")
    app_v = int.from_bytes(data[APPPROPS_OFF + 0x20 : APPPROPS_OFF + 0x24], "little")
    aat_v = int.from_bytes(data[AAT_OFF + 0x58 : AAT_OFF + 0x5C], "little")
    if app_v != NEW_VERSION or aat_v != NEW_VERSION:
        with open(path, "wb") as f:  # restore: leave the ELF unpatched on failure
            f.write(before)
        die(f"fields not at NEW_VERSION: app={app_v} aat={aat_v} (ELF restored from backup)")
    print(f"patched: {len(diff)} changed byte(s) at {[hex(i) for i in sorted(diff)]}")
    print(f"appProperties.app.version = {app_v}")
    print(f".aat.customerApplicationVersion = {aat_v}")


if __name__ == "__main__":
    main()
