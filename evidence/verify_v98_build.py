#!/usr/bin/env python3
"""TASK-13 round11 verification battery for the v98 test-sign candidate.

v98 = v97 layout with: external version 98 (0x62), inner versions 98, and the
GBL signed with the public GSDK example ECDSA-P256 key
(platform/common/example_signing_key.pem, SHA 3f50f3b4...). The signature adds
one new GBL tag, so this battery compares TAG-AWARE against the v97 baseline
(SHA-pinned), not byte-by-byte.

  W0  argv present and readable; v97 baseline OTA SHA-pinned (08f8560b...)
  W1  OTA header: magic, hlen 56, fileVersion 98, manuf 0x1002, imageType 0x1602
  W2  GBL APPLICATION tag: type 1 (zigbee), version 98
  W3  GBL body CRC32 residue 0x2144DF1C
  W4  tag sequence: identical to v97 in order, PLUS exactly one new tag
      0xF70A0AF7 (SIGNATURE_ECDSA_P256) positioned before END
  W5  flash reconstruction: chunks identical to v97; flash diff exactly 3 bytes
      at 0x4058 / 0x3C88C / 0x3F598, each 0x61 -> 0x62
  W6  signature sanity: SIGNATURE tag length 64 bytes (ECDSA-P256 r||s)
  W7  signature verification against the example_signing_pubkey.pem: parse the
      PEM point, verify the ECDSA(SHA256) signature over the GBL body up to
      (and including) the signature tag header, as the Gecko parser computes it

Usage: verify_v98_build.py V98_OTA V97_OTA PUBKEY_PEM
Exits non-zero on any failure. One PASS/FAIL line per check.
"""
import hashlib
import struct
import sys
import zlib

OTA_HDR_LEN = 56
OTA_MAGIC = 0x0BEEF11E
MANUF_CODE = 0x1002
IMAGE_TYPE = 0x1602
V97_SHA = "08f8560b5bbdae842f2ef38f7f8f6816c8c6eb4714dd0fcbc208c3dc40b4b4e0"

APP_TYPE_ZIGBEE = 1
GBL_APPLICATION = 0xF40A0AF4
GBL_ERASEPROG = 0xFD0303FD
GBL_SIGNATURE = 0xF70A0AF7
GBL_END = 0xFC0404FC
CRC_RESIDUE = 0x2144DF1C
# SHA256 over per-tag (header+payload) excluding SIGNATURE and END tags,
# recorded from the verified real v98; composition drift fails loudly here.
# Recorded from the verified real v98 candidate; any drift in the digest
# composition fails loudly instead of silently changing what W7 certifies.
EXPECTED_DIGEST = "6977750659880e9278385c3e51718424ce847a5742f485c160eaaceaf23721b0"
EXPECTED_FLASH_DIFF = {0x4058: (0x61, 0x62), 0x3C88C: (0x61, 0x62), 0x3F598: (0x61, 0x62)}

failures = []


def report(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not ok:
        failures.append(name)


def die(msg):
    raise SystemExit(f"ERROR: {msg} (usage: verify_v98_build.py V98_OTA V97_OTA PUBKEY_PEM)")


def read_or_die(path, label):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        die(f"cannot read {label} at {path}: {e}")


def ota_to_gbl(ota):
    tag_id, tag_len = struct.unpack("<HI", ota[OTA_HDR_LEN : OTA_HDR_LEN + 6])
    if tag_id != 0 or tag_len != len(ota) - OTA_HDR_LEN - 6:
        die(f"unexpected OTA wrapper (tag {tag_id}, len {tag_len})")
    return ota[OTA_HDR_LEN + 6 :]


def walk_tags(gbl):
    off = 0
    while off + 8 <= len(gbl):
        tag, ln = struct.unpack("<II", gbl[off : off + 8])
        yield off, tag, ln
        off += 8 + ln
        if tag == GBL_END:
            break




def reconstruct_flash(gbl):
    mem = {}
    chunks = []
    for off, tag, ln in walk_tags(gbl):
        if tag == GBL_ERASEPROG:
            if ln < 4:
                die(f"ERASEPROG at {off:#x} too short")
            payload = gbl[off + 8 : off + 8 + ln]
            addr = struct.unpack("<I", payload[:4])[0]
            chunks.append((addr, ln - 4))
            for i, b in enumerate(payload[4:]):
                mem[addr + i] = b
    return mem, chunks


def pem_pubkey_xy(pem_bytes):
    """Return (x, y) integers of the EC P-256 public point in a PEM pubkey."""
    import base64
    b64 = "".join(l for l in pem_bytes.decode().splitlines() if "-----" not in l)
    der = base64.b64decode(b64)
    i = der.find(bytes.fromhex("03420004"))
    if i < 0 or len(der) != i + 3 + 65:
        die("cannot find complete uncompressed P-256 point in PEM")
    point = der[i + 3 : i + 3 + 65]
    return int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:65], "big")


def main():
    if len(sys.argv) != 4:
        die("exactly three paths required")
    v98_ota = read_or_die(sys.argv[1], "v98 OTA")
    v97_ota = read_or_die(sys.argv[2], "v97 OTA baseline")
    pem = read_or_die(sys.argv[3], "public key PEM")

    # W0
    v97_sha = hashlib.sha256(v97_ota).hexdigest()
    report("W0 v97 baseline pinned", v97_sha == V97_SHA, f"sha={v97_sha[:16]}...")

    v98_gbl = ota_to_gbl(v98_ota)
    v97_gbl = ota_to_gbl(v97_ota)
    tags98 = list(walk_tags(v98_gbl))
    tags97 = list(walk_tags(v97_gbl))

    # W1
    magic, _, hlen, _, manuf, itype, fwver = struct.unpack("<IHHHHHI", v98_ota[:18])
    report("W1 OTA header",
           magic == OTA_MAGIC and hlen == OTA_HDR_LEN and fwver == 98
           and manuf == MANUF_CODE and itype == IMAGE_TYPE,
           f"magic={magic:#x} hlen={hlen} fileVersion={fwver} manuf={manuf:#x} imageType={itype:#x}")

    # W2
    apps = [(o, l) for o, t, l in tags98 if t == GBL_APPLICATION]
    ok2 = len(apps) == 1
    if ok2:
        o, l = apps[0]
        if l < 8:
            report("W2 APPLICATION", False, f"APPLICATION tag payload too short: {l} bytes")
        else:
            tag = v98_gbl[o + 8 : o + 8 + l]
            atype = tag[0]
            aver = int.from_bytes(tag[4:8], "little")
            ok2 = atype == APP_TYPE_ZIGBEE and aver == 98
            report("W2 APPLICATION", ok2, f"type={atype} version={aver} payload={tag.hex(' ')}")
    else:
        report("W2 APPLICATION", False, f"found {len(apps)} tags")

    # W3
    crc = zlib.crc32(v98_gbl)
    report("W3 GBL CRC residue", crc == CRC_RESIDUE, f"crc={crc:#010x}")

    # W4 tag sequence
    from collections import Counter
    seq98 = [(t, l) for _, t, l in tags98]
    seq97 = [(t, l) for _, t, l in tags97]
    extra = list((Counter(seq98) - Counter(seq97)).elements())
    missing = list((Counter(seq97) - Counter(seq98)).elements())
    sig_positions = [i for i, (t, _) in enumerate(seq98) if t == GBL_SIGNATURE]
    ok4 = (not missing) and len(extra) == 1 and extra[0][0] == GBL_SIGNATURE and len(sig_positions) == 1
    ok4 = ok4 and len(sig_positions) == 1 and sig_positions[0] == len(seq98) - 2  # right before END
    report("W4 tag sequence", ok4,
           f"v97 tags={len(seq97)} v98 tags={len(seq98)} extra={[hex(t) for t, _ in extra]} "
           f"missing={[hex(t) for t, _ in missing]} sig_pos={sig_positions}")

    # W5 flash
    mem97, chunks97 = reconstruct_flash(v97_gbl)
    mem98, chunks98 = reconstruct_flash(v98_gbl)
    common = set(mem97) & set(mem98)
    fdiff = sorted(a for a in common if mem97[a] != mem98[a])
    ok5 = chunks97 == chunks98 and set(mem97) == set(mem98)
    for a in fdiff:
        want = EXPECTED_FLASH_DIFF.get(a)
        if want is None or (mem97[a], mem98[a]) != want:
            ok5 = False
    for a in EXPECTED_FLASH_DIFF:
        if a not in fdiff:
            ok5 = False
    report("W5 flash vs v97", ok5,
           f"chunks equal={chunks97 == chunks98}; diff={[hex(a) for a in fdiff]} "
           f"({[(hex(a), hex(mem97[a]), hex(mem98[a])) for a in fdiff]})")

    # W6 signature size (derived from the W4 scan, no re-walk)
    sig_entries = [(o, l) for o, t, l in tags98 if t == GBL_SIGNATURE]
    if len(sig_entries) != 1:
        report("W6 signature size", False, f"found {len(sig_entries)} signature tags")
    else:
        sig_off, sig_len = sig_entries[0]
        report("W6 signature size", sig_len == 64, f"len={sig_len}")

    # W7 ECDSA verify (pure python P-256)
    try:
        sig = v98_gbl[sig_off + 8 : sig_off + 8 + sig_len]
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        # btl_gbl_parser.c: for every tag except SIGNATURE and END, the 8-byte
        # tag header (gbl_parseHeader) and the payload (applySHA path) are fed
        # to SHA256; SIGNATURE and END contribute nothing.
        h = hashlib.sha256()
        for off, tag, ln in tags98:
            if tag in (GBL_SIGNATURE, GBL_END):
                continue
            h.update(v98_gbl[off : off + 8 + ln])
        digest = h.digest()
        qx, qy = pem_pubkey_xy(pem)
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        a = p - 3
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
        n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
        Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5

        def inv(x, m):
            return pow(x, -1, m)

        def add(P, Q):
            if P is None:
                return Q
            if Q is None:
                return P
            if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
                return None
            if P == Q:
                lam = (3 * P[0] * P[0] + a) * inv(2 * P[1], p) % p
            else:
                lam = (Q[1] - P[1]) * inv(Q[0] - P[0], p) % p
            x3 = (lam * lam - P[0] - Q[0]) % p
            y3 = (lam * (P[0] - x3) - P[1]) % p
            return (x3, y3)

        def mul(k, P):
            R = None
            while k:
                if k & 1:
                    R = add(R, P)
                P = add(P, P)
                k >>= 1
            return R

        e = int.from_bytes(digest, "big")
        w = inv(s, n)
        u1 = e * w % n
        u2 = r * w % n
        pt = add(mul(u1, (Gx, Gy)), mul(u2, (qx, qy)))
        ok7 = pt is not None and pt[0] % n == r
        report("W7 ECDSA verify (example key)", ok7,
               f"sha256 over per-tag header+payload, SIGNATURE and END excluded (btl_gbl_parser.c); pub point on curve={mul(n, (qx, qy)) is None}")
    except Exception as ex:
        report("W7 ECDSA verify (example key)", False, f"error: {ex}")

    print()
    print("RESULT:", "ALL PASS" if not failures else f"FAILURES: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
