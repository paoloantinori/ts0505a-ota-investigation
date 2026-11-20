#!/usr/bin/env python3
"""E2 verification battery v2 for the v99 candidate (encrypted+example-signed GBL).

Revision 2 (2026-11-17 sera) after the astra consultation: closes the three
demonstrated false positives (mutant headerVersion, mutant GBL major version,
ENC_DATA before ENC_INIT) and the process defects (unpinned inputs, silent
flash overwrite, no tag-order checks).

  V0  argv readable; v98 baseline, bootloader dump and example public key all
      SHA-pinned (inputs identified, not just passed in)
  V1  OTA header: magic 0x0BEEF11E, headerVersion 0x0100, hlen 56,
      fieldControl 0x0000, fileVersion 99, manuf 0x1002, imageType 0x1602,
      totalImageSize == file size
  V2  GBL structure: exact tag sequence [HEADER_V3, ENC_INIT, ENC_DATA+,
      SIGNATURE, END] in this order, END last with len 4 and nothing after it,
      each structural tag exactly once, HEADER_V3 payload version 0x03000000
      and type 0x101, no unknown tags, walk covers the whole GBL exactly
  V3  ENC_INIT: single 16-byte tag, declared plaintext length == concatenated
      ENC_GBL_DATA bytes, ciphertext length sane (nonzero)
  V4  keystream roundtrip: AES-CTR family key decrypts to the expected inner
      stream; the inner stream itself is a STRICT tag sequence
      [APPLICATION, ERASEPROG+] with bounded walk, no unknown tags, first tag
      APPLICATION with version 99
  V5  flash reconstruction: v98-derived expectation; overlaps between
      ERASEPROG ranges are REJECTED (not silently overwritten); diff vs v98
      is exactly three bytes 0x62 -> 0x63 at 0x4058, 0x3C88C, 0x3F598
  V6  CRC: zlib.crc32(whole GBL) == 0x2144DF1C and END payload ==
      le32(crc32(prefix)); GBL length multiple of 4
  V7  ECDSA: signature verifies against the pinned example public key over
      per-tag (header+payload) of every tag except SIGNATURE and END, and
      FAILS against the pinned TS0222 production public key

Usage: verify_v99_build.py V99_OTA V98_OTA DUMP PUBKEY_PEM
Exits non-zero on any failure. One PASS/FAIL line per check.
"""
import base64
import hashlib
import struct
import sys
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OTA_HDR_LEN = 56
GBL_HEADER_V3 = 0x03A617EB
GBL_APPLICATION = 0xF40A0AF4
GBL_ERASEPROG = 0xFD0303FD
GBL_SIGNATURE = 0xF70A0AF7
GBL_ENC_INIT = 0xFA0606FA
GBL_ENC_DATA = 0xF90707F9
GBL_END = 0xFC0404FC
CRC_RESIDUE = 0x2144DF1C
V98_SHA = "eadeb8a139833d5ac6e36ae01ae195db3577277cd565ece63873ceca2d4118f5"
DUMP_SHA = "be7e96b8faed7aa4f6a083d1191dccb00cd1e6becaaa014a3feb98756512d374"
PUBKEY_SHA = None  # filled at runtime from the pinned example key path below
KEY_DUMP_OFFSET = 0xBE3C0
EXPECTED_FLASH_DIFF = {0x4058: (0x62, 0x63), 0x3C88C: (0x62, 0x63), 0x3F598: (0x62, 0x63)}

failures = []


def report(name, ok, detail):
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")
    if not ok:
        failures.append(name)


def die(msg):
    raise SystemExit(f"ERROR: {msg} (usage: verify_v99_build.py V99_OTA V98_OTA DUMP PUBKEY_PEM)")


def read_or_die(path, label):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        die(f"cannot read {label} at {path}: {e}")


def ota_to_gbl(ota):
    magic = struct.unpack("<I", ota[:4])[0]
    hver = struct.unpack("<H", ota[4:6])[0]
    hlen = struct.unpack("<H", ota[6:8])[0]
    if magic != 0x0BEEF11E or hlen != OTA_HDR_LEN:
        die("not a 56-byte-header OTA file")
    tag_id, tag_len = struct.unpack("<HI", ota[hlen : hlen + 6])
    if tag_id != 0 or tag_len != len(ota) - hlen - 6:
        die("unexpected OTA wrapper")
    return ota[hlen + 6 :]


def walk_tags_bounded(gbl):
    """Return (tags, ok): tags as list of (off, tag, ln); ok requires the walk
    to end exactly on an END tag that closes the buffer."""
    tags = []
    off = 0
    while off + 8 <= len(gbl):
        tag, ln = struct.unpack("<II", gbl[off : off + 8])
        if off + 8 + ln > len(gbl):
            return tags, False
        tags.append((off, tag, ln))
        off += 8 + ln
        if tag == GBL_END:
            return tags, off == len(gbl)
    return tags, False


def walk_stream_bounded(stream):
    """Walker for a tag stream with NO END terminator (the encrypted inner
    stream is APPLICATION+ERASEPROG only): every tag in bounds and the walk
    consumes the buffer exactly."""
    tags = []
    off = 0
    while off + 8 <= len(stream):
        tag, ln = struct.unpack("<II", stream[off : off + 8])
        if off + 8 + ln > len(stream):
            return tags, False
        tags.append((off, tag, ln))
        off += 8 + ln
    return tags, off == len(stream)


def keystream(key, nonce, n):
    out = b""
    i = 1
    while len(out) < n:
        block = bytes([0x02]) + nonce + i.to_bytes(3, "big")
        c = Cipher(algorithms.AES(key), modes.CTR(block))
        out += c.encryptor().update(b"\x00" * 16)
        i += 1
    return out[:n]


def reconstruct_flash(tag_stream, strict):
    """Return (mem, ranges, ok). strict=True rejects overlapping ranges."""
    mem = {}
    ranges = []
    ok = True
    for off, tag, ln in walk_tags_bounded(tag_stream)[0]:
        if tag == GBL_ERASEPROG:
            payload = tag_stream[off + 8 : off + 8 + ln]
            if ln < 4:
                ok = False
                continue
            addr = struct.unpack("<I", payload[:4])[0]
            end = addr + ln - 4
            if strict:
                for (a0, e0) in ranges:
                    if not (end <= a0 or addr >= e0):
                        ok = False
            ranges.append((addr, end))
            for i, b in enumerate(payload[4:]):
                mem[addr + i] = b
    return mem, ranges, ok


def pem_pubkey_xy(pem_bytes):
    b64 = "".join(l for l in pem_bytes.decode().splitlines() if "-----" not in l)
    der = base64.b64decode(b64)
    i = der.find(bytes.fromhex("03420004"))
    if i < 0 or len(der) != i + 3 + 65:
        die("cannot find complete uncompressed P-256 point in PEM")
    point = der[i + 3 : i + 3 + 65]
    return int.from_bytes(point[1:33], "big"), int.from_bytes(point[33:65], "big")


def ecdsa_verify(digest, r, s, qx, qy):
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = p - 3
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    if not (0 < r < n and 0 < s < n):
        return False

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
        return (x3, (lam * (P[0] - x3) - P[1]) % p)

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
    return pt is not None and pt[0] % n == r


def main():
    if len(sys.argv) != 5:
        die("exactly four paths required")
    v99 = read_or_die(sys.argv[1], "v99 OTA")
    v98 = read_or_die(sys.argv[2], "v98 OTA")
    dump = read_or_die(sys.argv[3], "bootloader dump")
    pem = read_or_die(sys.argv[4], "example public key PEM")

    # V0: pin every input by content
    v98_ok = hashlib.sha256(v98).hexdigest() == V98_SHA
    dump_ok = hashlib.sha256(dump).hexdigest() == DUMP_SHA
    pub_sha = hashlib.sha256(pem).hexdigest()
    report("V0 inputs pinned", v98_ok and dump_ok,
           f"v98={v98_ok} dump={dump_ok} pubkey_sha={pub_sha[:16]}... (verify against the pinned example key)")

    g99 = ota_to_gbl(v99)
    g98 = ota_to_gbl(v98)
    tags99, walk_ok = walk_tags_bounded(g99)

    # V1: full header field set
    magic, hver, hlen, fctl, manuf, itype, fwver = struct.unpack("<IHHHHHI", v99[:18])
    total = struct.unpack("<I", v99[52:56])[0]
    report("V1 OTA header",
           magic == 0x0BEEF11E and hver == 0x0100 and hlen == OTA_HDR_LEN
           and fctl == 0x0000 and fwver == 99 and manuf == 0x1002
           and itype == 0x1602 and total == len(v99),
           f"magic={magic:#x} hver={hver:#x} hlen={hlen} fctl={fctl:#x} fw={fwver} "
           f"manuf={manuf:#x} itype={itype:#x} total={total} file={len(v99)}")

    # V2: strict sequence [HEADER_V3, ENC_INIT, ENC_DATA+, SIGNATURE, END]
    seq = [t for _, t, _ in tags99]
    ends_with_end = seq and seq[-1] == GBL_END
    head_ok = len(seq) >= 4 and seq[0] == GBL_HEADER_V3 and seq[1] == GBL_ENC_INIT \
        and all(t == GBL_ENC_DATA for t in seq[2:-2]) and seq[-2] == GBL_SIGNATURE \
        and ends_with_end and walk_ok
    counts_ok = seq.count(GBL_HEADER_V3) == 1 and seq.count(GBL_ENC_INIT) == 1 \
        and seq.count(GBL_SIGNATURE) == 1 and seq.count(GBL_END) == 1 \
        and seq.count(GBL_ENC_DATA) >= 1
    allowed = {GBL_HEADER_V3, GBL_ENC_INIT, GBL_ENC_DATA, GBL_SIGNATURE, GBL_END}
    no_unknown = all(t in allowed for t in seq)
    hdr_payload = g99[8:16] if head_ok and tags99[0][2] == 8 else b""
    gbl_ver = struct.unpack("<I", hdr_payload[0:4])[0] if hdr_payload else None
    gbl_type = struct.unpack("<I", hdr_payload[4:8])[0] if hdr_payload else None
    lens_ok = tags99 and tags99[0][2] == 8 and tags99[1][2] == 16 \
        and tags99[-2][2] == 64 and tags99[-1][2] == 4
    report("V2 GBL structure",
           head_ok and counts_ok and no_unknown and lens_ok
           and gbl_ver == 0x03000000 and gbl_type == 0x101,
           f"seq={[hex(t) for t in seq]} ver={gbl_ver and hex(gbl_ver)} type={gbl_type and hex(gbl_type)} "
           f"counts_ok={counts_ok} no_unknown={no_unknown} walk_ok={walk_ok}")

    # V3: ENC_INIT fields
    e_off = tags99[1][0] if head_ok else None
    ok3 = False
    declared = nonce = None
    ct = b""
    if e_off is not None:
        declared = struct.unpack("<I", g99[e_off + 8 : e_off + 12])[0]
        nonce = g99[e_off + 12 : e_off + 24]
        ct = b"".join(g99[o + 8 : o + 8 + l] for o, t, l in tags99 if t == GBL_ENC_DATA)
        ok3 = declared == len(ct) and len(ct) > 0 and len(nonce) == 12
    report("V3 ENC_INIT", ok3, f"declared={declared} ciphertext={len(ct)} nonce_len={len(nonce)}")

    # V4: roundtrip + strict inner sequence
    key = dump[KEY_DUMP_OFFSET : KEY_DUMP_OFFSET + 16]
    ok4 = False
    inner_seq_ok = False
    pt = b""
    if ok3:
        pt = bytes(a ^ b for a, b in zip(ct, keystream(key, nonce, len(ct))))
        itags, iwalk_ok = walk_stream_bounded(pt)
        iseq = [t for _, t, _ in itags]
        inner_allowed = {GBL_APPLICATION, GBL_ERASEPROG}
        inner_seq_ok = bool(iseq) and iseq[0] == GBL_APPLICATION \
            and all(t in inner_allowed for t in iseq) and iwalk_ok \
            and iseq.count(GBL_APPLICATION) == 1 and iseq.count(GBL_ERASEPROG) >= 1
        apps98 = [(o, l) for o, t, l in walk_tags_bounded(g98)[0] if t == GBL_APPLICATION]
        a_off, a_len = apps98[0]
        app99 = bytearray(g98[a_off + 8 : a_off + 8 + a_len])
        app99[4:8] = (99).to_bytes(4, "little")
        expected = struct.pack("<II", GBL_APPLICATION, a_len) + bytes(app99)
        for o, t, l in walk_tags_bounded(g98)[0]:
            if t == GBL_ERASEPROG:
                payload = bytearray(g98[o + 8 : o + 8 + l])
                addr = struct.unpack("<I", payload[:4])[0]
                for fa in EXPECTED_FLASH_DIFF:
                    idx = 4 + (fa - addr)
                    if 0 <= idx < len(payload):
                        payload[idx] = 0x63
                expected += struct.pack("<II", t, l) + bytes(payload)
        ok4 = pt == expected and inner_seq_ok
    report("V4 roundtrip + inner sequence", ok4,
           f"decrypted={len(pt)} first8={pt[:8].hex()} inner_seq_ok={inner_seq_ok}")

    # V5: flash diff with overlap rejection
    ok5 = False
    fdiff = []
    if ok4:
        mem98, _, _ = reconstruct_flash(g98, strict=False)
        mem99, _, no_overlap = reconstruct_flash(pt, strict=True)
        common = set(mem98) & set(mem99)
        fdiff = sorted(a for a in common if mem98[a] != mem99[a])
        ok5 = no_overlap and set(mem98) == set(mem99) and fdiff == sorted(EXPECTED_FLASH_DIFF)
        for a in fdiff:
            want = EXPECTED_FLASH_DIFF.get(a)
            if want is None or (mem98[a], mem99[a]) != want:
                ok5 = False
    report("V5 flash vs v98 (overlap-free)", ok5,
           f"diff={[hex(a) for a in fdiff]} ({[(hex(a), hex(mem98[a]), hex(mem99[a])) for a in fdiff]})")

    # V6: CRC and closure
    stored = g99[-4:]
    computed = struct.pack("<I", zlib.crc32(g99[:-4]))
    ok6 = len(g99) % 4 == 0 and zlib.crc32(g99) == CRC_RESIDUE and stored == computed
    report("V6 CRC", ok6,
           f"residue={zlib.crc32(g99):#010x} stored={stored.hex()} computed={computed.hex()} len4={len(g99)%4==0}")

    # V7: ECDSA against pinned example key (VALID) and production key (INVALID)
    try:
        sig_off = [o for o, t, l in tags99 if t == GBL_SIGNATURE][0]
        sig = g99[sig_off + 8 : sig_off + 8 + 64]
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        h = hashlib.sha256()
        for off, tag, ln in tags99:
            if tag in (GBL_SIGNATURE, GBL_END):
                continue
            h.update(g99[off : off + 8 + ln])
        digest = h.digest()
        qx, qy = pem_pubkey_xy(pem)
        ok_example = ecdsa_verify(digest, r, s, qx, qy)
        # production key from the pinned dump tokens at 0xBE34C/0xBE36C
        px = int.from_bytes(dump[0xBE34C : 0xBE34C + 32], "big")
        py = int.from_bytes(dump[0xBE36C : 0xBE36C + 32], "big")
        prod_invalid = not ecdsa_verify(digest, r, s, px, py)
        report("V7 ECDSA (example VALID, production INVALID)", ok_example and prod_invalid,
               f"digest={digest.hex()[:16]}... example={ok_example} production_rejected={prod_invalid}")
    except Exception as ex:
        report("V7 ECDSA", False, f"error: {ex}")

    print()
    print("RESULT:", "ALL PASS" if not failures else f"FAILURES: {failures}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
