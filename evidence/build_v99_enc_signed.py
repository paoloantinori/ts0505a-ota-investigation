#!/usr/bin/env python3
"""E2 builder: v99 = v98 content rewrapped as an ENCRYPTED+SIGNed GBL (type 0x101).

Goal: discriminate which ECDSA verification key the TS0505A bootloader/SE
holds, by serving the only container shape never tried (all five prior
candidates were unencrypted). Encryption uses the Tuya family AES-128 key
extracted from the TS0222 bootloader dump (token at 0xBE3C0; the same key
decrypts the wincover 1.0.7 container). Signature uses the PUBLIC GSDK
example key (whose private half ships openly), exactly like v98.

Container layout (mirrors the wincover 1.0.7 production container):
  HEADER_V3 (type bits 0x101: ENCRYPTION_AESCCM | SIGNATURE_ECDSA)
  ENC_INIT  (16B: declared plaintext length u32 LE || 12B nonce)
  ENC_GBL_DATA (one chunk: AES-CTR keystream 0x02||nonce||ctr3BE-from-1,
                continuous, encrypting the inner tag stream APPLICATION +
                ERASEPROG with inner version bumped to 99)
  SIGNATURE (64B r||s, ECDSA-P256/SHA-256 over per-tag header+payload of
             every tag except SIGNATURE and END, i.e. GBL[0:sig_off])
  END + trailing CRC32 word such that zlib.crc32(whole GBL) == 0x2144DF1C
Zigbee OTA wrapper: v98 header with fileVersion 99 and total size updated,
then {u16 0, u32 len(gbl)} and the GBL.

Structural asserts throughout; refuses to overwrite the output.
Usage: build_v99_enc_signed.py <v98_ota.bin> <bootloader_dump.bin> <example_signing_key.pem> <out_ota.bin>
"""
import hashlib
import os
import struct
import sys
import zlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
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
NEW_VERSION = 99
V98_SHA = "eadeb8a139833d5ac6e36ae01ae195db3577277cd565ece63873ceca2d4118f5"
KEY_DUMP_OFFSET = 0xBE3C0
# flash addresses carrying the version byte inside the ERASEPROG image
# (v97->v98 diff was exactly these three, 0x61->0x62; v98->v99 is 0x62->0x63)
FLASH_VERSION_ADDRS = (0x4058, 0x3C88C, 0x3F598)


def die(msg):
    raise SystemExit(f"ERROR: {msg} (usage: build_v99_enc_signed.py V98_OTA DUMP PRIVKEY OUT)")


def walk_tags(gbl):
    off = 0
    while off + 8 <= len(gbl):
        tag, ln = struct.unpack("<II", gbl[off : off + 8])
        yield off, tag, ln
        off += 8 + ln
        if tag == GBL_END:
            break


def keystream(key, nonce, n):
    out = b""
    i = 1
    while len(out) < n:
        block = bytes([0x02]) + nonce + i.to_bytes(3, "big")
        c = Cipher(algorithms.AES(key), modes.CTR(block))
        out += c.encryptor().update(b"\x00" * 16)
        i += 1
    return out[:n]


def main():
    if len(sys.argv) != 5:
        die("exactly four paths required")
    v98_path, dump_path, priv_path, out_path = sys.argv[1:5]
    v98 = open(v98_path, "rb").read()
    if hashlib.sha256(v98).hexdigest() != V98_SHA:
        die("v98 OTA SHA mismatch")
    if os.path.exists(out_path):
        die(f"refusing to overwrite existing {out_path}")  # double check before exclusive create below
    key = open(dump_path, "rb").read()[KEY_DUMP_OFFSET : KEY_DUMP_OFFSET + 16]

    # --- parse v98 OTA header and GBL -------------------------------------
    magic, hver, hlen, fctl, manuf, itype, fwver = struct.unpack("<IHHHHHI", v98[:18])
    if magic != 0x0BEEF11E or hlen != OTA_HDR_LEN or manuf != 0x1002 or itype != 0x1602 or fwver != 98:
        die(f"unexpected v98 OTA header: magic={magic:#x} hlen={hlen} manuf={manuf:#x} itype={itype:#x} fw={fwver}")
    wt, wl = struct.unpack("<HI", v98[hlen : hlen + 6])
    if wt != 0 or wl != len(v98) - hlen - 6:
        die(f"unexpected OTA wrapper tag {wt} len {wl}")
    g98 = v98[hlen + 6 :]

    tags98 = list(walk_tags(g98))
    hdr98 = [(o, l) for o, t, l in tags98 if t == GBL_HEADER_V3]
    apps98 = [(o, l) for o, t, l in tags98 if t == GBL_APPLICATION]
    sigs98 = [(o, l) for o, t, l in tags98 if t == GBL_SIGNATURE]
    if len(hdr98) != 1 or len(apps98) != 1 or len(sigs98) != 1:
        die(f"v98 tag shape unexpected: hdr={len(hdr98)} app={len(apps98)} sig={len(sigs98)}")
    if zlib.crc32(g98) != CRC_RESIDUE:
        die("v98 GBL CRC residue mismatch")
    if len(g98) % 4 != 0:
        die("v98 GBL not 4-byte aligned")

    # --- HEADER_V3 with type bits 0x101 -----------------------------------
    h_off, h_len = hdr98[0]
    hdr_payload = bytearray(g98[h_off + 8 : h_off + 8 + h_len])
    if len(hdr_payload) < 8:
        die("HEADER_V3 payload too short")
    h_version = struct.unpack("<I", hdr_payload[0:4])[0]
    h_type = struct.unpack("<I", hdr_payload[4:8])[0]
    if h_type != 0x100:
        die(f"v98 HEADER_V3 type is {h_type:#x}, expected 0x100 (signed, unencrypted)")
    struct.pack_into("<I", hdr_payload, 4, 0x101)

    # --- inner tag stream: APPLICATION (version 99) + ERASEPROG -----------
    a_off, a_len = apps98[0]
    app_payload = bytearray(g98[a_off + 8 : a_off + 8 + a_len])
    if len(app_payload) < 8 or app_payload[0] != 1:
        die(f"v98 APPLICATION tag shape unexpected: {app_payload.hex()}")
    old_v = int.from_bytes(app_payload[4:8], "little")
    if old_v != 98:
        die(f"v98 APPLICATION version is {old_v}, expected 98")
    struct.pack_into("<I", app_payload, 4, NEW_VERSION)

    inner = b""
    inner += struct.pack("<II", GBL_APPLICATION, len(app_payload)) + bytes(app_payload)
    patched_flash = []
    for o, t, l in tags98:
        if t == GBL_ERASEPROG:
            payload = bytearray(g98[o + 8 : o + 8 + l])
            addr = struct.unpack("<I", payload[:4])[0]
            for fa in FLASH_VERSION_ADDRS:
                idx = 4 + (fa - addr)
                if 0 <= idx < len(payload):
                    if payload[idx] != 0x62:
                        die(f"flash byte at {fa:#x} is {payload[idx]:#x}, expected 0x62 (v98)")
                    payload[idx] = 0x63
                    patched_flash.append(hex(fa))
            inner += struct.pack("<II", t, l) + bytes(payload)
    if not inner:
        die("no ERASEPROG in v98")
    if sorted(patched_flash) != sorted(hex(a) for a in FLASH_VERSION_ADDRS):
        die(f"expected to patch {len(FLASH_VERSION_ADDRS)} flash version bytes, patched {patched_flash}")

    # --- encrypt -----------------------------------------------------------
    nonce = os.urandom(12)
    enc = bytes(a ^ b for a, b in zip(inner, keystream(key, nonce, len(inner))))
    enc_init_payload = struct.pack("<I", len(inner)) + nonce

    # --- assemble GBL body (signature span = everything before SIGNATURE) --
    body = b""
    body += struct.pack("<II", GBL_HEADER_V3, len(hdr_payload)) + bytes(hdr_payload)
    body += struct.pack("<II", GBL_ENC_INIT, len(enc_init_payload)) + enc_init_payload
    body += struct.pack("<II", GBL_ENC_DATA, len(enc)) + enc
    digest = hashlib.sha256(body).digest()

    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

    priv = load_pem_private_key(open(priv_path, "rb").read(), password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey) or priv.curve.name != "secp256r1":
        die("example key is not EC P-256")
    # the bootloader verifies the SHA-256 of the span directly: sign the
    # precomputed digest, never let the API hash it twice
    der_sig = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    # normalize to raw r||s: SEQUENCE { INTEGER r, INTEGER s }, short-form lengths
    if der_sig[0] != 0x30:
        die("unexpected DER signature tag")
    i = 2
    if der_sig[i] != 0x02:
        die("unexpected DER INTEGER tag for r")
    rlen = der_sig[i + 1]
    r = int.from_bytes(der_sig[i + 2 : i + 2 + rlen], "big")
    j = i + 2 + rlen
    if der_sig[j] != 0x02:
        die("unexpected DER INTEGER tag for s")
    slen = der_sig[j + 1]
    s = int.from_bytes(der_sig[j + 2 : j + 2 + slen], "big")
    if r >= 1 << 256 or s >= 1 << 256:
        die("signature component does not fit 32 bytes")
    sig_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

    gbl = body
    gbl += struct.pack("<II", GBL_SIGNATURE, len(sig_raw)) + sig_raw
    # END tag carries the CRC word as its 4-byte payload (layout of v98 and of
    # the wincover production container: zero trailing bytes after END)
    gbl += struct.pack("<II", GBL_END, 4)
    gbl += struct.pack("<I", zlib.crc32(gbl))
    if zlib.crc32(gbl) != CRC_RESIDUE:
        die("CRC append did not produce the expected residue")
    if len(gbl) % 4 != 0:
        die(f"GBL not 4-byte aligned: {len(gbl)}")

    # --- OTA wrapper -------------------------------------------------------
    hdr = bytearray(v98[:OTA_HDR_LEN])
    struct.pack_into("<I", hdr, 14, NEW_VERSION)  # fileVersion
    total = OTA_HDR_LEN + 6 + len(gbl)
    struct.pack_into("<I", hdr, 52, total)  # total image size (offset 52, verified on v98)
    ota = bytes(hdr) + struct.pack("<HI", 0, len(gbl)) + gbl

    fd = os.open(out_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(ota)
    print(f"v99 written: {out_path} ({len(ota)} bytes)")
    print(f"  HEADER_V3 version={h_version} type=0x101")
    print(f"  inner stream {len(inner)} B (APPLICATION v{NEW_VERSION} + ERASEPROG), 1 ENC_GBL_DATA chunk")
    print(f"  signature r||s 64B over GBL[0:{len(body)}] (sha256 {digest.hex()[:16]}...)")
    print(f"  GBL {len(gbl)} B, crc32 residue OK, OTA total={total}")


if __name__ == "__main__":
    main()
