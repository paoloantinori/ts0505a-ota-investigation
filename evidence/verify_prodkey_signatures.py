#!/usr/bin/env python3
"""Verify GBL SIGNATURE tags against known Tuya/Silabs P-256 public keys.

Evidence for analysis/bootloader-signature-policy-ts0222-dump_2026-11-17.md.
Keys are read from two 64-byte x||y files (default /tmp paths, override in code):
- production key extracted from the TS0222 stock bootloader key tokens (0xBE34C/0xBE36C)
- Silicon Labs example_signing_key.pem public point (negative control)

Usage: python3 verify_prodkey_signatures.py <file.ota|file.gbl> [...]
Accepts Zigbee OTA files (0x0BEEF11E wrapper) and raw GBLs. Walks GBL tags
without padding (Tuya GBLs are not 4-byte padded between tags), extracts the
64-byte r||s from the SIGNATURE tag (0xF70A0AF7), and tries three hash-span
variants: body up to and including the signature tag header, body up to the
signature tag (excl header), whole GBL including signature.
"""
import struct, hashlib, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def load_xy(path):
    b = open(path,'rb').read()
    assert len(b)==64
    return int.from_bytes(b[:32],'big'), int.from_bytes(b[32:],'big')

import os; _here = os.path.dirname(os.path.abspath(__file__))
PROD = load_xy(os.path.join(_here,'prodkey_ts0222_xy.bin'))
EXAMPLE = load_xy(os.path.join(_here,'example_key_xy.bin'))
TAG = {'APPLICATION':0xF40A0AF4,'ERASEPROG':0xFD0303FD,'END':0xFC0404FC,
       'SIGNATURE':0xF70A0AF7,'CONTAINER':0x03A617EB,'UNKNOWN_F509':0xF50909F5,
       'UNKNOWN_F608':0xF60808F6,'UNKNOWN_F709':0xF70909F7,'UNKNOWN_F907':0xF90707F9,
       'ENC_FA06':0xFA0606FA,'ENC_FE01':0xFE0101FE}

def unwrap_ota(d):
    if struct.unpack('<I', d[:4])[0] != 0x0BEEF11E:
        return d  # raw GBL
    hlen = struct.unpack('<H', d[6:8])[0]
    tag, ln = struct.unpack('<HI', d[hlen:hlen+6])
    assert tag == 0x0000, f"unexpected subelement tag {tag:#x}"
    return d[hlen+6 : hlen+6+ln]

def walk(g):
    tags = []; off = 0
    while off + 8 <= len(g):
        t, l = struct.unpack('<II', g[off:off+8])
        tags.append((off, t, l))
        if t == 0xFC0404FC:
            break
        off += 8 + l
    return tags

def verify(g, so, key, label):
    x, y = key
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    r = int.from_bytes(g[so+8:so+40], 'big')
    s = int.from_bytes(g[so+40:so+72], 'big')
    der = encode_dss_signature(r, s)
    variants = [("up-to-and-incl-sig-header", g[:so+8]),
                ("up-to-sig-tag-excl-header", g[:so]),
                ("whole-gbl-incl-sig", g)]
    for name, body in variants:
        h = hashlib.sha256(body).digest()
        try:
            pub.verify(der, h, ec.ECDSA(Prehashed(hashes.SHA256())))
            print(f"  [{label}] VALID   su {name}")
            return name
        except InvalidSignature:
            print(f"  [{label}] invalid su {name}")
        except Exception as e:
            print(f"  [{label}] errore  su {name}: {type(e).__name__}")
    return None

for path in sys.argv[1:]:
    d = open(path,'rb').read()
    name = path.split('/')[-1]
    g = unwrap_ota(d)
    print(f"\n== {name}: GBL {len(g)} bytes ==")
    tags = walk(g)
    for off,t,l in tags:
        label = next((k for k,v in TAG.items() if v==t), f"0x{t:08X}")
        print(f"  0x{off:06x}: {label:12} len {l}")
    sigs = [o for o,t,l in tags if t == 0xF70A0AF7]
    if not sigs:
        print("  NESSUN tag SIGNATURE")
        continue
    so = sigs[0]
    print(f"  r={g[so+8:so+24].hex()}... s={g[so+40:so+56].hex()}...")
    verify(g, so, PROD, "PROD-KEY")
    verify(g, so, EXAMPLE, "EXAMPLE-KEY")
