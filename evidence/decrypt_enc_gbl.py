#!/usr/bin/env python3
"""Decrypt an encrypted Tuya/Silabs GBL (type 0x101) using the image-file
encryption key tokens from a stock bootloader dump.

Scheme (from GSDK platform/bootloader/security/btl_security_aes.c):
AES-CTR, counter block = flags(0x02) || nonce(12B) || counter(3B, big-endian,
starts at 1), keystream CONTINUOUS across all ENC_GBL_DATA tags.
Inputs: bootloader dump (key at 0xBE3C0 per FUN_0000015c literal), OTA file.
Usage: python3 decrypt_enc_gbl.py <bootloader_dump.bin> <file.ota> <out.bin>
"""
import os, struct, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

dump, ota_path, out_path = sys.argv[1:4]
key = open(dump,'rb').read()[0xBE3C0:0xBE3D0]
d = open(ota_path,'rb').read()
assert struct.unpack('<I', d[:4])[0] == 0x0BEEF11E, "not an OTA file (magic 0x0BEEF11E missing)"
hlen = struct.unpack('<H', d[6:8])[0]
assert hlen >= 56, "short OTA header"
g = d[hlen+6:]
nonce = None; chunks = []; declared_len = None; ended = False
off = 0
while off + 8 <= len(g):
    t, l = struct.unpack('<II', g[off:off+8])
    if t == 0x03A617EB and off != 0:
        raise AssertionError("container tag outside offset 0")
    if t == 0xFA0606FA:
        assert l == 16, "ENC_INIT length != 16"
        assert nonce is None, "multiple ENC_INIT tags"
        declared_len = struct.unpack('<I', g[off+8:off+12])[0]
        nonce = g[off+12:off+24]
    if t == 0xF90707F9:
        chunks.append(g[off+8:off+8+l])
    if t == 0xFC0404FC:
        ended = True
        break
    off += 8 + l
assert nonce is not None, "no ENC_INIT tag"
assert ended, "no END tag"
stream = b''.join(chunks)
assert len(stream) == declared_len, f"declared ENC_INIT length {declared_len} != ciphertext {len(stream)}"
assert not os.path.exists(out_path), f"refusing to overwrite existing {out_path}"
def ks(n):
    out=b''; i=1
    while len(out)<n:
        block = bytes([0x02]) + nonce + i.to_bytes(3,'big')
        c=Cipher(algorithms.AES(key), modes.CTR(block))
        out+=c.encryptor().update(b'\x00'*16); i+=1
    return out[:n]
pt = bytes(a^b for a,b in zip(stream, ks(len(stream))))
first = pt[:4]
assert first == b'\xf4\x0a\x0a\xf4', f"decrypted stream does not start with APPLICATION tag (got {first.hex()})"
open(out_path,'wb').write(pt)
print("decrypted inner GBL:", len(pt), "bytes ->", out_path)
