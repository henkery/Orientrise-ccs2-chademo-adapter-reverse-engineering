#!/usr/bin/env python3
"""UPG prefix-footer / integrity analysis (bootloader entry contract, REPORT 4.1/5.6).

Reinterprets the plaintext footer at decoded 0x3EA..0x400:
  - u32 @0x3F2 as a payload LENGTH (hypothesis: filesize - 0x404, i.e. the code
    from 0x400 excluding a 4-byte trailer; matches the boot log UPGRADE:[594112])
  - last 4 image bytes as a possible CRC32 of the code
  - u16 @0x3FE as a possible CRC16/sum over header/prefix/code regions
Also compares the encrypted prefixes of two revisions: identical ciphertext =>
deterministic keystream + identical plaintext (vector table reuse is then safe).

Usage: python3 analyze44.py <raw_c009.UPG> <raw_c013.UPG>
"""
import sys, struct, zlib
from decode_upg import decode, derive_key, parse_header

def crc16(data, poly, init, refin, refout, xorout):
    def rev(x, n):
        r = 0
        for _ in range(n):
            r = (r << 1) | (x & 1); x >>= 1
        return r
    crc = init
    for b in data:
        if refin: b = rev(b, 8)
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ poly) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    if refout: crc = rev(crc, 16)
    return crc ^ xorout

CRC16S = {  # name: (poly, init, refin, refout, xorout)
    'CCITT-FALSE': (0x1021, 0xFFFF, False, False, 0x0000),
    'XMODEM':      (0x1021, 0x0000, False, False, 0x0000),
    'AUG-CCITT':   (0x1021, 0x1D0F, False, False, 0x0000),
    'KERMIT':      (0x1021, 0x0000, True,  True,  0x0000),
    'X-25':        (0x1021, 0xFFFF, True,  True,  0xFFFF),
    'MODBUS':      (0x8005, 0xFFFF, True,  True,  0x0000),
    'ARC/IBM':     (0x8005, 0x0000, True,  True,  0x0000),
    'MAXIM':       (0x8005, 0x0000, True,  True,  0xFFFF),
    'USB':         (0x8005, 0xFFFF, True,  True,  0xFFFF),
    'DNP':         (0x3D65, 0x0000, True,  True,  0xFFFF),
    'T10-DIF':     (0x8BB7, 0x0000, False, False, 0x0000),
    'TELEDISK':    (0xA097, 0x0000, False, False, 0x0000),
    'CRC-A':       (0x1021, 0xC6C6, True,  True,  0x0000),
    'RIELLO':      (0x1021, 0xB2AA, True,  True,  0x0000),
    'TMS37157':    (0x1021, 0x89EC, True,  True,  0x0000),
}

def sum16(d): return sum(d) & 0xFFFF
def xor16(d):
    v = 0
    for i in range(0, len(d) - 1, 2): v ^= d[i] | (d[i+1] << 8)
    if len(d) & 1: v ^= d[-1]
    return v
def fletcher16(d):
    a = b = 0
    for x in d: a = (a + x) % 255; b = (b + a) % 255
    return (b << 8) | a

def regions(dec, raw):
    n = len(dec)
    return {
        'hdr[00:58]':            dec[0x00:0x58],
        'prefix_ct[58:3EA]':     dec[0x58:0x3EA],
        'hdr+ct[00:3EA]':        dec[0x00:0x3EA],
        'all-but-ck[00:3FE]':    dec[0x00:0x3FE],
        'code[400:end-4]':       dec[0x400:n-4],
        'code[400:end]':         dec[0x400:n],
        'img[00:end-4]':         dec[0x00:n-4],
        'img[02:end-4]':         dec[0x02:n-4],
        'img[00:end-2]':         dec[0x00:n-2],
        'raw[00:end-2]':         raw[0x00:n-2],
        'raw_ct[58:3EA]':        raw[0x58:0x3EA],
        'raw_code[400:end-4]':   raw[0x400:n-4],
    }

def main():
    raws = [open(p, 'rb').read() for p in sys.argv[1:3]]
    decs = [decode(r) for r in raws]
    for name, raw, dec in zip(('IMG-A', 'IMG-B'), raws, decs):
        n = len(dec)
        print(f"== {name}: {len(raw)} B, key {derive_key(raw).hex(' ')}, fields {parse_header(dec)}")
        print(f"   footer 0x3E0..0x400: {dec[0x3E0:0x400].hex(' ')}")
        ln = struct.unpack_from('<I', dec, 0x3F2)[0]
        ck = struct.unpack_from('<H', dec, 0x3FE)[0]
        tail = struct.unpack_from('<I', dec, n-4)[0]
        print(f"   u32@3F2 = {ln} (0x{ln:X});  len-0x404 = {n-0x404};  len-0x400 = {n-0x400};"
              f"  match-0x404: {ln == n-0x404}")
        print(f"   u16@3FE = 0x{ck:04X};  last4 = 0x{tail:08X} ({dec[n-4:].hex(' ')})")
        print(f"   last 32 B: {dec[n-32:].hex(' ')}")
        # CRC32 hypotheses for the trailer
        for rn, rd in regions(dec, raw).items():
            c = zlib.crc32(rd) & 0xFFFFFFFF
            if c == tail:
                print(f"   [CRC32 MATCH] last4 == crc32({rn})")
            if c & 0xFFFF == ck: print(f"   [u16~crc32lo] {rn}")
            if (c >> 16) & 0xFFFF == ck: print(f"   [u16~crc32hi] {rn}")
        # CRC16 / sum hypotheses for the footer u16
        hits = []
        for rn, rd in regions(dec, raw).items():
            for cn, p in CRC16S.items():
                if crc16(rd, *p) == ck: hits.append(f"crc16/{cn}({rn})")
            if sum16(rd) == ck: hits.append(f"sum16({rn})")
            if xor16(rd) == ck: hits.append(f"xor16({rn})")
            if fletcher16(rd) == ck: hits.append(f"fletcher16({rn})")
        print(f"   u16 candidates: {hits if hits else 'NONE'}")
    a, b = decs
    pa, pb = a[0x58:0x3EA], b[0x58:0x3EA]
    same = sum(x == y for x, y in zip(pa, pb))
    print(f"== prefix ciphertext compare: {same}/{len(pa)} bytes equal")
    if same != len(pa):
        diffs = [i for i, (x, y) in enumerate(zip(pa, pb)) if x != y]
        print(f"   first diffs at prefix offsets {[hex(d) for d in diffs[:16]]} (image off +0x58)")
        runs = []
        s = diffs[0]; p = diffs[0]
        for d in diffs[1:]:
            if d != p + 1: runs.append((s, p)); s = d
            p = d
        runs.append((s, p))
        print(f"   diff runs (prefix-relative): {[(hex(s), hex(e)) for s, e in runs[:24]]}")
    print(f"== header equal: {a[:0x58] == b[:0x58]};  footer[3EA:3FE] equal: {a[0x3EA:0x3FE] == b[0x3EA:0x3FE]}")

if __name__ == '__main__':
    main()
