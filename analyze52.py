#!/usr/bin/env python3
"""Differential CRC attack on the UPG integrity fields + boundary-region hunt.

Key insight: for a fixed CRC setup (poly/refin/refout) and SAME-LENGTH messages,
CRC(m1,init,xorout) ^ CRC(m2,init,xorout) = CRC0(m1) ^ CRC0(m2) — init and xorout
CANCEL. C009/C013 share equal-length header/prefix/footer/entry-header regions,
so we can test whether first4/trailer/footer-u16 are CRCs of those regions
WITHOUT knowing init/xorout, across the whole CRC16/CRC32 catalog. A hit proves
the field covers only that metadata region (not the code) and lets us solve for
init afterwards. Also sweeps boundary regions ([0:n-2], [0:0x3FE], ...) that
analyze47/50/51 missed, plus version/model/timestamp string targets.
Usage: python3 analyze52.py <raw_c009.UPG> <dec_c009.bin> <raw_c013.UPG> <dec_c013.bin>"""
import sys, struct

def mk32(poly, refin):
    t = []
    for i in range(256):
        if refin:
            c = i
            for _ in range(8): c = (c >> 1) ^ (poly if c & 1 else 0)
        else:
            c = i << 24
            for _ in range(8): c = ((c << 1) ^ poly) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        t.append(c)
    return t

def c32(d, t, refin):
    c = 0
    if refin:
        for b in d: c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    else:
        for b in d: c = ((c << 8) & 0xFFFFFFFF) ^ t[((c >> 24) ^ b) & 0xFF]
    return c

def mk16(poly, refin):
    t = []
    for i in range(256):
        if refin:
            c = i
            for _ in range(8): c = (c >> 1) ^ (poly if c & 1 else 0)
        else:
            c = i << 8
            for _ in range(8): c = ((c << 1) ^ poly) & 0xFFFF if c & 0x8000 else (c << 1) & 0xFFFF
        t.append(c)
    return t

def c16(d, t, refin):
    c = 0
    if refin:
        for b in d: c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    else:
        for b in d: c = ((c << 8) & 0xFFFF) ^ t[((c >> 8) ^ b) & 0xFF]
    return c

P32 = [('CRC32', 0xEDB88320, True), ('CRC32-BE', 0x04C11DB7, False),
       ('CRC32C', 0x82F63B78, True), ('CRC32C-BE', 0x1EDC6F41, False),
       ('CRC32K', 0x741B8CD7, True), ('CRC32K-BE', 0x814141AB, False),
       ('CRC32Q', 0x814141AB, False), ('CRC32D', 0xD5828281, True)]
P16 = [('CCITT', 0x1021, False), ('CCITT-refl', 0x8408, True), ('IBM', 0x8005, False),
       ('IBM-refl', 0xA001, True), ('DNP', 0x3D65, True), ('DNP-BE', 0xA6BC, False),
       ('T10', 0x8BB7, False), ('PROFIBUS', 0x1DCF, False), ('DECT', 0x0589, False),
       ('DECT-refl', 0x91A0, True), ('RIELLO-poly', 0x1021, True)]
T32 = {n: mk32(p, r) for n, p, r in P32}
T16 = {n: mk16(p, r) for n, p, r in P16}

raw1 = open(sys.argv[1], 'rb').read(); dec1 = open(sys.argv[2], 'rb').read()
raw2 = open(sys.argv[3], 'rb').read(); dec2 = open(sys.argv[4], 'rb').read()
n1, n2 = len(dec1), len(dec2)

def fields(dec, n):
    return (struct.unpack_from('<I', dec, 0x400)[0],
            struct.unpack_from('<H', dec, n - 2)[0],
            struct.unpack_from('>H', dec, n - 2)[0],
            struct.unpack_from('<H', dec, 0x3FE)[0])
f1 = fields(dec1, n1); f2 = fields(dec2, n2)
print(f"C009 first4=0x{f1[0]:08X} trLE=0x{f1[1]:04X} trBE=0x{f1[2]:04X} foot=0x{f1[3]:04X}")
print(f"C013 first4=0x{f2[0]:08X} trLE=0x{f2[1]:04X} trBE=0x{f2[2]:04X} foot=0x{f2[3]:04X}")
d32 = f1[0] ^ f2[0]
d16 = [f1[i] ^ f2[i] for i in (1, 2, 3)]
print(f"deltas: first4=0x{d32:08X} trLE=0x{d16[0]:04X} trBE=0x{d16[1]:04X} foot=0x{d16[2]:04X}")

# equal-length regions across revisions (offsets valid in both)
REG = [(0x00, 0x58, 'hdr[0:58]'), (0x02, 0x58, 'hdr[2:58]'), (0x00, 0x02, 'keyhdr[0:2]'),
       (0x58, 0x3EA, 'prefix[58:3EA]'), (0x3EA, 0x400, 'footer[3EA:400]'),
       (0x3EA, 0x3F2, 'footer-txt[3EA:3F2]'), (0x3EA, 0x3FE, 'footer-nocheck[3EA:3FE]'),
       (0x3F2, 0x3F6, 'lenfield[3F2:3F6]'), (0x3F6, 0x3FE, 'zeros[3F6:3FE]'),
       (0x400, 0x40A, 'entryhdr[400:40A]'), (0x400, 0x404, 'entry4[400:404]'),
       (0x404, 0x40A, 'entry6[404:40A]'), (0x00, 0x400, 'pre-code[0:400]'),
       (0x00, 0x40A, 'pre-code+entry[0:40A]'), (0x02, 0x400, 'hdr2..footer[2:400]'),
       (0x58, 0x400, 'prefix+footer[58:400]'), (0x00, 0x3FE, 'all-before-footcheck[0:3FE]'),
       (0x02, 0x3FE, 'hdr2-before-footcheck[2:3FE]'), (0x58, 0x3FE, 'prefix..footcheck[58:3FE]')]

print("\n== differential CRC32 (first4) — init/xorout cancel ==")
hit = False
for src, s1, s2 in (('dec', dec1, dec2), ('raw', raw1, raw2)):
    for a, b, rn in REG:
        r1, r2 = s1[a:b], s2[a:b]
        for cn, p, ri in P32:
            if c32(r1, T32[cn], ri) ^ c32(r2, T32[cn], ri) == d32:
                print(f"  HIT first4 = {cn}({src}.{rn}) ^ const(init,xorout)"); hit = True
if not hit: print("  none")

print("\n== differential CRC16 (trLE / trBE / footer) — init/xorout cancel ==")
hit = False
for src, s1, s2 in (('dec', dec1, dec2), ('raw', raw1, raw2)):
    for a, b, rn in REG:
        r1, r2 = s1[a:b], s2[a:b]
        for cn, p, ri in P16:
            d = c16(r1, T16[cn], ri) ^ c16(r2, T16[cn], ri)
            for tn, tv in zip(('trLE', 'trBE', 'footer'), d16):
                if d == tv:
                    print(f"  HIT {tn} = crc16/{cn}({src}.{rn}) ^ const(init,xorout)"); hit = True
if not hit: print("  none")

print("\n== differential sum/xor (same-length regions) ==")
hit = False
for src, s1, s2 in (('dec', dec1, dec2), ('raw', raw1, raw2)):
    for a, b, rn in REG:
        r1, r2 = s1[a:b], s2[a:b]
        ds16 = (sum(r1) - sum(r2)) & 0xFFFF
        ds32 = (sum(r1) - sum(r2)) & 0xFFFFFFFF
        dx16 = 0; dx32 = 0
        for i in range(0, len(r1) - 1, 2):
            dx16 ^= struct.unpack_from('<H', r1, i)[0] ^ struct.unpack_from('<H', r2, i)[0]
        for i in range(0, len(r1) - 3, 4):
            dx32 ^= struct.unpack_from('<I', r1, i)[0] ^ struct.unpack_from('<I', r2, i)[0]
        for tn, tv in zip(('trLE', 'trBE', 'footer'), d16):
            if ds16 == tv: print(f"  HIT {tn} = sum16({src}.{rn}) + const"); hit = True
            if dx16 == tv: print(f"  HIT {tn} = xor16({src}.{rn}) ^ const"); hit = True
        if ds32 == d32: print(f"  HIT first4 = sum32({src}.{rn}) + const"); hit = True
        if dx32 == d32: print(f"  HIT first4 = xor32({src}.{rn}) ^ const"); hit = True
if not hit: print("  none")

print("\n== boundary-region catalog sweep (single-image, standard setups) ==")
def crc32_full(d, t, init, refin, refout, xo):
    c = init
    if refin:
        for b in d: c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    else:
        for b in d: c = ((c << 8) & 0xFFFFFFFF) ^ t[((c >> 24) ^ b) & 0xFF]
    if refout != refin:
        r = 0
        for _ in range(32): r = (r << 1) | (c & 1); c >>= 1
        c = r
    return c ^ xo
def crc16_full(d, t, init, refin, refout, xo):
    c = init
    if refin:
        for b in d: c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    else:
        for b in d: c = ((c << 8) & 0xFFFF) ^ t[((c >> 8) ^ b) & 0xFF]
    if refout != refin:
        r = 0
        for _ in range(16): r = (r << 1) | (c & 1); c >>= 1
        c = r
    return c ^ xo
S32 = [('CRC32', 0xEDB88320, True, 0xFFFFFFFF, True, 0xFFFFFFFF),
       ('BZIP2', 0x04C11DB7, False, 0xFFFFFFFF, False, 0xFFFFFFFF),
       ('MPEG2', 0x04C11DB7, False, 0xFFFFFFFF, False, 0),
       ('JAM', 0xEDB88320, True, 0xFFFFFFFF, True, 0),
       ('CRC32/0', 0xEDB88320, True, 0, True, 0xFFFFFFFF),
       ('CRC32C', 0x82F63B78, True, 0xFFFFFFFF, True, 0xFFFFFFFF),
       ('CRC32C/JAM', 0x82F63B78, True, 0xFFFFFFFF, True, 0)]
S16 = [('CCITT-FALSE', 0x1021, False, 0xFFFF, False, 0), ('XMODEM', 0x1021, False, 0, False, 0),
       ('KERMIT', 0x8408, True, 0, True, 0), ('X-25', 0x8408, True, 0xFFFF, True, 0xFFFF),
       ('MODBUS', 0xA001, True, 0xFFFF, True, 0), ('ARC', 0xA001, True, 0, True, 0),
       ('MAXIM', 0xA001, True, 0, True, 0xFFFF), ('USB', 0xA001, True, 0xFFFF, True, 0xFFFF),
       ('DNP', 0x3D65, True, 0, True, 0xFFFF), ('T10-DIF', 0x8BB7, False, 0, False, 0),
       ('CRC-A', 0x8408, True, 0xC6C6, True, 0), ('RIELLO', 0x8408, True, 0xB2AA, True, 0),
       ('TMS37157', 0x8408, True, 0x89EC, True, 0), ('AUG-CCITT', 0x1021, False, 0x1D0F, False, 0),
       ('GENIBUS', 0x1021, False, 0xFFFF, False, 0xFFFF), ('PROFIBUS', 0x1DCF, False, 0xFFFF, False, 0xFFFF),
       ('MCRF4XX', 0x8408, True, 0xFFFF, True, 0), ('DECT', 0x0589, False, 0, False, 0x0001)]
TT32 = {p: mk32(p, r) for _, p, r, _, _, _ in S32}
TT16 = {p: mk16(p, r) for _, p, r, _, _, _ in S16}
for tag, raw, dec, n, f in (('C009', raw1, dec1, n1, f1), ('C013', raw2, dec2, n2, f2)):
    regs = {}
    for name, src in (('dec', dec), ('raw', raw)):
        for a, b, rt in [(0x00, n - 2, 'img[0:n-2]'), (0x02, n - 2, 'img[2:n-2]'),
                         (0x400, n - 2, 'code+entry[400:n-2]'), (0x404, n - 2, 'code[404:n-2]'),
                         (0x40A, n - 2, 'code[40A:n-2]'), (0x58, n - 2, 'prefix+code[58:n-2]'),
                         (0x00, 0x3FE, 'all-before-footcheck[0:3FE]'), (0x02, 0x3FE, 'hdr2..[2:3FE]'),
                         (0x58, 0x3FE, 'prefix..[58:3FE]'), (0x3EA, 0x3FE, 'footer-nocheck[3EA:3FE]')]:
            regs[f'{name}.{rt}'] = src[a:b]
        # version / model / timestamp strings as regions
        hdr = src[2:0x58]
        for line in hdr.split(b'\r\n'):
            if line.startswith(b'$$'):
                regs[f'{name}.str({line[2:14].decode("ascii","replace")})'] = line[2:]
    hit = False
    for rn, rd in regs.items():
        for cn, p, ri, init, ro, xo in S32:
            v = crc32_full(rd, TT32[p], init, ri, ro, xo)
            if v == f[0]: print(f"  [{tag}] first4 = {cn}({rn})"); hit = True
        for cn, p, ri, init, ro, xo in S16:
            v = crc16_full(rd, TT16[p], init, ri, ro, xo)
            for tn, tv in zip(('trLE', 'trBE', 'footer'), f[1:]):
                if v == tv: print(f"  [{tag}] {tn} = crc16/{cn}({rn})"); hit = True
        s16 = sum(rd) & 0xFFFF; s32 = sum(rd) & 0xFFFFFFFF
        for tn, tv in zip(('trLE', 'trBE', 'footer'), f[1:]):
            if s16 == tv: print(f"  [{tag}] {tn} = sum16({rn})"); hit = True
        if s32 == f[0]: print(f"  [{tag}] first4 = sum32({rn})"); hit = True
    if not hit: print(f"  [{tag}] none")
