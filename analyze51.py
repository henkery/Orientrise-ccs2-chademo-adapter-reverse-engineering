#!/usr/bin/env python3
"""Trailing-byte / integrity-field SEMANTICS hunt (does the updater verify a
checksum at all, or are first4/trailer/footer-u16 metadata?).
1) Parse $$ headers of both revisions; test first4@0x400 as a unix build timestamp.
2) CRC/sum/xor hunt over SMALL regions (header, footer, entry header, length
   field) that analyze47/50 did not cover — targets first4, trailer, footer u16.
3) Scan the app image for CRC polynomial constants / CRC tables (does the app
   even contain a software CRC routine?).
Usage: python3 analyze51.py <raw_c009.UPG> <dec_c009.bin> <raw_c013.UPG> <dec_c013.bin>"""
import sys, struct, zlib, datetime, calendar

def load(rp, dp):
    raw = open(rp, 'rb').read(); dec = open(dp, 'rb').read()
    return raw, dec

def hdr_fields(dec):
    return [l[2:].decode('ascii', 'replace') for l in dec[2:0x58].split(b'\r\n') if l.startswith(b'$$')]

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

def c32(d, t, init, refin, refout, xo):
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

P = 0x04C11DB7; PR = 0xEDB88320; PC = 0x1EDC6F41; PCR = 0x82F63B78
TF = mk32(P, False); TR = mk32(PR, True); TCF = mk32(PC, False); TCR = mk32(PCR, True)

def crc32s(d):
    return {'CRC32': c32(d, TR, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
            'BZIP2': c32(d, TF, 0xFFFFFFFF, False, False, 0xFFFFFFFF),
            'MPEG2': c32(d, TF, 0xFFFFFFFF, False, False, 0),
            'JAM': c32(d, TR, 0xFFFFFFFF, True, True, 0),
            'POSIX': c32(d, TF, 0, False, False, 0xFFFFFFFF),
            'CRC32C': c32(d, TCR, 0xFFFFFFFF, True, True, 0xFFFFFFFF),
            'CRC32C/JAM': c32(d, TCR, 0xFFFFFFFF, True, True, 0),
            'CRC32/0': c32(d, TR, 0, True, True, 0xFFFFFFFF),
            'CRC32/nofinal': c32(d, TR, 0xFFFFFFFF, True, True, 0),
            'CRC32C/0': c32(d, TCR, 0, True, True, 0xFFFFFFFF)}

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

def c16(d, t, init, refin, refout, xo):
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

C16 = [('CCITT-FALSE', 0x1021, 0xFFFF, False, False, 0), ('XMODEM', 0x1021, 0, False, False, 0),
       ('KERMIT', 0x1021, 0, True, True, 0), ('X-25', 0x1021, 0xFFFF, True, True, 0xFFFF),
       ('MODBUS', 0x8005, 0xFFFF, True, True, 0), ('ARC', 0x8005, 0, True, True, 0),
       ('MAXIM', 0x8005, 0, True, True, 0xFFFF), ('USB', 0x8005, 0xFFFF, True, True, 0xFFFF),
       ('DNP', 0x3D65, 0, True, True, 0xFFFF), ('T10-DIF', 0x8BB7, 0, False, False, 0),
       ('CRC-A', 0x1021, 0xC6C6, True, True, 0), ('RIELLO', 0x1021, 0xB2AA, True, True, 0),
       ('TMS37157', 0x1021, 0x89EC, True, True, 0), ('AUG-CCITT', 0x1021, 0x1D0F, False, False, 0),
       ('GENIBUS', 0x1021, 0xFFFF, False, False, 0xFFFF), ('PROFIBUS', 0x1DCF, 0xFFFF, False, False, 0xFFFF),
       ('MCRF4XX', 0x1021, 0xFFFF, True, True, 0), ('DECT', 0x0589, 0, False, False, 0x0001)]
T16 = {(p, r): mk16(p, r) for _, p, _, r, _, _ in C16}

def sums(d):
    s8 = sum(d) & 0xFF; s16 = sum(d) & 0xFFFF; s32 = sum(d) & 0xFFFFFFFF
    x8 = 0; x16 = 0; x32 = 0
    for i in range(0, len(d) - 1, 2):
        x16 ^= struct.unpack_from('<H', d, i)[0]
    for i in range(0, len(d) - 3, 4):
        x32 ^= struct.unpack_from('<I', d, i)[0]
    for b in d: x8 ^= b
    # internet one's-complement 16-bit sum
    c = 0
    for i in range(0, len(d) - 1, 2):
        c += struct.unpack_from('>H', d, i)[0]
        c = (c & 0xFFFF) + (c >> 16)
    inet = (~c) & 0xFFFF
    return {'sum8': s8, 'sum16': s16, 'sum32': s32, 'xor8': x8, 'xor16': x16, 'xor32': x32, 'inet': inet, 'inet-nofinal': c & 0xFFFF}

pairs = [(sys.argv[1], sys.argv[2], 'C009'), (sys.argv[3], sys.argv[4], 'C013')]
imgs = []
for rp, dp, tag in pairs:
    raw, dec = load(rp, dp); n = len(dec)
    first4 = struct.unpack_from('<I', dec, 0x400)[0]
    tr4 = struct.unpack_from('<I', dec, n - 4)[0]
    tr_hi = struct.unpack_from('>H', dec, n - 2)[0]; tr_lo = struct.unpack_from('<H', dec, n - 2)[0]
    foot = struct.unpack_from('<H', dec, 0x3FE)[0]
    print(f"== {tag} ==  raw[0:2]={raw[0:2].hex(' ')} raw[n-4:]={raw[n-4:].hex(' ')} dec[n-4:]={dec[n-4:].hex(' ')}")
    print(f"   first4=0x{first4:08X} tr4=0x{tr4:08X} tr_hiBE=0x{tr_hi:04X} tr_loLE=0x{tr_lo:04X} footer=0x{foot:04X}")
    fields = hdr_fields(dec)
    print("   header fields:", fields)
    # timestamp hypothesis: first4 as unix epoch
    dt = datetime.datetime.utcfromtimestamp(first4)
    print(f"   first4 as unix UTC: {dt.isoformat()}")
    for f in fields:
        if '-' in f and ':' in f:
            print(f"   header datetime field: {f!r}")
    imgs.append((tag, raw, dec, n, first4, tr4, tr_hi, tr_lo, foot))

if len(imgs) == 2:
    d = imgs[1][4] - imgs[0][4]
    print(f"\nfirst4 delta C013-C009 = {d} s = {d/86400:.4f} days")

print("\n== small-region hunt (targets: first4, tr4, tr_hiBE, tr_loLE, footer) ==")
for tag, raw, dec, n, first4, tr4, tr_hi, tr_lo, foot in imgs:
    regs = {}
    for name, src in (('dec', dec), ('raw', raw)):
        for a, b, rt in [(0x00, 0x58, 'hdr[0:58]'), (0x02, 0x58, 'hdr[2:58]'), (0x00, 0x02, 'keyhdr[0:2]'),
                         (0x3EA, 0x400, 'footer[3EA:400]'), (0x3EA, 0x3F2, 'footer-txt[3EA:3F2]'),
                         (0x3F2, 0x3F6, 'lenfield[3F2:3F6]'), (0x3EA, 0x3FE, 'footer-nocheck[3EA:3FE]'),
                         (0x3F6, 0x3FE, 'footer-zeros[3F6:3FE]'), (0x400, 0x40A, 'entryhdr[400:40A]'),
                         (0x400, 0x404, 'entry4[400:404]'), (0x404, 0x40A, 'entry6[404:40A]'),
                         (0x00, 0x400, 'hdr+prefix+footer[0:400]'), (0x00, 0x40A, 'all-before-code[0:40A]'),
                         (0x58, 0x400, 'prefix+footer[58:400]'), (0x02, 0x400, 'hdr2+prefix+footer[2:400]')]:
            regs[f'{name}.{rt}'] = src[a:b]
    hit = False
    for rn, rd in regs.items():
        ad = zlib.adler32(rd) & 0xFFFFFFFF
        for tn, tv in (('first4', first4), ('tr4', tr4)):
            if ad == tv: print(f"  [{tag} {tn}] Adler32({rn})"); hit = True
        for cn, v in crc32s(rd).items():
            for tn, tv in (('first4', first4), ('tr4', tr4)):
                if v == tv: print(f"  [{tag} {tn}] {cn}({rn})"); hit = True
        for cn, p, init, ri, ro, xo in C16:
            v = c16(rd, T16[(p, ri)], init, ri, ro, xo)
            for tn, tv in (('tr_hiBE', tr_hi), ('tr_loLE', tr_lo), ('footer', foot)):
                if v == tv: print(f"  [{tag} {tn}] crc16/{cn}({rn})"); hit = True
        for sn, sv in sums(rd).items():
            for tn, tv in (('first4', first4), ('tr4', tr4), ('tr_hiBE', tr_hi), ('tr_loLE', tr_lo), ('footer', foot)):
                if sv == tv: print(f"  [{tag} {tn}] {sn}({rn})"); hit = True
    if not hit: print(f"  [{tag}] none")

print("\n== app-image CRC routine scan (decoded C009) ==")
dec = imgs[0][2]
for p in (0x04C11DB7, 0xEDB88320, 0x1EDC6F41, 0x82F63B78, 0x741B8CD7, 0xD5828281, 0x814141AB, 0x914141EB):
    pat = struct.pack('<I', p)
    offs = []
    i = dec.find(pat)
    while i != -1 and len(offs) < 8:
        offs.append(i); i = dec.find(pat, i + 1)
    print(f"  u32 poly 0x{p:08X}: {[hex(o) for o in offs] if offs else 'none'}")
# standard CRC32 reflected table head
tab = struct.pack('<IIII', 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA)
i = dec.find(tab); print(f"  CRC32 table head: {hex(i) if i != -1 else 'none'}")
tab = struct.pack('>IIII', 0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9)
i = dec.find(tab); print(f"  CRC32 BE table head: {hex(i) if i != -1 else 'none'}")
for p in (0x8408, 0xA001, 0x3D65, 0x8BB7, 0x1DCF, 0x0589, 0x1021, 0x8005):
    pat = struct.pack('<H', p)
    cnt = dec.count(pat)
    offs = []
    i = dec.find(pat)
    while i != -1 and len(offs) < 6:
        offs.append(i); i = dec.find(pat, i + 1)
    print(f"  u16 poly 0x{p:04X}: count={cnt} first={[hex(o) for o in offs]}")
tab = struct.pack('<HHHH', 0x0000, 0xC0C1, 0xC181, 0x0140)
i = dec.find(tab); print(f"  CRC16/ARC table head: {hex(i) if i != -1 else 'none'}")
tab = struct.pack('<HHHH', 0x0000, 0x1021, 0x2042, 0x3063)
i = dec.find(tab); print(f"  CRC16/CCITT table head: {hex(i) if i != -1 else 'none'}")
