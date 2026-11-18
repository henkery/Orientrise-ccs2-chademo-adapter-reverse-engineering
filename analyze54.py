#!/usr/bin/env python3
"""Confirm the cracked MODBUS CRC16 fields and exhaust first4@0x400 hypotheses.
analyze52 proved: footer u16@0x3FE = CRC16/MODBUS(dec[0x3EA:0x3FE]) and trailer
u16LE@n-2 = CRC16/MODBUS(dec[2:n-2]), both revisions. Here: explicit verify, then
first4 as packed CRC16 pairs / CRC32 with the MODBUS polynomial / subregion CRCs.
Usage: python3 analyze54.py <raw_c009.UPG> <dec_c009.bin> <raw_c013.UPG> <dec_c013.bin>"""
import sys, struct

TAB = []
for i in range(256):
    c = i
    for _ in range(8): c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    TAB.append(c)

def modbus(d):
    c = 0xFFFF
    for b in d: c = (c >> 8) ^ TAB[(c ^ b) & 0xFF]
    return c

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

def c32(d, t, init, refin, xo):
    c = init
    if refin:
        for b in d: c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    else:
        for b in d: c = ((c << 8) & 0xFFFFFFFF) ^ t[((c >> 24) ^ b) & 0xFF]
    return c ^ xo

pairs = [(sys.argv[1], sys.argv[2], 'C009'), (sys.argv[3], sys.argv[4], 'C013')]
for rp, dp, tag in pairs:
    raw = open(rp, 'rb').read(); dec = open(dp, 'rb').read(); n = len(dec)
    first4 = struct.unpack_from('<I', dec, 0x400)[0]
    foot = struct.unpack_from('<H', dec, 0x3FE)[0]
    tr = struct.unpack_from('<H', dec, n - 2)[0]
    cf = modbus(dec[0x3EA:0x3FE]); ct = modbus(dec[2:n - 2])
    print(f"== {tag} == footer stored=0x{foot:04X} computed=0x{cf:04X} {'OK' if cf==foot else 'MISMATCH'}")
    print(f"          trailer stored=0x{tr:04X} computed=0x{ct:04X} {'OK' if ct==tr else 'MISMATCH'}")
    print(f"          first4=0x{first4:08X} (loLE=0x{first4&0xFFFF:04X} hiLE=0x{first4>>16:04X} loBE=0x{((first4&0xFF)<<8)|((first4>>8)&0xFF):04X} hiBE=0x{((first4>>16)&0xFF)<<8|(first4>>24):04X})")
    regs = {}
    for name, src in (('dec', dec), ('raw', raw)):
        for a, b, rt in [(0x02, 0x58, 'hdr[2:58]'), (0x58, 0x3EA, 'prefix[58:3EA]'),
                         (0x3EA, 0x400, 'footer[3EA:400]'), (0x400, 0x40A, 'entryhdr[400:40A]'),
                         (0x404, n - 2, 'code[404:n-2]'), (0x40A, n - 2, 'code[40A:n-2]'),
                         (0x02, n - 2, 'payload[2:n-2]'), (0x404, n - 4, 'code[404:n-4]'),
                         (0x40A, n - 4, 'code[40A:n-4]'), (0x02, 0x400, 'pre-code[2:400]'),
                         (0x02, 0x404, 'pre-code[2:404]'), (0x58, 0x400, 'prefix+footer[58:400]'),
                         (0x00, 0x400, 'pre-code[0:400]'), (0x400, n - 2, 'entry+code[400:n-2]')]:
            regs[f'{name}.{rt}'] = src[a:b]
    crcs = {rn: modbus(rd) for rn, rd in regs.items()}
    hit = False
    loLE, hiLE = first4 & 0xFFFF, first4 >> 16
    loBE = ((first4 & 0xFF) << 8) | ((first4 >> 8) & 0xFF)
    hiBE = (((first4 >> 16) & 0xFF) << 8) | (first4 >> 24)
    for rn, v in crcs.items():
        for tn, tv in (('loLE', loLE), ('hiLE', hiLE), ('loBE', loBE), ('hiBE', hiBE)):
            if v == tv: print(f"  HIT first4.{tn} = MODBUS({rn})"); hit = True
    # packed pairs: first4 = crcA | crcB<<16 (and byte-swapped halves)
    rns = list(crcs)
    for i, ra in enumerate(rns):
        for rb in rns[i:]:
            a, b = crcs[ra], crcs[rb]
            if a | (b << 16) == first4: print(f"  HIT first4 = MODBUS({ra}) | MODBUS({rb})<<16"); hit = True
            if b | (a << 16) == first4: print(f"  HIT first4 = MODBUS({rb}) | MODBUS({ra})<<16"); hit = True
    # CRC32 with MODBUS-family polynomials
    for pn, poly, ri in (('CRC32/8005', 0x00008005, False), ('CRC32/8005-refl', 0xA0010000, True),
                         ('CRC32/A001', 0x0000A001, False), ('CRC32/1021', 0x00001021, False)):
        t = mk32(poly, ri)
        for rn in ('dec.payload[2:n-2]', 'dec.code[404:n-2]', 'dec.code[40A:n-2]', 'dec.entry+code[400:n-2]', 'raw.payload[2:n-2]'):
            for init in (0, 0xFFFFFFFF):
                for xo in (0, 0xFFFFFFFF):
                    if c32(regs[rn], t, init, ri, xo) == first4:
                        print(f"  HIT first4 = {pn}({rn}, init=0x{init:X}, xo=0x{xo:X})"); hit = True
    if not hit: print("  first4: no MODBUS/CRC32 relation found — consistent with per-image IV/nonce [H]")
