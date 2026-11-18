#!/usr/bin/env python3
"""Anchor the dump cave on the app's OWN FatFs usage (it writes LOGS.BIN), which gives
known-good f_open/f_write/f_close addresses + calling context + a FIL/path pattern.

 (1) locate log/update file-name strings ("LOGS", ".BIN", "0:/", "BOOT") and xref them
     (movw/movt, LDR-literal T1/T2 by pool VALUE, ADR T1/T3 by formed address);
 (2) disassemble each referencing function to read off the f_open/f_write/f_close BL
     targets and the FIL object / path / mode arguments;
 (3) confirm FatFs API by full disasm of f_read candidate 0x0363e0 and the large
     f_open candidate 0x0360f2, and the read+write f_write candidates 0x036584/0x0366c8.
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze62.py firmware.bin'
"""
import sys, struct, re, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def u32(o): return struct.unpack_from('<I', dec, o)[0]
def bl_target(a):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return (a + 4) + off

def disasm(start, end, label, maxins=400):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a = start; cnt = 0
    while a < end and cnt < maxins:
        ins = list(md.disasm(dec[a:a + 4], BASE + a, count=1))
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{struct.unpack_from('<H', dec, a)[0]:04x} (bad)"); a += 2; continue
        i = ins[0]; h1 = struct.unpack_from('<H', dec, a)[0]; note = ''
        if i.mnemonic == 'bl':
            t = bl_target(a)
            if t is not None: note = f"   -> f+0x{t:06x}"
        elif (h1 & 0xFF7F) == 0xF85F and i.size == 4:
            h2 = struct.unpack_from('<H', dec, a + 2)[0]; u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3: note = f"   [pool f+0x{t:06x}=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3: note = f"   [pool f+0x{t:06x}=0x{u32(t):08X}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size; cnt += 1

# (1) string search
print("== file-name / path strings ==")
pats = [b'LOGS', b'.BIN', b'.UPG', b'0:/', b'BOOT', b'1:/', b'USB', b'.TXT', b'.LOG']
offs = {}
for p in pats:
    hits = [m.start() for m in re.finditer(re.escape(p), dec)]
    offs[p] = hits
    print(f"  {p!r}: {[hex(h) for h in hits[:20]]} ({len(hits)})")

# show context around LOGS / .BIN hits
for p in (b'LOGS', b'.BIN', b'0:/'):
    for h in offs.get(p, [])[:8]:
        s = max(0, h - 16); ctx = dec[s:h + 32]
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        print(f"    ctx f+0x{h:06x}: {asc}")

# (2) xref the string addresses (only those in plausible rodata range)
def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
str_targets = set()
for p in (b'LOGS', b'.BIN', b'0:/', b'BOOT'):
    for h in offs.get(p, []):
        if 0x400 <= h < n: str_targets.add(BASE + h)
const = collections.defaultdict(list); adr = collections.defaultdict(list); last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, lo = last[rd]
            if a - pa <= 12: const[(imm16(h1, h2) << 16) | lo].append(('movw/movt', pa))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:
        u = (h1 >> 7) & 1; t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3: const[u32(t)].append(('ldrT2', a))
    if (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3: const[u32(t)].append(('ldrT1', a))
    if (h1 & 0xF800) == 0xA000:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n: adr[BASE + t].append(('adrT1', a))
    if (h1 & 0xFBFF) in (0xF20F, 0xF2AF):
        imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        t = ((a + 4) & ~3) + (imm if (h1 & 0xFBFF) == 0xF20F else -imm)
        if 0 <= t < n: adr[BASE + t].append(('adrT3', a))
refs = []
for v, l in const.items():
    if v in str_targets:
        for k, o in l: refs.append((o, k, v))
for v, l in adr.items():
    if v in str_targets:
        for k, o in l: refs.append((o, k, v))
refs.sort()
print(f"\n== xrefs to file-name strings ({len(refs)}) ==")
for o, k, v in refs[:40]:
    print(f"  f+0x{o:06x} {k:9s} -> str f+0x{v-BASE:06x}")

# disassemble windows around the refs (the log/update file-I/O functions)
seen = set()
for o, k, v in refs[:20]:
    w = max(0x400, (o - 96) & ~1)
    key = w // 256
    if key in seen: continue
    seen.add(key)
    disasm(w, w + 256, f"log/update I/O near f+0x{o:06x} ({k}->str f+0x{v-BASE:06x})", maxins=90)

# (3) confirm FatFs API candidates
disasm(0x0363e0, 0x036584, "f_read candidate 0x0363e0 (full)", maxins=160)
disasm(0x0360f2, 0x036368, "f_open candidate 0x0360f2 (full)", maxins=200)
