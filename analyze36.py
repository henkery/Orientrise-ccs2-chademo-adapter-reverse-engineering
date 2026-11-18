#!/usr/bin/env python3
"""Is the 'NO NAME' FAT volume label a flasher ID check, or an f_mkfs placeholder? (§5.6)

Dumps the MSDOS5.0 / NO NAME / FAT-type / FSInfo string cluster, then xrefs it with
the PROVEN corrected_xref.py logic (movw+movt pairs; LDR-literal T1/T2 keyed by the
dereferenced pool VALUE, imm8 in h1; ADR T1/T3 keyed by the formed address BASE+t),
and disassembles the referencing sites to classify WRITE (f_mkfs) vs COMPARE (label check).
Read-only analysis.
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze36.py firmware.bin'
"""
import sys, struct, re, collections
dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000

def u32(o): return struct.unpack_from('<I', dec, o)[0]
def hexdump(o, ln=64):
    for r in range(o, min(o + ln, n), 16):
        c = dec[r:r + 16]
        hx = ' '.join(f'{b:02x}' for b in c)
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in c)
        print(f'  f+0x{r:06x} 0x{BASE+r:08x}  {hx:<47}  {asc}')

CL_LO, CL_HI = 0x37300, 0x37400          # cluster + immediate neighbours
print("=== 1. cluster bytes ===")
hexdump(0x37330, 0x50)
print("\n=== 2. string offsets ===")
for pat in [b'NO NAME', b'MSDOS5.0', b'FAT32', b'RRaA', b'rrAa']:
    hits = [m.start() for m in re.finditer(re.escape(pat), dec)]
    print(f"  {pat!r}: {[hex(h) for h in hits[:16]]}  ({len(hits)} total)")

targets = set(range(BASE + CL_LO, BASE + CL_HI))
def imm16(h1, h2):
    return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)

# --- proven corrected_xref.py scan: const(value loaded) / adr(address formed) ---
const = collections.defaultdict(list); adr = collections.defaultdict(list); last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240:
        last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, lo = last[rd]
            if a - pa <= 12: const[(imm16(h1, h2) << 16) | lo].append(('movw/movt', pa))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:                       # LDR literal T2 (U=bit7)
        u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3: const[u32(t)].append(('ldrT2', a))
    if (h1 & 0xF800) == 0x4800:                       # LDR literal T1 (imm8 in h1)
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3: const[u32(t)].append(('ldrT1', a))
    if (h1 & 0xF800) == 0xA000:                       # ADR T1 (imm8 in h1)
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n: adr[BASE + t].append(('adrT1', a))
    if (h1 & 0xFBFF) == 0xF20F:                       # ADR T3 add
        imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        t = ((a + 4) & ~3) + imm
        if t < n: adr[BASE + t].append(('adrT3+', a))
    elif (h1 & 0xFBFF) == 0xF2AF:                     # ADR T3 sub
        imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
        t = ((a + 4) & ~3) - imm
        if 0 <= t < n: adr[BASE + t].append(('adrT3-', a))

refs = []
for v, l in const.items():
    if v in targets:
        for k, o in l: refs.append((o, k, v))
for v, l in adr.items():
    if v in targets:
        for k, o in l: refs.append((o, k, v))
refs.sort()
print(f"\n=== 3. code xrefs into cluster 0x{BASE+CL_LO:08x}..0x{BASE+CL_HI:08x} ===")
print(f"  {len(refs)} ref(s):")
for o, k, v in refs[:60]:
    print(f"    f+0x{o:06x} (0x{BASE+o:08x}) {k:9s} -> 0x{v:08x} (f+0x{v-BASE:06x})")

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    print("\n=== 4. disasm window around each xref (classify write vs compare) ===")
    seen = set()
    for o, k, v in refs[:24]:
        w = (o // 48) * 48
        if w in seen: continue
        seen.add(w)
        print(f"\n  -- ref f+0x{o:06x} ({k} -> 0x{v:08x}); window f+0x{w:06x} --")
        for ins in md.disasm(dec[w:w + 96], BASE + w):
            mark = ' <==' if ins.address == BASE + o else ''
            print(f"    0x{ins.address:08x} f+0x{ins.address-BASE:06x}: {ins.mnemonic:8s} {ins.op_str}{mark}")
except ImportError:
    print("\n[disasm] capstone not available — run under nix-shell for step 4")
