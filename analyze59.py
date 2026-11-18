#!/usr/bin/env python3
"""Anchor the service-firmware hook on NON-relocated code:
(1) full disasm of the SRAM flash writer (file 0x91000-0x91200) — entry context,
    unlock/erase/program/verify, sector table refs;
(2) re-derive f_mkfs code xrefs to the MSDOS5.0/NO NAME cluster (0x37300-0x37400,
    analyze36 logic) to locate the FatFs object-file cluster;
(3) disassemble a wide window around f_mkfs to expose f_open/f_read/f_write/f_close.
Usage: python3 analyze59.py firmware.bin [> update59.txt]"""
import sys, struct, collections
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

def disasm(start, end, label):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a = start
    while a < end:
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
        a += i.size

disasm(0x91000, 0x91200, "SRAM flash writer + sector tables")

# --- f_mkfs cluster xrefs (analyze36 logic) ---
def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
targets = set(range(BASE + 0x37300, BASE + 0x37400))
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
    if v in targets:
        for k, o in l: refs.append((o, k, v))
for v, l in adr.items():
    if v in targets:
        for k, o in l: refs.append((o, k, v))
refs.sort()
print(f"\n== f_mkfs cluster xrefs ({len(refs)}) ==")
for o, k, v in refs[:30]: print(f"  f+0x{o:06x} {k:9s} -> f+0x{v-BASE:06x}")
if refs:
    site = refs[0][0]
    w = (site // 256) * 256
    disasm(w, w + 0x400, "FatFs cluster around f_mkfs")
