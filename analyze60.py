#!/usr/bin/env python3
"""Identify FatFs f_open/f_read/f_write/f_close in the NORMAL (non-relocated) FatFs
cluster anchored by f_mkfs (file 0x037100). disk_write candidate = 0x038F28 (called
by f_mkfs). Disassemble it + find its read counterpart, list ALL static BL callers
of disk_read/disk_write (these are f_read/f_write/f_mkfs/f_sync/f_open), and
disassemble the candidate file-I/O functions to confirm signatures.
Usage: python3 analyze60.py firmware.bin [> update60.txt]"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

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
        i = ins[0]; note = ''
        if i.mnemonic == 'bl':
            t = bl_target(a)
            if t is not None: note = f"   -> f+0x{t:06x}"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size

disasm(0x038F28, 0x038FC0, "disk_write candidate 0x038F28")

# find all BL callers of a set of targets
def callers(targets):
    res = collections.defaultdict(list)
    for a in range(0x400, n - 4, 2):
        h1 = struct.unpack_from('<H', dec, a)[0]
        if (h1 >> 11) != 0x1E: continue
        h2 = struct.unpack_from('<H', dec, a + 2)[0]
        if (h2 & 0xD000) != 0xD000: continue
        t = bl_target(a)
        if t in targets: res[t].append(a)
    return res

# disk_read is usually right before/after disk_write; scan 0x038E00-0x039000 prologues
print("\n== function prologues (push) in 0x038E00..0x039100 ==")
for a in range(0x038E00, 0x039100, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]
    if h1 in (0xB500, 0xB510, 0xB530, 0xB570, 0xB5F0) or (h1 & 0xFF00) == 0xE900 or h1 == 0xE92D:
        ins = list(md.disasm(dec[a:a + 4], BASE + a, count=1))
        if ins: print(f"  f+0x{a:06x}: {ins[0].mnemonic} {ins[0].op_str}")

cw = callers({0x038F28})
print("\n== BL callers of disk_write 0x038F28 ==")
for a in cw.get(0x038F28, []): print(f"  f+0x{a:06x}")

# guess disk_read near disk_write; disassemble a few candidates and find their callers
for cand in (0x038E90, 0x038EC0, 0x038EF0, 0x038F00, 0x038F60, 0x038F90):
    disasm(cand, cand + 48, f"candidate {hex(cand)}")

# --- locate the update routine via the flash writer's FIXED address ---
WR = {0x080B10AC: 'writer main', 0x080B1020: 'writer prog1', 0x080B1006: 'writer prog0',
      0x080B119E: 'sector-size table', 0x080B11CE: 'sector-start table', 0x080B1076: 'unlock',
      0x080B1094: 'prog word', 0x080B1168: 'lock'}
print("\n== u32 LE == flash-writer fixed addresses (any alignment) ==")
for v, nm in WR.items():
    pat = struct.pack('<I', v); i = dec.find(pat); found = []
    while i != -1:
        found.append(i); i = dec.find(pat, i + 1)
    print(f"  {nm} 0x{v:08X}: {[hex(f) for f in found] if found else 'none'}")

def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
print("\n== movw/movt + LDR-literal loading writer fixed addresses ==")
sites = []; last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, lo = last[rd]; v = (imm16(h1, h2) << 16) | lo
            if v in WR: sites.append((pa, f"movw/movt {WR[v]} 0x{v:08X}"))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:
        u = (h1 >> 7) & 1; t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in WR: sites.append((a, f"ldrT2 {WR[v]} (pool f+0x{t:06x})"))
    if (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in WR: sites.append((a, f"ldrT1 {WR[v]} (pool f+0x{t:06x})"))
for a, why in sites: print(f"  f+0x{a:06x}: {why}")
print(f"total: {len(sites)}")
seen = set()
for a, why in sites:
    w = max(0x400, (a - 128) & ~1)
    if w // 384 in seen: continue
    seen.add(w // 384)
    disasm(w, w + 384, why)
