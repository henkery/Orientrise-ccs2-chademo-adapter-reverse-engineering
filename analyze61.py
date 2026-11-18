#!/usr/bin/env python3
"""Map the NORMAL FatFs object-file cluster to identify f_open/f_read/f_write/f_close
(the API a bootloader-dump cave must call), and assess the usbdisk-caller region
(file ~0x00243c) as a normal-code hook anchor.

Strategy:
 (1) enumerate function prologues (push / push.w) across 0x034000..0x039200 to get
     function start/size boundaries;
 (2) for every static BL caller of disk_write(0x038F28) and disk_read(0x038ED8),
     find the enclosing function and dump its head — f_write is the big sector-loop
     writer, f_read the big sector-loop reader, f_mkfs helpers cluster at 0x0371xx;
 (3) f_open is the large path/dir function (calls dir_find -> disk_read), f_close is
     small (calls f_sync then clears FIL). Dump the largest few functions' heads;
 (4) disassemble around the usbdisk BL callers 0x00243c/0x00244e and resolve their
     literal pools / BL targets to judge whether that region is normal (hookable).
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze61.py firmware.bin'
"""
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

def disasm(start, end, label, maxins=200):
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

# (1) function prologues across the FatFs cluster
LO, HI = 0x034000, 0x039200
pro = []
for a in range(LO, HI, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]
    if h1 == 0xE92D:  # push.w (T2) — 4-byte, next half is reglist
        pro.append(a)
    elif (h1 & 0xFE00) == 0xB400 and (h1 & 0x0100):  # push {..,lr} T1
        pro.append(a)
pro = sorted(set(pro))
bounds = []
for i, s in enumerate(pro):
    e = pro[i + 1] if i + 1 < len(pro) else HI
    bounds.append((s, e))
print(f"== {len(bounds)} function prologues in f+0x{LO:06x}..f+0x{HI:06x} ==")
for s, e in bounds:
    print(f"  f+0x{s:06x}  size~0x{e-s:04x} ({e-s})")

def enclosing(off):
    best = None
    for s, e in bounds:
        if s <= off < e: return (s, e)
        if s <= off: best = (s, e)
    return best

def callers(target):
    res = []
    for a in range(0x400, n - 4, 2):
        if bl_target(a) == target: res.append(a)
    return res

# (2) enclosing functions of disk_write / disk_read callers
for tgt, nm in ((0x038F28, 'disk_write'), (0x038ED8, 'disk_read')):
    cs = callers(tgt)
    print(f"\n== {nm} 0x{tgt:06x}: {len(cs)} BL callers -> enclosing functions ==")
    seen = set()
    for c in cs:
        en = enclosing(c)
        if not en: continue
        s, e = en
        if s in seen: continue
        seen.add(s)
        print(f"  caller f+0x{c:06x} in func f+0x{s:06x} (size~{e-s})")

# (3) dump heads of the largest functions (f_open/f_read/f_write candidates)
big = sorted(bounds, key=lambda se: se[1] - se[0], reverse=True)[:8]
print("\n== largest 8 functions (heads) ==")
for s, e in big:
    disasm(s, min(s + 120, e), f"func f+0x{s:06x} size~{e-s}", maxins=40)

# (4) usbdisk-caller region: is it normal code?
for site in (0x00243c, 0x00244e):
    w = (site - 64) & ~1
    disasm(w, w + 160, f"usbdisk-caller region around f+0x{site:06x}", maxins=70)
