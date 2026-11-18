#!/usr/bin/env python3
"""Final pre-build pass:
 (a) confirm f_sync (candidate 0x035792) and find f_close = small function that BLs
     f_sync then stores 0 to fp->obj.fs ([fp]);
 (b) confirm the +2-byte literal-pool shift is uniform on f_open/f_write/f_sync pools
     (real value lives at pool_target+2) — the overlay packing that blocks static hooks;
 (c) locate free cave space (runs of 0xFF or 0x00 >= 256 B) in the app code region for
     a position-independent dump cave.
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze64.py firmware.bin'
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
            if 0 <= t < n - 3: note = f"   [pool@f+0x{t:06x}=0x{u32(t):08X} | +2=0x{u32(t+2):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3: note = f"   [pool@f+0x{t:06x}=0x{u32(t):08X} | +2=0x{u32(t+2):08X}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size; cnt += 1

# (a) f_sync candidate + f_close search
disasm(0x035792, 0x03581c, "f_sync candidate 0x035792", maxins=70)
print("\n== BL callers of f_sync candidate 0x035792 (f_close is a small one) ==")
for a in range(0x400, n - 4, 2):
    if bl_target(a) == 0x035792:
        print(f"  f+0x{a:06x}")
# dump small windows around each caller to spot f_close (calls f_sync then str 0,[fp])
seen = set()
for a in range(0x400, n - 4, 2):
    if bl_target(a) == 0x035792:
        w = max(0x400, (a - 24) & ~1)
        if w // 96 in seen: continue
        seen.add(w // 96)
        disasm(w, w + 72, f"f_close? near caller f+0x{a:06x}", maxins=34)

# (b) encoding uniformity on f_open / f_write pools
disasm(0x0363e0, 0x036420, "f_open head pools (+2 shift check)", maxins=18)
disasm(0x0366c8, 0x036700, "f_write head pools (+2 shift check)", maxins=16)

# (c) free cave space: runs of 0xFF or 0x00 >= 256 in app region 0x40A..n-4
print("\n== free runs (>=256 B of 0xFF or 0x00) in app region ==")
for fill in (0xFF, 0x00):
    run = 0; start = None; found = []
    for i in range(0x40A, n - 4):
        if dec[i] == fill:
            if run == 0: start = i
            run += 1
        else:
            if run >= 256: found.append((start, run))
            run = 0
    if run >= 256: found.append((start, run))
    print(f"  fill 0x{fill:02X}: {len(found)} runs")
    for s, ln in found[:24]:
        print(f"    f+0x{s:06x} .. f+0x{s+ln:06x}  len={ln} (0x{ln:x})")
