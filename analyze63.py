#!/usr/bin/env python3
"""Decisive pass before building the service UPG:
 (A) confirm the flash-writer hook anchor (file 0x910AC) is NORMAL fixed code by
     resolving its literal pools (expect FLASH base 0x40023C00, keys 0x45670123/
     0xCDEF89AB, sector tables) — NOT halfword-swapped;
 (B) nail f_write / f_close: f_open=0x0363e0 (confirmed). Disasm the read+write
     candidates 0x036584/0x0366c8/0x036906 (f_write = sector-write loop, btw/bw args)
     and small funcs that call a sync helper then clear fp->obj.fs (f_close);
 (C) relocation mechanism: do usbdisk-overlay BLs resolve WITHIN the overlay to the
     FatFs API (=> overlay runs in flash, pools fixed up at boot)? Search for a
     fixup routine (halfword-swap + store into overlay) or an overlay->RAM memcpy.
Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze63.py firmware.bin'
"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def u32(o): return struct.unpack_from('<I', dec, o)[0]
def swap16(v): return ((v >> 16) | (v << 16)) & 0xFFFFFFFF
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
            if 0 <= t < n - 3:
                v = u32(t); note = f"   [pool f+0x{t:06x}=0x{v:08X} swap16=0x{swap16(v):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3:
                v = u32(t); note = f"   [pool f+0x{t:06x}=0x{v:08X} swap16=0x{swap16(v):08X}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size; cnt += 1

# (A) flash writer anchor — are its pools sensible (normal) or swapped?
disasm(0x91000, 0x91200, "flash writer 0x91000 (pool sanity)", maxins=200)

# (B) f_write candidates (read+write) — heads
for s, e in ((0x036584, 0x0366c8), (0x0366c8, 0x03685a), (0x036906, 0x036a3c)):
    disasm(s, min(s + 150, e), f"f_write candidate f+0x{s:06x}", maxins=55)

# f_close: small functions; dump a few near the FatFs API
for s, e in ((0x035fe6, 0x03605c), (0x035c1a, 0x035c66), (0x036092, 0x0360f2)):
    disasm(s, e, f"small func f+0x{s:06x} (f_close/f_sync candidate)", maxins=50)

# (C) relocation: usbdisk overlay BLs — do they land on FatFs API function starts?
FATFS_FUNCS = {0x0363e0: 'f_open', 0x0360f2: 'find_volume', 0x035398: 'move_window',
               0x036584: 'candA', 0x0366c8: 'candB', 0x036906: 'candC', 0x038f28: 'disk_write',
               0x038ed8: 'disk_read', 0x036f20: 'f_mkfs'}
print("\n== usbdisk overlay (f+0x02FE00..0x030400) BL targets ==")
hits = collections.Counter(); clean = 0; tot = 0
for a in range(0x02FE00, 0x030400, 2):
    t = bl_target(a)
    if t is None: continue
    tot += 1
    if t in FATFS_FUNCS:
        hits[FATFS_FUNCS[t]] += 1
        print(f"  f+0x{a:06x}: bl -> {FATFS_FUNCS[t]} f+0x{t:06x}  (CLEAN within-overlay)")
        clean += 1
print(f"  total BLs={tot}, clean-to-FatFs={clean}, hits={dict(hits)}")

# search for a fixup: code that loads an overlay pool address and stores a swapped value,
# or a memcpy whose source is the overlay region. Look for movw/movt forming BASE+overlay.
def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
OV_LO, OV_HI = BASE + 0x02F000, BASE + 0x03A000
print("\n== movw/movt forming an address INSIDE the overlay (possible copy/fixup source) ==")
last = {}; found = []
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, lo = last[rd]; v = (imm16(h1, h2) << 16) | lo
            if OV_LO <= v < OV_HI and not (0x02F000 <= pa < 0x03A000):
                found.append((pa, v))
            del last[rd]
for pa, v in found[:40]:
    print(f"  f+0x{pa:06x}: movw/movt -> 0x{v:08X} (overlay f+0x{v-BASE:06x})")
print(f"  total external refs into overlay: {len(found)}")
