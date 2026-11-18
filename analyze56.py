#!/usr/bin/env python3
"""Structure inspection around the UPG string cluster + offset-based reference
hunt. analyze55: no absolute pointers to the UPG strings exist; the cluster
region interleaves Thumb function pointers (odd values) — looks like process
descriptor blocks. Dump the structures, the scatter-load region table (file
0x488, from startup adr r0,#0x28 @0x45E), and hunt offset-based references
(u32 == file offset; movw/movt / LDR-literal loading the offset).
Usage: python3 analyze56.py firmware.bin [> update56.txt]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def hexdump(a, b, label):
    print(f"\n== hexdump {label} f+0x{a:06x}..f+0x{b:06x} ==")
    for off in range(a, b, 16):
        row = dec[off:off + 16]
        hx = ' '.join(f'{x:02x}' for x in row)
        asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in row)
        print(f"  f+0x{off:06x}  {hx:<47s}  {asc}")

hexdump(0x02ff00, 0x030300, "UPG string cluster + following words")
hexdump(0x03ae00, 0x03b200, "pointer-table region (0x0804F102 refs)")

print("\n== scatter-load region table @f+0x488 (words) ==")
for off in range(0x488, 0x540, 4):
    v = struct.unpack_from('<I', dec, off)[0]
    print(f"  f+0x{off:06x}: 0x{v:08X}")

OFFS = [0x02ff56, 0x02ff76, 0x02ffee, 0x03001a, 0x030102, 0x03011a, 0x030132, 0x030d72]
print("\n== u32 LE == string FILE OFFSET (any alignment) ==")
for o in OFFS:
    pat = struct.pack('<I', o); i = dec.find(pat); found = []
    while i != -1:
        found.append(i); i = dec.find(pat, i + 1)
    print(f"  offset 0x{o:06x}: {[hex(f) for f in found] if found else 'none'}")

def imm16(h1, h2): return (((h1 >> 4) & 0xF) << 12) | (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
OFFSET = set(OFFS)
print("\n== code loading string FILE OFFSETS (movw/movt, LDR-literal) ==")
sites = []
last = {}
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 & 0xFBF0) == 0xF240: last[(h2 >> 8) & 0xF] = (a, imm16(h1, h2))
    elif (h1 & 0xFBF0) == 0xF2C0:
        rd = (h2 >> 8) & 0xF
        if rd in last:
            pa, l = last[rd]; v = (imm16(h1, h2) << 16) | l
            if v in OFFSET: sites.append((pa, f"movw/movt offset 0x{v:06x}"))
            del last[rd]
    if (h1 & 0xFF7F) == 0xF85F:
        u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in OFFSET: sites.append((a, f"ldrT2 offset 0x{v:06x} (pool f+0x{t:06x})"))
    if (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3:
            v = struct.unpack_from('<I', dec, t)[0]
            if v in OFFSET: sites.append((a, f"ldrT1 offset 0x{v:06x} (pool f+0x{t:06x})"))
for a, why in sites: print(f"  f+0x{a:06x}: {why}")
print(f"total: {len(sites)}")

print("\n== resolve words in 0x03ae00..0x03b200 to strings ==")
for off in range(0x03ae00, 0x03b200, 4):
    v = struct.unpack_from('<I', dec, off)[0]
    if BASE <= v < BASE + n:
        t = v - BASE
        s = dec[t:t + 40]
        pr = s.split(b'\x00')[0]
        if len(pr) >= 4 and all(32 <= c < 127 for c in pr):
            print(f"  f+0x{off:06x}: 0x{v:08X} -> f+0x{t:06x} {pr.decode()!r}")
