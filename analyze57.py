#!/usr/bin/env python3
"""Disassemble the usbdisk process function found at f+0x03014E (right after the
UPG filename strings) with FULL PC-relative target resolution: every LDR-literal
(T1/T2) and ADR (T1/T3) target is printed as word + string preview, revealing how
the UPG strings are actually referenced (analyze55/56 found no absolute pointers).
Also finds callers of 0x03014E and disassembles its first BL target.
Usage: python3 analyze57.py firmware.bin [> update57.txt]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

dec = open(sys.argv[1], 'rb').read(); n = len(dec); BASE = 0x08020000
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

def preview(t):
    if not (0 <= t < n): return ""
    w = struct.unpack_from('<I', dec, t)[0] if t < n - 3 else 0
    s = dec[t:t + 32].split(b'\x00')[0]
    pr = s.decode('ascii', 'replace') if len(s) >= 3 and all(32 <= c < 127 for c in s) else ''
    extra = f" str={pr!r}" if pr else ''
    if BASE <= w < BASE + n:
        ts = dec[w - BASE:w - BASE + 32].split(b'\x00')[0]
        if len(ts) >= 3 and all(32 <= c < 127 for c in ts):
            extra += f" ->f+0x{w-BASE:06x} {ts.decode()!r}"
    return f"word=0x{w:08X}{extra}"

def disasm(start, end, label):
    print(f"\n--- {label}: f+0x{start:06x}..f+0x{end:06x} ---")
    a = start
    while a < end:
        ins = list(md.disasm(dec[a:a + 4], BASE + a, count=1))
        if not ins:
            print(f"  0x{BASE+a:08x} f+0x{a:06x}: .hword 0x{struct.unpack_from('<H', dec, a)[0]:04x} (bad)")
            a += 2; continue
        i = ins[0]; h1 = struct.unpack_from('<H', dec, a)[0]
        note = ''
        if (h1 & 0xFF7F) == 0xF85F and i.size == 4:
            h2 = struct.unpack_from('<H', dec, a + 2)[0]; u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            note = f"   [pool f+0x{t:06x}: {preview(t)}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            note = f"   [pool f+0x{t:06x}: {preview(t)}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            note = f"   [adr f+0x{t:06x}: {preview(t)}]"
        elif (h1 & 0xFBFF) in (0xF20F, 0xF2AF) and i.size == 4:
            h2 = struct.unpack_from('<H', dec, a + 2)[0]
            imm = (((h1 >> 10) & 1) << 11) | (((h2 >> 12) & 7) << 8) | (h2 & 0xFF)
            t = ((a + 4) & ~3) + (imm if (h1 & 0xFBFF) == 0xF20F else -imm)
            note = f"   [adr f+0x{t:06x}: {preview(t)}]"
        print(f"  0x{i.address:08x} f+0x{i.address-BASE:06x}: {i.mnemonic:9s} {i.op_str}{note}")
        a += i.size

disasm(0x03014E, 0x0302B0, "usbdisk process function")

print("\n== callers of f+0x03014E (BL/B.W) ==")
def sx(v, b): return v - (1 << b) if v & (1 << (b - 1)) else v
callers = []
for a in range(0x400, n - 4, 2):
    h1 = struct.unpack_from('<H', dec, a)[0]; h2 = struct.unpack_from('<H', dec, a + 2)[0]
    if (h1 >> 11) != 0x1E: continue
    m = h2 & 0xD000
    if m not in (0xD000, 0x8000): continue
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF
    J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = sx((S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1), 25)
    tgt = (a + 4) + off
    if tgt == 0x03014E: callers.append((a, 'BL' if m == 0xD000 else 'B.W'))
for a, k in callers: print(f"  {k} @f+0x{a:06x}")
print(f"total: {len(callers)}")

# first BL in the function: 39 f0 65 fd @0x030156
h1 = struct.unpack_from('<H', dec, 0x030156)[0]; h2 = struct.unpack_from('<H', dec, 0x030158)[0]
S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
off = sx((S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1), 25)
tgt = 0x030156 + 4 + off
print(f"\nfirst BL @0x030156 -> f+0x{tgt:06x}")
disasm(tgt, tgt + 256, "first BL target")
