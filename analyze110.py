#!/usr/bin/env python3
"""analyze110 — does stock get_hv / NV-cal lazy-init FALL BACK to a default calibration when the
external-flash record @0xFE000 is absent? CALDUMP on the clone shows all-FF @0xFE000 and CALSCAN
finds no cal magic in the lower 1 MB (yet ~213 KB of factory data IS present). The custom replica
returns outvol=0 when cal absent; if stock instead loads default cal points, that is the gap that
makes C009 abort on this clone. Dump the full cal lazy-init / getter / get_hv for C013 (addresses
from analyze88) and locate the C009 equivalents by the cal-magic literal + SPI-read signature.

Usage: nix-shell -p python3 python3Packages.capstone --run 'python3 analyze110.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

TB = 0x0801FBFE
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True


def load(path):
    return open(path, 'rb').read()


def u16(fw, o): return struct.unpack_from('<H', fw, o)[0]
def u32(fw, o): return struct.unpack_from('<I', fw, o)[0]
def rt(f): return TB + f


def pool(fw, o):
    h1 = u16(fw, o)
    if (h1 & 0xF800) == 0x4800:
        p = (((rt(o) + 4) & ~3) - TB) + (h1 & 0xFF) * 4
        if 0 <= p and p + 4 <= len(fw): return u32(fw, p)
    if (h1 & 0xFF7F) == 0xF85F and o + 4 <= len(fw):
        U = (h1 >> 7) & 1; imm12 = u16(fw, o + 2) & 0xFFF
        base = ((rt(o) + 4) & ~3)
        p = (base + imm12 if U else base - imm12) - TB
        if 0 <= p and p + 4 <= len(fw): return u32(fw, p)
    return None


def dump(fw, addr, n, label):
    print(f"\n== {label}  0x{addr:08X} (f+0x{addr - TB:05x}) ==")
    a = addr - TB
    for _ in range(n):
        if a < 0 or a + 8 > len(fw):
            print("  <out of range>"); break
        ins = list(md.disasm(fw[a:a + 8], rt(a), count=1))
        if not ins:
            print(f"  f+0x{a:05x}: <no disasm>"); a += 2; continue
        i = ins[0]; w = pool(fw, a); extra = ""
        if w is not None:
            tag = (" FLASH" if 0x08000000 <= w < 0x08100000 else
                   " RAM" if 0x20000000 <= w < 0x20030000 else
                   " PERIPH" if 0x40000000 <= w < 0x60000000 else "")
            extra = f"  ; =0x{w:08X}{tag}"
        print(f"  f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}{extra}")
        a += i.size
        if i.mnemonic == 'bx' and 'lr' in i.op_str: break
        if i.mnemonic == 'pop' and 'pc' in i.op_str: break


def find_magic(fw, magic, label):
    """Find LDR-literal pool words equal to magic, then the LDR that loads them (xref)."""
    hits = []
    for o in range(0, len(fw) - 4, 4):
        if u32(fw, o) == magic:
            hits.append(o)
    print(f"\n## {label}: literal 0x{magic:08X} pool words at f+{[hex(h) for h in hits[:12]]}")
    return hits


c013 = load('.qwen/tmp/c013/decoded_c013.bin')
c009 = load('firmware.bin')

print("################ C013 NV-CAL / get_hv (analyze88 addresses) ################")
dump(c013, 0x0805231E, 70, "C013 NV cal lazy-init (full flow incl. failure path)")
dump(c013, 0x08052356, 14, "C013 cal getter")
dump(c013, 0x08052770, 40, "C013 get_hv (two-point interpolation)")
find_magic(c013, 0x41444A67, "C013 cal magic")

print("\n################ C009 cal-magic literal locations (locate equivalents) ################")
find_magic(c009, 0x41444A67, "C009 cal magic")
