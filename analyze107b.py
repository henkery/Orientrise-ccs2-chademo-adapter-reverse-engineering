#!/usr/bin/env python3
"""analyze107b.py — boot recovery-entry trace, pass 2: the top-level fork.

Pass 1 (analyze107) isolated the boot-mode decision f+0x8b2 (sets flags[0]/flags[1] @0x2000250C,
tail-calls f+0xe04) and the update wrapper f+0x9ae (always resets after). This pass disassembles
the pieces that decide UPDATE-WRAPPER vs BOOT->APP-JUMP at the top level:

  boot MAIN f+0x430 (called from reset f+0x3C) — the update-vs-launch fork
  decision continuation f+0xe04 (tail-called by f+0x8b2) — intake / flag consumer
  SRAM-magic recv f+0x103c + USB write f+0x1070 + FLASH-option f+0x11b4
  config-block reader f+0x21d8 (launch cluster f+0x1938 consumes its return bytes)
  reset f+0x18b6 + cluster init helpers f+0x17fc/f+0x1824/f+0x18c8/f+0x18e2/f+0x18fc
  accessors f+0x1918/f+0x191e/f+0x1922

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze107b.py acq/dump/boot.bin > .qwen/tmp/ccs2_re/a107b.out'
"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
d = open(sys.argv[1], 'rb').read(); n = len(d)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True

def u16(o): return struct.unpack_from('<H', d, o)[0]
def u32(o): return struct.unpack_from('<I', d, o)[0]

def bl_target(a):
    h1 = u16(a); h2 = u16(a + 2)
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return BASE + (a + 4) + off

SYSREG = {0x08: 'MSP', 0x09: 'PSP', 0x10: 'PRIMASK', 0x11: 'BASEPRI',
          0x12: 'BASEPRI_MAX', 0x13: 'FAULTMASK', 0x14: 'CONTROL'}

def disasm_range(lo, hi, label):
    print(f"\n===== {label}  f+0x{lo:06x}..0x{hi:06x} (0x{BASE+lo:08x}) =====")
    regimm = {}; branches = []; calls = []
    a = lo
    while a < hi:
        ins = list(md.disasm(d[a:a + 8], BASE + a, count=1)); h1 = u16(a)
        if not ins and (h1 & 0xFFF0) == 0xF380 and a + 2 < hi and (u16(a + 2) & 0xFF00) == 0x8800:
            sysm = u16(a + 2) & 0xFF; rn = h1 & 0xF
            print(f"  0x{BASE+a:08x} f+0x{a:06x}: msr       {SYSREG.get(sysm, hex(sysm))}, r{rn}   (manual)")
            a += 4; continue
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{u16(a):04x} (data/bad)"); a += 2; continue
        ins = ins[0]; note = ''; mn = ins.mnemonic; ops = ins.op_str
        if mn == 'bl':
            t = bl_target(a)
            if t is not None: note = f"   -> f+0x{t-BASE:06x}"; calls.append((a, t - BASE))
        elif (h1 & 0xFF7F) == 0xF85F and ins.size == 4:
            h2 = u16(a + 2); u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3: note = f"   [pool f+0x{t:06x}=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3: note = f"   [pool f+0x{t:06x}=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            s = d[t:t + 48].split(b'\x00')[0]
            pr = s.decode('ascii', 'replace') if len(s) >= 2 and all(32 <= c < 127 for c in s) else ''
            note = f"   [adr f+0x{t:06x} {pr!r}]"
        elif mn in ('movw', 'movt') and len(ins.operands) == 2:
            rn = ins.reg_name(ins.operands[0].reg) or ''; imm = ins.operands[1].imm
            if rn.startswith('r') and rn[1:].isdigit():
                rd = int(rn[1:])
                if mn == 'movw': regimm[rd] = (imm, None)
                else:
                    lo16 = regimm.get(rd, (0, None))[0]; regimm[rd] = (lo16, imm)
                    note = f"   ; r{rd}=0x{(imm<<16)|lo16:08X}"
        if mn.startswith('b') and mn not in ('bx', 'blx', 'bkpt') and ins.operands and ins.operands[0].type == 2:
            tgt = ins.operands[0].imm - BASE
            if mn != 'bl': branches.append((a, mn, tgt))
        print(f"  0x{ins.address:08x} f+0x{a:06x}: {mn:9s} {ops}{note}")
        a += ins.size
    print(f"  --- branches ---")
    for off, mn, tgt in branches: print(f"    f+0x{off:06x}: {mn:6s} -> f+0x{tgt:06x}")
    print(f"  --- calls ---")
    for off, tgt in calls: print(f"    f+0x{off:06x}: bl -> f+0x{tgt:06x}")

for lo, hi, label in [
    (0x0430, 0x078e, "BOOT MAIN f+0x430 (update-vs-launch fork)"),
    (0x0e04, 0x1108, "DECISION CONTINUATION f+0xe04 (intake / flag consumer)"),
    (0x103c, 0x1108, "SRAM-magic recv f+0x103c + USB write f+0x1070"),
    (0x11b4, 0x12e0, "FLASH-option f+0x11b4 + misc"),
    (0x17fc, 0x1926, "config-flag helpers f+0x17fc/f+0x1824 + reset f+0x18b6 + cluster init"),
    (0x21d8, 0x2254, "config-block reader f+0x21d8"),
    (0x1918, 0x1926, "accessors f+0x1918/f+0x191e/f+0x1922"),
]:
    disasm_range(lo, hi, label)