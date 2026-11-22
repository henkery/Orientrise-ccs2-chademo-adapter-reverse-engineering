#!/usr/bin/env python3
"""analyze108b.py — install dispatcher f+0x2168 staging layout + SPI4 init/RDSR.

Resolves WHERE the boot reads the staged UPG payload (so a CDC revert upload stages it at the
right SPI offset), plus the SPI4 init f+0x1a08 and RDSR busy-poll f+0x1aa4. The xPAI descriptor
is read from logical 0 (physical 0x100000) by f+0x1ace; f+0x1108 calls f+0x2168 with r0=0x100000.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze108b.py acq/dump/boot.bin > .qwen/tmp/ccs2_re/a108b.out'
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
def disasm_range(lo, hi, label):
    print(f"\n===== {label}  f+0x{lo:06x}..0x{hi:06x} =====")
    regimm = {}; a = lo
    while a < hi:
        ins = list(md.disasm(d[a:a + 8], BASE + a, count=1)); h1 = u16(a)
        if not ins and (h1 & 0xFFF0) == 0xF380 and a + 2 < hi and (u16(a + 2) & 0xFF00) == 0x8800:
            print(f"  f+0x{a:06x}: msr (manual)"); a += 4; continue
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{u16(a):04x}"); a += 2; continue
        ins = ins[0]; note = ''; mn = ins.mnemonic; ops = ins.op_str
        if mn == 'bl':
            t = bl_target(a)
            if t is not None: note = f"   -> f+0x{t-BASE:06x}"
        elif (h1 & 0xFF7F) == 0xF85F and ins.size == 4:
            h2 = u16(a + 2); u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3: note = f"   [pool=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3: note = f"   [pool=0x{u32(t):08X}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            s = d[t:t + 40].split(b'\x00')[0]
            pr = s.decode('ascii', 'replace') if len(s) >= 2 and all(32 <= c < 127 for c in s) else ''
            note = f"   [adr {pr!r}]"
        elif mn in ('movw', 'movt') and len(ins.operands) == 2:
            rn = ins.reg_name(ins.operands[0].reg) or ''; imm = ins.operands[1].imm
            if rn.startswith('r') and rn[1:].isdigit():
                rd = int(rn[1:])
                if mn == 'movw': regimm[rd] = imm
                else: note = f"   ; r{rd}=0x{(imm<<16)|regimm.get(rd,0):08X}"
        print(f"  f+0x{a:06x}: {mn:9s} {ops}{note}")
        a += ins.size
for lo, hi, label in [
    (0x1a08, 0x1ace, "SPI4 init f+0x1a08 + RDSR f+0x1aa4 + helpers"),
    (0x2168, 0x2254, "INSTALL DISPATCHER f+0x2168 + config reader f+0x21d8"),
    (0x1d68, 0x1ece, "component parse f+0x1d68 (TBB)"),
]:
    disasm_range(lo, hi, label)