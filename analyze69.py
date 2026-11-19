#!/usr/bin/env python3
"""analyze69.py — full bootloader disassembly + call graph + string/constant xrefs.

The acquired bootloader (acq/dump/boot.bin, REPORT §5.14) is small (~11 KB of code,
almost all in flash sector 0, file 0x0000..0x4000). This disassembles that region with
full annotation — LDR-literal pool values, ADR string targets, BL targets, and movw+movt
32-bit constant reconstruction — then derives a function map (BL targets + reset entry),
a per-function call graph, and a string-xref table. Use it to trace the update
orchestration (USB read -> XOR decode -> flash write), the install transform (strip 0x402
header + verbatim copy, §5.16), the exact boot->app jump (bx to the app reset vector),
XMODEM-1K recovery, and the MAINARM/BOOTARM/ROOTCERTS/PRIROOT UPG-component parsing.

Boot literal pools are PLAINTEXT (the bootloader is the decoder, §5.13b), so standard
LDR-literal / ADR resolution applies (no +2-byte overlay shift here).

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze69.py acq/dump/boot.bin > boot69.txt'
  (full annotated disasm on stdout; function/call-graph/xref summary at the end)
"""
import sys, struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

BASE = 0x08000000
d = open(sys.argv[1], 'rb').read(); n = len(d)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.detail = True

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

# --- locate non-FF islands across the whole 128 KB ---
islands = []; i = 0
while i < n:
    if d[i] != 0xFF:
        j = i
        while j < n and d[j] != 0xFF: j += 1
        if j - i >= 4: islands.append((i, j))
        i = j
    else:
        i += 1
print("=== non-FF islands (>=4 B) ===")
for a, b in islands:
    print(f"  f+0x{a:06x}..0x{b:06x}  ({b-a} B)  runtime 0x{BASE+a:08x}")

# --- disassemble the code region 0..0x4000 with annotation ---
CODE_END = 0x4000
regimm = {}          # reg -> (lo16, hi16 or None)
edges = collections.defaultdict(set)   # caller func -> set of BL targets
bl_targets = set()
strxrefs = []        # (code_off, target_off, string)
poolloads = []       # (code_off, pool_off, value)
lines = []
SYSREG = {0x08: 'MSP', 0x09: 'PSP', 0x10: 'PRIMASK', 0x11: 'BASEPRI',
          0x12: 'BASEPRI_MAX', 0x13: 'FAULTMASK', 0x14: 'CONTROL'}
a = 0
while a < CODE_END:
    ins = list(md.disasm(d[a:a + 8], BASE + a, count=1))
    h1 = u16(a)
    # capstone 5.0.9 refuses the MSR(register) T1 encoding (f38x 88xx); decode it manually
    if not ins and (h1 & 0xFFF0) == 0xF380 and a + 2 < CODE_END and (u16(a + 2) & 0xFF00) == 0x8800:
        sysm = u16(a + 2) & 0xFF; rn = h1 & 0xF
        sn = SYSREG.get(sysm, f'SYSm0x{sysm:02x}')
        lines.append(f"  0x{BASE+a:08x} f+0x{a:06x}: msr       {sn}, r{rn}   (manual)")
        a += 4; continue
    if not ins:
        lines.append(f"  f+0x{a:06x}: .hword 0x{u16(a):04x} (data/bad)"); a += 2; continue
    ins = ins[0]; note = ''
    mn = ins.mnemonic; ops = ins.op_str
    if mn == 'bl':
        t = bl_target(a)
        if t is not None:
            bl_targets.add(t - BASE); note = f"   -> f+0x{t-BASE:06x}"
    elif (h1 & 0xFF7F) == 0xF85F and ins.size == 4:      # LDR-literal T2
        h2 = u16(a + 2); u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= t < n - 3:
            w = u32(t); note = f"   [pool f+0x{t:06x}=0x{w:08X}]"; poolloads.append((a, t, w))
    elif (h1 & 0xF800) == 0x4800:                        # LDR-literal T1
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        if t < n - 3:
            w = u32(t); note = f"   [pool f+0x{t:06x}=0x{w:08X}]"; poolloads.append((a, t, w))
    elif (h1 & 0xF800) == 0xA000:                        # ADR
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
        s = d[t:t + 40].split(b'\x00')[0]
        pr = s.decode('ascii', 'replace') if len(s) >= 2 and all(32 <= c < 127 for c in s) else ''
        note = f"   [adr f+0x{t:06x} {pr!r}]"
        if pr: strxrefs.append((a, t, pr))
    elif mn in ('movw', 'movt') and len(ins.operands) == 2:
        rn = ins.reg_name(ins.operands[0].reg) or ''
        imm = ins.operands[1].imm
        if rn.startswith('r') and rn[1:].isdigit():
            rd = int(rn[1:])
            if mn == 'movw':
                regimm[rd] = (imm, None)
            else:
                lo = regimm.get(rd, (0, None))[0]
                regimm[rd] = (lo, imm)
                note = f"   ; r{rd}=0x{(imm<<16)|lo:08X}"
    lines.append(f"  0x{ins.address:08x} f+0x{a:06x}: {mn:9s} {ops}{note}")
    a += ins.size

# --- function map + call graph ---
func_starts = sorted({0x8, 0x3C} | {t for t in bl_targets if 0 <= t < CODE_END})
def func_of(off):
    lo = 0
    for s in func_starts:
        if s <= off: lo = s
        else: break
    return lo
# rebuild edges by scanning BL sites
for a in range(0, CODE_END - 3, 2):
    h1 = u16(a)
    if (h1 >> 11) == 0x1E and (u16(a + 2) & 0xD000) == 0xD000:
        t = bl_target(a)
        if t is not None and 0 <= t - BASE < CODE_END:
            edges[func_of(a)].add(t - BASE)

print("\n=== full disassembly f+0x0000..0x4000 ===")
print("\n".join(lines))

print(f"\n=== functions ({len(func_starts)}) + call graph ===")
for s in func_starts:
    callees = ", ".join(f"f+0x{t:06x}" for t in sorted(edges.get(s, [])))
    print(f"  fn f+0x{s:06x} (0x{BASE+s:08x}): bl -> {callees or '(none/leaf)'}")

print(f"\n=== string xrefs ({len(strxrefs)}) ===")
for a, t, pr in strxrefs:
    print(f"  code f+0x{a:06x} -> f+0x{t:06x}  {pr!r}")

# merge islands separated by small FF gaps (<=16 B) so tables dump coherently
merged = []
for a, b in islands:
    if merged and a - merged[-1][1] <= 16:
        merged[-1] = (merged[-1][0], b)
    else:
        merged.append((a, b))
print("\n=== islands outside sector 0 (merged, hex) ===")
for a, b in merged:
    if a >= CODE_END and b - a <= 1024:
        print(f"  f+0x{a:06x}..0x{b:06x}  ({b-a} B):")
        for o in range(a, b, 16):
            chunk = d[o:min(o + 16, b)]
            hx = ' '.join(f'{x:02x}' for x in chunk)
            asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
            print(f"    f+0x{o:06x}: {hx:<48s} {asc}")