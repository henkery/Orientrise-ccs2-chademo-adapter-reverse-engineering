#!/usr/bin/env python3
"""analyze107.py — boot RECOVERY-ENTRY trigger trace (REPORT §5.14/§5.15 follow-up).

Question: with a custom (or any) app installed, what makes the bootloader STAY in its
USB/XMODEM recovery/update path instead of jumping to the app? This isolates the boot-mode
decision chain and extracts every conditional branch + call that gates update-vs-launch:

  reset f+0x8 -> boot main f+0x3C -> launch/update cluster f+0x1926
    -> update wrapper f+0x9ae -> boot-mode decision f+0x8b2
       (polls serial read f+0x12e0 for 0x55/0x75; magic 0x55AAAA55/0x5AA5A55A @0x20002538;
        flags 0x2000250C; app/config verifier f+0x7b0)
    -> on update: XMODEM f+0xc5e / USB intake / update cmd f+0x1108 -> install -> reset
    -> on launch: boot->app jump f+0x119e (BOOT/TOOB magic @0x20000000, bx app reset)

Reuses analyze69's annotation (LDR-literal pool, ADR strings, BL targets, movw/movt const,
manual MSR(register) T1). Adds: per-function conditional-branch + call extraction, the
0x08004000 config-block dump, and a magic/SRAM-address xref scan.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze107.py acq/dump/boot.bin > .qwen/tmp/ccs2_re/a107.out'
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

SYSREG = {0x08: 'MSP', 0x09: 'PSP', 0x10: 'PRIMASK', 0x11: 'BASEPRI',
          0x12: 'BASEPRI_MAX', 0x13: 'FAULTMASK', 0x14: 'CONTROL'}

def disasm_range(lo, hi, label):
    """Annotated disasm of [lo,hi); returns (lines, branches, calls)."""
    print(f"\n===== {label}  f+0x{lo:06x}..0x{hi:06x} (0x{BASE+lo:08x}) =====")
    regimm = {}
    branches = []   # (off, mnemonic, target_off)
    calls = []      # (off, target_off)
    a = lo
    while a < hi:
        ins = list(md.disasm(d[a:a + 8], BASE + a, count=1))
        h1 = u16(a)
        if not ins and (h1 & 0xFFF0) == 0xF380 and a + 2 < hi and (u16(a + 2) & 0xFF00) == 0x8800:
            sysm = u16(a + 2) & 0xFF; rn = h1 & 0xF
            sn = SYSREG.get(sysm, f'SYSm0x{sysm:02x}')
            print(f"  0x{BASE+a:08x} f+0x{a:06x}: msr       {sn}, r{rn}   (manual)")
            a += 4; continue
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{u16(a):04x} (data/bad)"); a += 2; continue
        ins = ins[0]; note = ''
        mn = ins.mnemonic; ops = ins.op_str
        if mn == 'bl':
            t = bl_target(a)
            if t is not None:
                note = f"   -> f+0x{t-BASE:06x}"; calls.append((a, t - BASE))
        elif (h1 & 0xFF7F) == 0xF85F and ins.size == 4:
            h2 = u16(a + 2); u = (h1 >> 7) & 1
            t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
            if 0 <= t < n - 3:
                w = u32(t); note = f"   [pool f+0x{t:06x}=0x{w:08X}]"
        elif (h1 & 0xF800) == 0x4800:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            if t < n - 3:
                w = u32(t); note = f"   [pool f+0x{t:06x}=0x{w:08X}]"
        elif (h1 & 0xF800) == 0xA000:
            t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
            s = d[t:t + 48].split(b'\x00')[0]
            pr = s.decode('ascii', 'replace') if len(s) >= 2 and all(32 <= c < 127 for c in s) else ''
            note = f"   [adr f+0x{t:06x} {pr!r}]"
        elif mn in ('movw', 'movt') and len(ins.operands) == 2:
            rn = ins.reg_name(ins.operands[0].reg) or ''
            imm = ins.operands[1].imm
            if rn.startswith('r') and rn[1:].isdigit():
                rd = int(rn[1:])
                if mn == 'movw': regimm[rd] = (imm, None)
                else:
                    lo16 = regimm.get(rd, (0, None))[0]; regimm[rd] = (lo16, imm)
                    note = f"   ; r{rd}=0x{(imm<<16)|lo16:08X}"
        # branch target extraction (b/bl/b<cond>/cbz/cbnz)
        if mn.startswith('b') and mn not in ('bx', 'blx', 'bkpt') and ins.operands:
            op0 = ins.operands[0]
            if op0.type == 2:  # IMM
                tgt = op0.imm - BASE
                if mn != 'bl':
                    branches.append((a, mn, tgt))
        print(f"  0x{ins.address:08x} f+0x{a:06x}: {mn:9s} {ops}{note}")
        a += ins.size
    return branches, calls

def summarize(name, branches, calls):
    print(f"\n  --- {name}: conditional/direct branches ---")
    for off, mn, tgt in branches:
        cond = '' if mn in ('b', 'cbz', 'cbnz') else f' [{mn}]'
        print(f"    f+0x{off:06x}: {mn:6s} -> f+0x{tgt:06x}{cond}")
    print(f"  --- {name}: calls ---")
    for off, tgt in calls:
        print(f"    f+0x{off:06x}: bl -> f+0x{tgt:06x}")

# ---- the decision-path functions ----
ranges = [
    (0x0008, 0x0240, "reset + boot main + helpers"),
    (0x078e, 0x08b2, "additive checksum f+0x78e + app/config verifier f+0x7b0"),
    (0x08b2, 0x09ae, "BOOT-MODE DECISION f+0x8b2"),
    (0x09ae, 0x0c5e, "UPDATE WRAPPER f+0x9ae"),
    (0x1108, 0x11b4, "update cmd handler f+0x1108 + boot->app jump f+0x119e"),
    (0x12e0, 0x1420, "serial read f+0x12e0 (poll 0x55/0x75)"),
    (0x1926, 0x1ace, "LAUNCH/UPDATE CLUSTER f+0x1926"),
]
allbr = {}
for lo, hi, label in ranges:
    br, ca = disasm_range(lo, hi, label)
    summarize(label.split('  ')[0], br, ca)
    allbr[label] = (br, ca)

# ---- config block @0x08004000 (file 0x4000), 160 B ----
print("\n===== config block f+0x4000 (0x08004000), 160 B =====")
for o in range(0x4000, 0x40A0, 16):
    chunk = d[o:o + 16]
    hx = ' '.join(f'{x:02x}' for x in chunk)
    asc = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
    print(f"  f+0x{o:06x}: {hx:<48s} {asc}")
cfg_magic = u32(0x4000 + 0x98)
cfg_len = u32(0x4000 + 0x90)
cfg_chk = u32(0x4000 + 0x94)
print(f"  magic@0x98=0x{cfg_magic:08X} (expect 0x55AA55AA)  length@0x90=0x{cfg_len:X}  checksum@0x94=0x{cfg_chk:08X}")

# ---- magic / SRAM-address xref scan across sector-0 code ----
print("\n===== magic / SRAM xref scan (LDR-literal pool values in f+0x0..0x4000) =====")
targets = {
    0x55AAAA55: 'serial magic A', 0x5AA5A55A: 'serial magic B', 0x55AA55AA: 'config magic',
    0x424F4F54: 'BOOT magic', 0x544F4F42: 'TOOB magic', 0xADA5AD01: 'config-writer magic',
    0x20002538: 'serial-magic SRAM', 0x2000250C: 'boot flags SRAM', 0x20000000: 'BOOT/TOOB handshake SRAM',
    0x08004000: 'config block', 0x08020000: 'app base', 0x49415078: 'xPAI cmd magic',
    0xABCDEF12: 'xPAI cmd magic2', 0xE000ED0C: 'SCB_AIRCR', 0x40003000: 'IWDG',
}
hits = collections.defaultdict(list)
a = 0
while a < 0x4000:
    h1 = u16(a)
    t = None
    if (h1 & 0xFF7F) == 0xF85F and a + 4 <= 0x4000:
        h2 = u16(a + 2); u = (h1 >> 7) & 1
        t = ((a + 4) & ~3) + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
    elif (h1 & 0xF800) == 0x4800:
        t = ((a + 4) & ~3) + (h1 & 0xFF) * 4
    if t is not None and 0 <= t < n - 3:
        w = u32(t)
        if w in targets:
            hits[w].append(a)
    a += 2
for w, desc in targets.items():
    sites = hits.get(w, [])
    s = ', '.join(f'f+0x{x:06x}' for x in sites) if sites else '(no LDR-literal hit)'
    print(f"  0x{w:08X} {desc:28s}: {s}")