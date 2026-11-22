#!/usr/bin/env python3
"""analyze109.py — which USB core does the stock MAIN APP use, and how does it init the FS PHY?

Stage-0 CDC stall: our OTG_FS (0x50000000) device core detects reset SE0 but decodes NO packets
(SOF=0, RXFLVL=0 even unmasked). Clock config matches stock exactly (PLLQ=7, DCKCFGR=0). GSNPSID/
GHWCFG read 0 (clone). Hypothesis: the clone OTG_FS is a broken stub and the stock working USB uses
OTG_HS (0x40040000) with its internal FS PHY. This scans firmware.bin (=C009, runs on this clone)
for USB-core base LDR-literal xrefs and constant-tracks the PHY-init register writes.

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze109.py'
"""
import struct, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('firmware.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f): return TB + f

def ldr_lit(o):
    """Resolve a LDR-literal (T1 0x4800 or T2 0xF85F) pool word at file offset o."""
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:                      # T1: ldr rt, [pc, #imm8*4]
        p = ((rt(o) + 4) & ~3) - TB + (h1 & 0xFF) * 4
        if 0 <= p <= N - 4: return u32(p)
    elif (h1 & 0xFF7F) == 0xF85F and o + 4 <= N:     # T2: ldr.w rt, [pc, #+/-imm12]
        h2 = u16(o + 2); u = (h1 >> 7) & 1
        p = ((rt(o) + 4) & ~3) - TB + ((h2 & 0xFFF) if u else -(h2 & 0xFFF))
        if 0 <= p <= N - 4: return u32(p)
    return None

CORES = {0x50000000: 'OTG_FS', 0x40040000: 'OTG_HS'}
sites = collections.defaultdict(list)
for o in range(0, N - 4, 2):
    w = ldr_lit(o)
    if w in CORES:
        sites[w].append(o)

print("== USB-core base LDR-literal xref counts (stock main app) ==")
for w, nm in CORES.items():
    s = sites.get(w, [])
    print(f"  0x{w:08X} {nm}: {len(s)} sites")
    for x in s[:24]:
        print(f"      f+0x{x:06x} (addr 0x{rt(x):08X})")

# Constant-track register writes around each OTG_FS/HS init cluster to recover PHY config.
USBREG = {0x000:'GOTGCTL',0x008:'GAHBCFG',0x00C:'GUSBCFG',0x010:'GRSTCTL',0x014:'GINTSTS',
          0x018:'GINTMSK',0x020:'GRXSTSP',0x038:'GCCFG',0x03C:'GUID',0x040:'GSNPSID',
          0x800:'DCFG',0x804:'DCTL',0x808:'DSTS',0xE00:'PCGCCTL'}
def track(lo, hi, base, label):
    print(f"\n== {label}: register writes f+0x{lo:06x}..0x{hi:06x} (base 0x{base:08X}) ==")
    rv = {}; base_reg = {}; regs = {}
    a = lo
    while a < hi:
        ins = list(md.disasm(fw[a:a+8], rt(a), count=1))
        if not ins: a += 2; continue
        i = ins[0]; mn = i.mnemonic; ops = i.operands
        if mn in ('ldr',) and len(ops) >= 2 and ops[1].type == 3:
            # ldr rt, [pc, #...] literal -> known constant
            w = ldr_lit(a)
            if w is not None:
                rv[ops[0].reg] = w; base_reg[ops[0].reg] = w
            else:
                rv.pop(ops[0].reg, None); base_reg.pop(ops[0].reg, None)
        elif mn in ('movw','movs','mov.w') and len(ops) == 2 and ops[1].type == 2:
            rv[ops[0].reg] = ops[1].imm & 0xFFFF; base_reg.pop(ops[0].reg, None)
        elif mn == 'movt' and len(ops) == 2 and ops[1].type == 2:
            rv[ops[0].reg] = (rv.get(ops[0].reg, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
            base_reg[ops[0].reg] = rv[ops[0].reg]
        elif mn in ('orr','orr.w','bic','bic.w','lsls','lsrs','adds','add','add.w','mov','mvns','ands','ubfx'):
            if ops and ops[0].type == 1:
                rv.pop(ops[0].reg, None); base_reg.pop(ops[0].reg, None)
        elif mn in ('str','str.w') and len(ops) == 2 and ops[1].type == 3:
            b = base_reg.get(ops[1].mem.base); v = rv.get(ops[0].reg)
            if b == base and v is not None:
                regs[ops[1].mem.disp] = v
        a += i.size
    for off in sorted(regs):
        nm = USBREG.get(off, f'+0x{off:03X}')
        v = regs[off]; extra = ''
        if off == 0x00C:
            extra = f"  PHYSEL(bit6)={(v>>6)&1} FDMOD(bit30)={(v>>30)&1} FHMOD(bit29)={(v>>29)&1} TRDT={(v>>10)&0xF}"
        if off == 0x038:
            extra = f"  PWRDWN(bit16)={(v>>16)&1} NOVBUSSENS(bit21)={(v>>21)&1} VBUSASEN(18)={(v>>18)&1} VBUSBSEN(19)={(v>>19)&1}"
        if off == 0xE00:
            extra = f"  STOPPCLK(0)={v&1} GATEHCLK(1)={(v>>1)&1} PWRCLMP(2)={(v>>2)&1} RSTPDWN(3)={(v>>3)&1}"
        print(f"  {nm:9s} +0x{off:03X} = 0x{v:08X}{extra}")
    if not regs: print("  (no constant writes resolved)")

# Track a window after the first few xref sites of whichever core is present.
for w, nm in CORES.items():
    s = sites.get(w, [])
    if s:
        # cluster: take the earliest site, scan a generous window forward for the init function
        lo = s[0]
        track(lo, min(lo + 0x600, N - 8), w, f"{nm} init near first xref")

# Also catch movw/movt loads of the USB bases (LDR-literal scan misses these).
print("\n== movw/movt USB-base loads ==")
mv = collections.defaultdict(list)
pend = {}
for o in range(0, N - 4, 2):
    ins = list(md.disasm(fw[o:o+8], rt(o), count=1))
    if not ins: continue
    i = ins[0]; ops = i.operands
    if i.mnemonic == 'movw' and len(ops) == 2 and ops[1].type == 2:
        pend[ops[0].reg] = ops[1].imm & 0xFFFF
    elif i.mnemonic == 'movt' and len(ops) == 2 and ops[1].type == 2:
        v = (pend.get(ops[0].reg, 0) & 0xFFFF) | ((ops[1].imm & 0xFFFF) << 16)
        if v in CORES: mv[v].append(o)
for w, nm in CORES.items():
    print(f"  0x{w:08X} {nm}: {len(mv.get(w, []))} movw/movt sites " +
          ', '.join(f'f+0x{x:06x}' for x in mv.get(w, [])[:12]))

# Disassemble the OTG_HS init region to confirm FS-PHY (PHYSEL) + RCC enable.
def disasm_range(lo, hi, label):
    print(f"\n== {label}  f+0x{lo:06x}..0x{hi:06x} ==")
    a = lo
    while a < hi:
        ins = list(md.disasm(fw[a:a+8], rt(a), count=1)); h1 = u16(a)
        if not ins:
            print(f"  f+0x{a:06x}: .hword 0x{u16(a):04x}"); a += 2; continue
        i = ins[0]; note = ''; mn = i.mnemonic; ops = i.op_str
        w = ldr_lit(a)
        if w is not None: note = f"   [pool=0x{w:08X}]"
        if mn in ('movw','movt') and len(i.operands) == 2 and i.operands[1].type == 2:
            note = f"   ; imm=0x{i.operands[1].imm:04X}"
        print(f"  f+0x{a:06x}: {mn:9s} {ops}{note}")
        a += i.size

hs = sites.get(0x40040000, [])
if hs:
    disasm_range(max(0, hs[0] - 0x40), hs[0] + 0x180, "OTG_HS init around first xref")

# The USB core-init fn (push at f+0x03932e = 0x08058F2C) takes core-index in r2:
#   r2==0 -> OTG_HS (0x40040000, ep_max 6); r2==1 -> OTG_FS (0x50000000, ep_max 4).
# Find its BL callers and trace the r2 (core index) each passes -> which core the app uses.
INIT_FN = rt(0x03932e)
def bl_target(a):
    h1 = u16(a); h2 = u16(a + 2)
    if (h1 >> 11) != 0x1E or (h2 & 0xD000) != 0xD000: return None
    S = (h1 >> 10) & 1; imm10 = h1 & 0x3FF; J1 = (h2 >> 13) & 1; J2 = (h2 >> 11) & 1; imm11 = h2 & 0x7FF
    I1 = 1 - ((J1 ^ S) & 1); I2 = 1 - ((J2 ^ S) & 1)
    off = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if off & (1 << 24): off -= 1 << 25
    return rt(a + 4) + off

def find_callers(fn):
    return [o for o in range(0, N - 4, 2)
            if (u16(o) >> 11) == 0x1E and bl_target(o) == fn]

def dump_callers(fn, label, back=0x90):
    cs = find_callers(fn)
    print(f"\n== BL callers of {label} 0x{fn:08X}: {len(cs)} ==")
    for c in cs:
        print(f"\n  caller f+0x{c:06x} (0x{rt(c):08X}):")
        a = max(0, c - back)
        while a < c + 4:
            ins = list(md.disasm(fw[a:a+8], rt(a), count=1))
            if not ins: a += 2; continue
            i = ins[0]; mark = '  <-- BL' if a == c else ''
            print(f"    f+0x{a:06x}: {i.mnemonic:9s} {i.op_str}{mark}")
            a += i.size
    return cs

dump_callers(INIT_FN, "USB core-init (r2=core idx)")
# wrapper at f+0x037834 takes core idx as 3rd arg (r2) -> r6 -> init. Chase its callers.
WRAP = rt(0x037834)
dump_callers(WRAP, "USB HAL open wrapper (r2=core idx)", back=0x60)

# Stock core-init function body AFTER the memcpy call (f+0x039398): the actual PHY/device register
# writes (GCCFG 0x38 PWRDWN, GUSBCFG 0x0C PHYSEL/TRDT, PCGCCTL 0xE00, DCFG 0x800). Recover proven init.
disasm_range(0x03939c, 0x039680, "stock USB core-init register writes (post-memcpy)")

# Decisive: which RCC USB clock bit does stock enable? AHB1ENR(0x40023830) bit29=OTGHSLEN/
# bit30=OTGHSULPIEN; AHB2ENR(0x40023834) bit7=OTGFSEN. Find base loads + dump the ORR/STR window.
print("\n== RCC AHB1ENR/AHB2ENR (USB clock enable) load sites + following insns ==")
RCCUSB = {0x40023830: 'AHB1ENR', 0x40023834: 'AHB2ENR'}
for o in range(0, N - 4, 2):
    w = ldr_lit(o)
    if w in RCCUSB:
        print(f"\n  {RCCUSB[w]} base load f+0x{o:06x} (0x{rt(o):08X}):")
        a = o
        while a < o + 0x30:
            ins = list(md.disasm(fw[a:a+8], rt(a), count=1))
            if not ins: a += 2; continue
            i = ins[0]; note = ''
            ww = ldr_lit(a)
            if ww is not None: note = f"   [pool=0x{ww:08X}]"
            if i.mnemonic in ('movw','movt','orr','orr.w','bic','bic.w') and len(i.operands) >= 2:
                if i.operands[-1].type == 2: note = f"   ; imm=0x{i.operands[-1].imm:08X}"
            print(f"    f+0x{a:06x}: {i.mnemonic:9s} {i.op_str}{note}")
            a += i.size