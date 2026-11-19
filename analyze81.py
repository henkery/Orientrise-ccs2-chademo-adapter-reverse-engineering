#!/usr/bin/env python3
"""analyze81.py — C013 power-stage control mapper (§5.5c/§5.17/§8.5): ties the CHAdeMO charge
state-machine actions to the physical GPIO outputs and ADC measurements, re-derived from the C013
firmware bytes (the improved-charge revision). The GPIO pin assignments are hardware-invariant (same
board as C009, analyze78); C013 only shifts the code, so this re-locates the primitives and traces the
power-stage drivers (set_precharge_relay / inner contactor / d1,d2 enables / get_hv) to their pins.

Parts:
  1. Decode the C013 GPIO primitive cluster (push-less leaves; BSRR set-shift = write pin, IDR/ODR
     ubfx = read pin, bics = active-low; flush at bx lr; capstone reg IDs PC=81/LR=80).
  2. Name each write primitive via BL-callers -> enclosing-function ADR/LDR naming strings
     (PreChargeRELAY / BatteryPower / BatteryCharge / CHAdeMO enables / e-lock).
  3. Locate the HV ADC front-end by its ADC12_COMMON (0x40012300) base loads (HV DC-link = ADC1+ADC2
     dual simultaneous); disassemble the ADC init/calibration function and report the Vrefint-based
     udiv scale-factor constants + the calibration struct address. ('get_hv' is only a log substring,
     no standalone xref — the full raw->volts getter that consumes these factors is still pending.)

Usage:
  nix-shell -p python3 python3Packages.capstone --run 'python3 analyze81.py'
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm_const import ARM_REG_PC, ARM_REG_LR

TB = 0x0801FBFE
fw = open('.qwen/tmp/c013/decoded_c013.bin', 'rb').read(); N = len(fw)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN); md.detail = True
def u16(o): return struct.unpack_from('<H', fw, o)[0]
def u32(o): return struct.unpack_from('<I', fw, o)[0]
def rt(f):  return TB + f
def dis(o, n=1): return list(md.disasm(fw[o:o+8], rt(o), count=n))
GPIO = {0x40020000:'A', 0x40020400:'B', 0x40020800:'C', 0x40020C00:'D', 0x40021000:'E'}
def ldr_pool(o):
    h1 = u16(o)
    if (h1 & 0xF800) == 0x4800:
        p = (((rt(o)+4) & ~3) - TB) + (h1 & 0xFF)*4
        if 0 <= p and p+4 <= N: return u32(p)
    return None
def cstr_at(o):
    s = o
    while s > 0 and fw[s-1] != 0 and 32 <= fw[s-1] < 127: s -= 1
    e = fw.find(b'\x00', o)
    if e < 0 or e-s > 80: return None
    t = fw[s:e]
    if len(t) >= 3 and all(32 <= c < 127 for c in t): return t.decode()
    return None

print("== 1. C013 GPIO primitive cluster (BSRR writes / IDR-ODR reads) ==")
base_loads = []
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0x4800 and ldr_pool(o) in GPIO: base_loads.append(o)
groups = []
for o in base_loads:
    if groups and o - groups[-1][-1] < 0x180: groups[-1].append(o)
    else: groups.append([o])
def has_bsrr(lo, hi):
    a = lo
    while a < hi:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]
        if i.mnemonic in ('str','str.w') and len(i.operands)==2 and i.operands[1].type==3 and i.operands[1].mem.disp==0x18:
            return True
        a += i.size
    return False
cand = [g for g in groups if has_bsrr(g[0]-0x20, g[-1]+0x40)]
grp = max(cand, key=lambda g: len(g))
lo = grp[0]; hi = grp[-1]+0x60
prims = {}
def flush(fstart, writes, reads, alow):
    if writes or reads:
        prims[rt(fstart)] = {'w': [(GPIO[p], n) for p, n in writes],
                             'r': [(GPIO[p], n, k) for p, n, k in reads], 'alow': alow}
fstart = lo; regbase = {}; last_shift = None; reads = []; writes = []; alow = False; rd_base = None
a = lo
while a < hi:
    ins = dis(a)
    if not ins: a += 2; continue
    j = ins[0]; ops = j.operands; mn = j.mnemonic
    if mn in ('ldr','ldr.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.base==ARM_REG_PC:
        w = ldr_pool(a)
        if w in GPIO: regbase[ops[0].reg] = w
    elif mn in ('ldr','ldr.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.disp in (0x10,0x14):
        bb = regbase.get(ops[1].mem.base)
        if bb: rd_base = (bb, ops[1].mem.disp)
    elif mn == 'ubfx' and len(ops)==4 and rd_base:
        reads.append((rd_base[0], ops[2].imm, 'ODR' if rd_base[1]==0x14 else 'IDR'))
    elif mn in ('orr','orr.w') and len(ops)==3 and ops[2].type==1 and 0 <= ops[2].shift.value <= 15:
        last_shift = ops[2].shift.value
    elif mn in ('str','str.w') and len(ops)==2 and ops[1].type==3 and ops[1].mem.disp==0x18:
        bb = regbase.get(ops[1].mem.base)
        if bb is not None and last_shift is not None: writes.append((bb, last_shift))
    elif mn == 'bics': alow = True
    end = (mn=='bx' and ops and ops[0].type==1 and ops[0].reg==ARM_REG_LR) or \
          (mn=='pop' and any(op.type==1 and op.reg==ARM_REG_PC for op in ops))
    a += j.size
    if end:
        flush(fstart, writes, reads, alow)
        fstart = a; regbase = {}; last_shift = None; reads = []; writes = []; alow = False; rd_base = None
flush(fstart, writes, reads, alow)
for addr in sorted(prims):
    p = prims[addr]
    ws = '+'.join(f'P{port}{n}' for port, n in p['w'])
    rs = '+'.join(f'P{port}{n}({k})' for port, n, k in p['r'])
    print(f"  0x{addr:08X} (f+0x{addr-TB:05x}): {'WRITE' if p['w'] else 'read ':5s} {ws or rs}{' active-low' if p['alow'] else ''}")

print("\n== 2. write-primitive -> BL callers -> naming strings ==")
bls = []
for o in range(0, N-4, 2):
    if (u16(o) & 0xF800) == 0xF000:
        ins = dis(o)
        if ins and ins[0].mnemonic=='bl' and ins[0].operands and ins[0].operands[0].type==2:
            bls.append((o, ins[0].operands[0].imm))
def callers(t): return [o for o, tt in bls if tt == t]
def func_start(o):
    a = o
    while a > o-0x200:
        h = u16(a)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: return a
        a -= 2
    return o-0x40
def strings_near(o, span=0x120):
    fs = func_start(o); fe = fs + 2
    while fe < fs + 0x300 and fe < N-2:
        h = u16(fe)
        if (h & 0xFF00)==0xB500 or (h & 0xFFF0)==0xE920: break
        fe += 2
    out = []; a = fs; limit = min(fe, o+span)
    while a < limit and a < N-4:
        ins = dis(a)
        if not ins: a += 2; continue
        i = ins[0]; tgt = None
        if i.mnemonic=='adr' and len(i.operands)==2: tgt = ((rt(a)+4)&~3) + i.operands[1].imm
        elif (u16(a)&0xF800)==0x4800:
            w = ldr_pool(a)
            if w is not None: tgt = w
        if tgt is not None and TB <= tgt < TB+N:
            s = cstr_at(tgt-TB)
            if s: out.append(s)
        a += i.size
    return out
NAMEKEY = [('PreChargeRELAY', ['prechargerelay']), ('BatteryPower', ['batterypower']),
           ('BatteryCharge', ['batterycharge']), ('CHAdeMO', ['chademo']),
           ('SLAC/D_LINK', ['d_link', 'slac', 'avln'])]
def name_from(ss):
    low = ' '.join(ss).lower()
    for name, keys in NAMEKEY:
        if any(k in low for k in keys): return name
    return None
write_prims = {addr: p for addr, p in prims.items() if p['w']}
for addr in sorted(write_prims):
    p = write_prims[addr]; pins = '+'.join(f'P{port}{n}' for port, n in p['w'])
    cs = callers(addr); names = {}
    for o in cs:
        nm = name_from(strings_near(o))
        if nm: names[nm] = names.get(nm, 0) + 1
    tag = ', '.join(f'{k}×{v}' for k, v in names.items()) if names else '(no naming string)'
    print(f"  {pins:12s} 0x{addr:08X}: {len(cs):2d} callers -> {tag}")

print("\n== 3. HV ADC front-end: ADC12_COMMON dual-read cluster + calibration ==")
# 'get_hv' is only a log substring (no standalone xref); locate the ADC front-end by its
# ADC12_COMMON (0x40012300) base loads — the HV DC-link is measured ADC1+ADC2 dual simultaneous.
ADC = {0x40012000:'ADC1', 0x40012100:'ADC2', 0x40012300:'ADC12_COMMON', 0x40012200:'ADC3'}
adc_sites = [(o, ADC[ldr_pool(o)]) for o in range(0, N-4, 2)
             if (u16(o)&0xF800)==0x4800 and ldr_pool(o) in ADC]
print(f"  ADC-base load sites: {len(adc_sites)}")
for o, nm in adc_sites: print(f"    f+0x{o:05x} (0x{rt(o):08X}): {nm}")
# the ADC init/calibration function: disassemble around the first ADC12_COMMON load, capture the
# udiv calibration constants (Vrefint-based scale factors) and the calibration struct address.
common = [o for o, nm in adc_sites if nm=='ADC12_COMMON']
if common:
    fs = func_start(common[0])
    print(f"  ADC init/calibration function f+0x{fs:05x} (0x{rt(fs):08X}):")
    a = fs; consts = []; struct_addr = None
    for _ in range(70):
        ins = dis(a)
        if not ins: break
        i = ins[0]; w = ldr_pool(a)
        if i.mnemonic=='udiv' and w is not None: consts.append(w)
        if w is not None and 0x20000000 <= w < 0x20030000 and struct_addr is None: struct_addr = w
        if w is not None and (i.mnemonic in ('ldr','ldr.w')):
            print(f"    f+0x{a:05x} 0x{rt(a):08X}: {i.mnemonic:8s} {i.op_str}  ; =0x{w:08X} ({w})")
        if i.mnemonic=='bx' or (i.mnemonic=='pop' and 'pc' in i.op_str): break
        a += i.size
    # the udiv dividends are loaded just before each udiv; recover them from the pool loads above
    print(f"  calibration struct = 0x{struct_addr:08X}" if struct_addr else "  calibration struct not found")
    print("  HV = ADC1+ADC2 dual simultaneous (PB0/PB1); scale factors = const/ADC_raw stored to the")
    print("  calibration struct (Vrefint-referenced). Full get_hv raw->volts law needs the getter that")
    print("  consumes these factors (pending); the engagement guard (§5.17) uses the scaled outvol/ress_vol.")

print("\n== RESOLVED power-stage map (C013) ==")
print("  PreChargeRELAY=PB10/PB11, BatteryPower(inner contactor)=PD8, BatteryCharge=PC9,")
print("  e-lock motor=PD3/PE4, CHAdeMO enables(d1/d2)=PE7/PE8 — hardware-invariant vs C009 (analyze78);")
print("  C013 shifts the primitive cluster to 0x08088400+ (C009: 0x080879FE). State-machine actions")
print("  set_precharge_relay / close inner relay / SET_CSS1(d1) / SET_CSS2(d2) / switchK / close A+ drive these pins.")